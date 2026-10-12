# Review: stack d (Hono + Better Auth organization plugin + Cerbos + Postgres)

Reviewed on 2026-10-13, branch `review-d` (from main `275420c`), against `ps-d` on cs-ws rebuilt from the branch. Builder's claim: 390/390. After the fixes below: **392/392** (2 new race tests in `idp-tenancy`), including the slow break-glass expiry test. Unit tests: 31 (was 28).

The builder's main claims hold. Organization writes do join the app's transaction, the login policy can't be bypassed through any mounted route, and the pool survives bursts. The one real bug sits where the two transaction models meet. Better Auth's accept endpoint repairs its own failures with a compensating write. Inside our transaction a failed statement aborts the transaction, so that repair write fails too, and two concurrent joins answered 500 instead of 409.

## Builder's claims, checked

| claim | how checked | result |
|---|---|---|
| organization writes join the app's tx (`getCurrentAdapter` + AsyncLocalStorage) | re-ran `ts-org/scripts/tx-probe.mjs` in the container and extended it: `setStatus`, `removeMember`, `listInvitations`, `findInvitation`, `cancelInvitation` and `attachClient` inside one tx with Better Auth's only pooled connection held, then a throw | **holds.** No call touched Better Auth's pool. After the rollback, status, membership and invitation were unchanged. `acceptInvitation` (session lookup, recipient check, update, member insert, session update) stays on the tx too. `adminCreateOAuthClient` times out (writes on its own pool), as the builder reported |
| no plugin write path escapes the tx | read the plugin source (1.7.7) for `ctx.context.adapter.*` | **holds for what d uses** (the adapter from `getOrgAdapter` and the accept endpoint). Unused paths do escape: `invite-member` (its resend update), the member endpoints' role lookups, `has-permission` and every dynamic-access-control route read or write through `ctx.context.adapter`, outside the tx. None are mounted or called |
| suspended users can't get a session | sign-in burst (60 sign-ins by members of a suspended merchant) | **holds.** 403 every time. Only `sign-in/email` is mounted. `sign-up`, `get-session`, `/token` (jwt), `organization/*` and `oauth2/{register,create-client,introspect,revoke,userinfo}` all 404, and so do encoded traversal, `//`, a trailing slash and upper case |
| suspended agents can't get a token | token requests with Basic auth, a JSON body, a duplicated `grant_type`, `client_id` in the query, no `resource`, form with a charset, a trailing slash and upper case | **holds today.** Basic was refused only because the agent's client is registered for `client_secret_post` (method mismatch), not by the hook. Hardened (#2) |
| tokens issued before suspension → 403 `merchant_suspended` | suite | holds. Existing sessions stay valid and keep being refreshed by use (#10) |
| dynamic access control can't carry §3 | read `crud-access-control.mjs`, `has-permission.mjs` | **agree.** `update-role` checks `ac:update` plus the new permissions only; delete checks `ac:delete` only; the guardrail uses the process-global `cacheAllRoles`; and the role routes read through `ctx.context.adapter` (outside the tx) as well |
| pool safety (c's deadlock, the builder's hook deadlock) | parallel bursts: (a) 30 sign-ins + 30 user creations (sign-up runs inside Better Auth's own tx, so the session hook fires there) + 20 invitation accepts + 20 agent registrations + 60 `/me/permissions` + 20 invitation creates; (b) 80 sign-up+sign-in + 60 suspended sign-ins + 30 suspended token requests; (c) 600 mixed `/me` and `/me/permissions` | **holds.** All 2xx (or the expected 403/400), no timeouts, `/healthz` 200 after each. Max 5.2 s for (c) |

## Findings, by severity

| # | sev | what | where | scenario | status |
|---|---|---|---|---|---|
| 1 | **medium** | Concurrent joins → 500. Two joins for one user (two invitations, or an accept racing a direct add or a merchant create) both pass the "already a member?" check. The second insert waits on the unique index on `member("userId")` and then violates it. Inside Better Auth's `acceptInvitation` that aborts the app's transaction, Better Auth's `.catch` then runs its compensating `accepted → pending` update on the aborted transaction (25P02), and the original 23505 is lost. Better Auth's own error recovery assumes autocommit, and our outer transaction breaks that assumption. | `ts-org/src/modules/merchants.ts` (accept, add), `platform.ts` (create); Better Auth `crud-invites.mjs` accept | One user accepts invitations from A and B at once: `200 \| 500` in 5 of 5 runs; accept vs a direct add elsewhere: 1 of 5. Reproduced. | **fixed**: `lockMembership(tx, userId)` (a transaction advisory lock per user) before the membership check in accept, direct add and merchant create, so the loser sees the winner's commit and answers 409. Conformance: 2 race tests |
| 2 | medium | The token-endpoint login policy read only `body.client_id`, and only on `client_credentials`. A client registered for `client_secret_basic` (the OAuth provider's default when the method is omitted) authenticates in the header and skipped the hook. So did any other grant enabled later. Not exploitable today: `createClient` pins `client_secret_post` and only `client_credentials` is enabled. | `ts-org/src/adapters/better-auth.ts` (`hooks.before`) | Suspended agent with `Authorization: Basic` → refused by the method check, not the policy. Change one default and suspended agents get tokens again. | **fixed**: `tokenRequestClientId` reads the Basic header first (as the provider does), then the body, for every grant; unit tests. Live: Basic now gets "owning organization is suspended" |
| 3 | medium | Joining the tx rests on internal APIs and on each plugin's discipline. `getCurrentDBAdapterAsyncLocalStorage` is marked internal. The organization plugin calls `getCurrentAdapter` in its adapter, but not in `invite-member`, the member role lookups or dynamic access control. The OAuth provider never does. A Better Auth upgrade can move a write out of the tx without a failing test, and the only check, `tx-probe.mjs`, is run by hand. | `adapters/better-auth.ts` (`inTx`, `txKysely`) | Upgrade Better Auth; `acceptInvitation` switches to `ctx.context.adapter` → it runs on the auth pool, outside the app's tx (a dual write again), and the suite stays green. | open: run `tx-probe.mjs` in CI against the built image (today it only prints; make it assert and exit non-zero), and pin Better Auth exactly (`^1.7.7` today for `better-auth` and `oauth-provider`) |
| 4 | medium | Agent and app registration are still a dual write (c #10). The OAuth client commits on Better Auth's pool before the app's transaction; on rollback it stays, with no agent row and no `referenceId`, so the suspension policy can't see it. | `modules/agents.ts`, `apps.ts`, `better-auth.ts` `createClient` | Agent insert fails after `createClient` → an orphan client with a valid secret. Its tokens map to no principal (401). | open (as the builder recorded): sweep orphans, or create the client through the adapter inside the tx (the provider's hashing/validation would then be ours) |
| 5 | medium | Agents can make temporary grants permanent (c #2, §14 P1). Unchanged in d. | `modules/roles.ts`, `apps.ts` | as review-c | open: P1 |
| 6 | low | The session-create hook fails open without a context (`if (!ctx) return`). Every mounted route passes one; a server-side `internalAdapter.createSession` without ctx would mint a session for a suspended merchant's user. | `better-auth.ts` `databaseHooks.session.create.before` | Latent. | open |
| 7 | low | Invitations don't require a verified email. `requireEmailVerificationOnInvitation` is unset, so Better Auth only requires one with custom id generation, and every user here is unverified. Safe as mounted: there is no sign-up route, and invitation ids are opaque. | `orgOptions` | Once sign-up opens, anyone who registers the invitee's address unverified and learns the invitation id joins the merchant. | open: set it to `true` together with email verification |
| 8 | low | `authenticate` turns every Better Auth error into "no credential". A pool timeout or a DB outage answers 401 `unauthenticated` (clients drop the token) instead of 5xx. | `better-auth.ts` `authenticate` (both `catch {}`) | Not reproduced under a 600-request burst (the pools held). Seen by reading. | open: return null only for `APIError`/JWT errors, rethrow the rest |
| 9 | low | `POST /members` still claims any unaffiliated user without consent (c #16, P8), now beside invitations, which do ask. | `merchants.ts` `member.add` | as review-c | open: §15.1 keeps it for the helpers; make it platform-only or test-only |
| 10 | low | §15.3 "the IdP refuses" covers new logins only. Existing sessions of a suspended merchant's users stay valid in Better Auth and are even extended by use (`getSession` refresh); only the app's 403 stops them. | Better Auth sessions | Suspend, use the old token daily: the session never expires; after reinstatement it works again. Matches the suite (tokens issued before → 403 `merchant_suspended`). | open: spec choice (see below) |
| 11 | low | The raw bearer in `Principal.credential` (c #11) is now load-bearing: `acceptInvitation` needs the caller's session to run Better Auth's endpoint. | `kernel/principal.ts`, `merchants.ts` accept | as review-c | open |
| 12 | info | `/api/auth/.well-known/openid-configuration` is allow-listed but returns 404: the provider serves discovery elsewhere. A dead allow-list entry. | `better-auth.ts` `exposedPaths` | — | open (cosmetic) |

Checked, no finding: cross-tenant invitation list and cancel (403/404, stays pending); accepting as another user (403, still acceptable by the invitee); an agent, a customer or platform staff accepting (403 `forbidden`, `kinds`); accepting into a suspended merchant (403 `merchant_suspended`); the same invitation accepted twice at once (200 + 404); the email matched case-insensitively (stored lowercased; Better Auth lowercases both sides); one merchant per user under every race above (now 409).

### review-c findings in d

| c # | what | in d |
|---|---|---|
| 1 | pool deadlock | fixed (three pools, timeouts). The org writes take no connection: they run on the request's own |
| 2 | agents' durable changes | open (#5) |
| 3 | break-glass store list audit | fixed (carried) |
| 4 | `clientPrivileges` | fixed (carried) |
| 5 | cross-tenant suspension leak | fixed (c's policies, unchanged) |
| 6 | 500 on absurd input | fixed (carried) |
| 7 | rate limiter | on by default; compose turns it off for the suite (same production caveats) |
| 8 | PIP reloads per `can()` | open. Same shape: it reads `member`/`organization` instead of `members`/`merchants` |
| 9 | apps and staff not confined in SQL | open |
| 10 | client creation outside the tx | open (#4). Agents now also get an after-the-fact `referenceId` link |
| 11 | bearer passthrough | open, more used (#11) |
| 12 | CSRF check off | open; still safe as mounted (no cookie reads) |
| 13 | check-then-act | open |
| 14 | test endpoint on the tailnet | open (`TEST_MODE=1`, `test-secret`, port 8086 published) |
| 15 | agents may call `agent.grant` | open |
| 16 | `member.add` without consent | open (#9). Invitations now exist beside it |

## Pattern verdicts (SPEC §1)

1. **Action = unit of capability, one executor: bent (as c).** Still one executor. IdP writes moved into `run` through the `RunCtx.idp` port, inside the outbox's transaction. That is better than c, where client creation was a side effect. Guardrails still run inside `run`, and the registry ids still aren't the catalog ids.
2. **One `can()` in AuthZEN shape: holds.** Unchanged. Who may invite, cancel or add is `member.manage` through `can()`, never the plugin's role checks.
3. **Custom roles are data: holds.** Roles stay in the app. Better Auth's `member.role` is a constant `"member"`, so nothing lives in two places.
4. **App DB is the source of truth: holds, and is stronger.** The IdP's tenancy tables live in the same Postgres and commit in the same transaction, so the IdP is effectively part of the app DB. Merchant create, suspend/reinstate, member add/remove and invitations have no failure window. Agent and app registration still have one (#4).
5. **Three checks: bent (as c).**
6. **Tenant isolation twice: bent (as c).** SQL scoping now joins the IdP's `member` table. Apps and staff are still unconfined in SQL.
7. **Composition root by hand: holds.** `transact` in `main.ts` binds the IdP port to the request's connection. The cost is a second Better Auth adapter over a hand-made Kysely "pool".

## Round 2's question, for Better Auth: does the organization plugin make the spec cleaner?

**Barely. The data model is cleaner; the code is not smaller and is more fragile.** The organization plugin helps with storage and gets in the way of authorization.

**What it removed:** the app's `merchants` and `members` tables and their inserts and deletes; invitation storage and the accept rules (recipient by email, case-insensitive, pending, unexpired, compensated on failure); the client→organization link (`referenceId`); a place to hang the login policy. Merchant/member writes didn't go away; they became port calls. In code, `ts/src` → `ts-org/src` is +588/−103, most of it glue (`better-auth.ts` 157 → 405 lines, comments included).

**What it pushed back into the app:**
- **The transaction bridge.** A second Better Auth adapter over the app's transaction connection, through an internal AsyncLocalStorage, plus a guard against `BEGIN`/`COMMIT` on that connection. Without it every tenancy write is a dual write that needs the outbox. With it, the app depends on internals (#3).
- **Concurrency rules the plugin doesn't have.** One merchant per user is our unique index. Concurrent joins need our lock (#1), because the plugin's error recovery breaks inside an outer transaction.
- **Read-only mirrors of its tables** and a hand-written migration (FKs, unique index), because tenant scoping, the PIP and the last-owner lock are SQL.
- **The login policy as two hooks** that have to cover every session-creation route and every token-auth method (#2, #6). The plugin has no "suspended organization" concept: `status` is our additional field, without a DB default.
- **All authorization.** Its endpoints (invite, cancel, remove, update role) enforce its own role model, so only the adapter plus `acceptInvitation` is usable when roles live in the app.

**What's fragile:**
- `getCurrentDBAdapterAsyncLocalStorage` and the `{adapter, isTransactionActive, pendingHooks}` store shape are internal. Each plugin's choice between `getCurrentAdapter` and `ctx.context.adapter` decides atomicity silently (#3).
- Better Auth's compensating writes misbehave inside an outer transaction (#1). The fix is ours; the next Better Auth endpoint we call may have the same pattern.
- The org adapter (`getOrgAdapter`) skips `organizationHooks`. Only endpoint paths fire them, so where a rule lives depends on which surface you call.
- Dynamic access control is not usable for §3: no store scope, no assignments, no limits, an incomplete guardrail, a process-global role cache, and reads outside the transaction.

**Would I keep it?** For invitations and a stock organization schema, yes, as long as Better Auth is pinned exactly and `tx-probe` runs in CI. With roles in the app (as they must be for §3), the plugin is a storage library for three tables, and writing invitations in-app would be about the same size as the glue. The spec gets cleaner (one tenancy writer, no IdP outbox consumer) because Better Auth shares the app's Postgres. That comes from Better Auth being in-process, not from the plugin.

## What I'd change in the spec

- **§15.1:** when the IdP shares the app's DB and joins its transaction, require a regression check that proves it (a probe or test that fails if an IdP write leaves the transaction), not just evidence in the results. Also say that "one merchant per user" must hold under concurrent joins with 409, never 5xx (now tested).
- **§15.2:** name the result of a concurrent second accept (409 `already_member`, now tested). Say whether acceptance needs a verified email (#7). Decide whether `POST /members` stays open to merchants now that invitations exist (P8).
- **§15.3:** "can't log in" should list every way to get a credential: session routes, every token grant and every client auth method (#2). Decide whether suspension also revokes existing sessions. Today the suite requires those tokens to keep answering 403 `merchant_suspended`, so a stack that revokes them would fail with 401 (#10).
- **§9:** an internal failure during authentication is 5xx, never 401 (#8).
- Carried from review-c and still open: P1 (agent blocked list), P5 (test mode off by default).

## Fixed in this review (commits on `review-d`)

1. `tx-probe.mjs` also covers status, member removal, invitation list/find/cancel and the client link: all stay in the app's tx and roll back.
2. Concurrent joins answer 409, not 500 (per-user advisory lock in accept, direct add, merchant create); 2 conformance race tests.
3. The token-endpoint suspension hook reads the client from Basic auth too, for every grant; 3 unit tests.
