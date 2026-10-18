# Review: stack h2 (stack h with pools as rows: an issuer per pool, in-app on zitadel/oidc v3.51.16, + SpiceDB)

Reviewed 2026-10-19, branch `review-h2` (from `stack-h2` `1d3cd26`), against `ps-h2` on cs-ws. Read SPEC §16, `results/h2.md`, the adapter (`go/internal/adapters/oidcpool`: pools, storage, users, federation, keys, rate limits, schema), the shared module changes (migration 003, core principal/authenticator/executor, platform, merchants, invitations, roles, agents, orders, me, scope, testsupport, new `customers`), the composition roots and the driver. Probed the running stack with a scripted attacker (`stacks/h2/review-probe.mjs`, 42 probes) and added Go tests for each fix.

**Suite after fixes:** **401/401** (362 core + 39 multi-pool; 30 `idp-tenancy` skipped), 109 s, stack rebuilt from this branch on the grown DB (migration 102 applied over ~600 existing pools). Probes **42/42** hold. Go: `go test ./...` passes; issuer tests 24 → 28 (`review_test.go`).

**Regression (owed by the builder):** stacks a, a2 and h built from h2's code (`1d3cd26`) in separate projects with fresh volumes (`ps-a-r4`, `ps-a2-r4`, `ps-h-r4` on 818x/819x; migration 003 ran on each), removed afterwards:

| stack | result | time |
|---|---|---|
| a (Zitadel) | **362/362** (69 skipped: idp-tenancy, multi-pool) | 91 s |
| a2 (Zitadel orgs) | **392/392** (incl. the 30 idp-tenancy tests; 39 multi-pool skipped) | 74 s |
| h (oidcop) | **362/362** (69 skipped) | 68 s |

This review's later commits touch only the `oidcpool` adapter (loaded and migrated only when `IDP=oidcpool`) and a doc comment in the identity port, so a/a2/h paths are unchanged since that run.

The builder's work holds up. Every cross-pool attack I tried failed, and the builder's checklist evidence reproduced. Isolation is also stronger than h2.md says: the pool filters in the queries aren't the only guard (see #2). What the review found sits at the edges: what happens to a Shop-linked identity when the Shop account goes away, and limits that are still shared by every pool.

## Findings, by severity

| # | sev | what | where | evidence | status |
|---|---|---|---|---|---|
| 1 | **medium** | **Disabling (or deleting) a Shop account didn't end its sessions at merchants.** A Shop-federated tenant identity refreshed with no check of its upstream account, so a disabled Shop buyer kept a tenant session at every merchant they had signed in at, for up to `REFRESH_TOKEN_TTL` (24 h), rotating forever inside that window. Also, Sign in with Shop's `ON CONFLICT … RETURNING id` revived a tenant identity the merchant had disabled. Only new Shop logins were refused. This is the account-deletion / fraud-lock path: "suspend this buyer" must cut them off everywhere. | `storage.go` `TokenRequestByRefreshToken`, `federation.go` `fedCallback` | `TestShopAccountDisabledEndsTenantSessions` fails on `1d3cd26`: M1 and M2 refreshes → 200 after the Shop account was disabled; a disabled tenant identity → new tenant token via Shop | **fixed**: refresh of a federated identity requires its upstream account to exist and be enabled (one deliberate cross-pool read: the link itself; in a cells deployment this becomes a back-channel logout or a status check over HTTP); `fedCallback` refuses a disabled tenant identity. Access tokens still live 15 min (h #8). The app side has no buyer status yet; a production "delete Shop account" also needs the app's linked customer records handled |
| 2 | medium | **Cross-pool isolation had nothing structural under the ~15 pool filters** (the builder's top risk). Reviewed every statement: all filtered, except two that weren't exploitable (family revoke by a family id read under a pool filter; `DeleteClient` limited to `kind='machine'`, which only exists in `platform`). **The real defence in depth was already there and h2.md understates it:** (a) the port subject is `"<pool>:<sub>"` built from the pool the *verified* token came from, and user ids are globally unique, so a token minted at pool B for pool A's user maps to no principal (`LookupPrincipal` → 401); (b) per-pool keys plus `iss` → pool mean only B's key makes a B token; (c) the Authenticator requires a tenant principal's home merchant to equal the token pool's merchant. A missed read filter on codes or refresh tokens therefore gives a useless token, not an account takeover. What was missing is a guard that makes the cross-pool row itself impossible, and a check that fails when someone writes the 16th query without a filter. | schema, `storage.go`, `oidcpool.go` | `TestCrossPoolRowsRefused` fails on `1d3cd26` (cross-pool refresh token, auth request completed for another pool's user, federation state for another pool's request: all stored); `TestEveryQueryNamesItsPool` lists the two unfiltered statements | **fixed**: `schema/102_pool_guards.sql` composite keys: `(user_id, pool_id)` → `idp_users(id, pool_id)` on auth requests and refresh tokens, `(auth_request_id, pool_id)` → `idp_auth_requests` on federation states (cascade with the sweep), `upstream_pool` → `idp_pools`. A lint test parses the adapter and fails on any SQL literal on a pool-scoped table without `pool_id` (allowlist: the global sweep). Both remaining statements now filter. **Recommendation:** these two, not RLS. RLS keyed on a session variable (`SET LOCAL app.pool`) would cover reads too, but every read here runs on the pool, not in a tx (the library calls storage outside our transaction), so RLS would mean a `SET` per statement or a tx per storage call: more moving parts than the gap it closes, given (a)–(c). A pool-scoped store type (`poolStore{id}` with only filtered methods) is the next step if the adapter grows. |
| 3 | medium | **Limits are shared by every pool.** The per-IP token bucket (50/s, burst 200) and the argon2 hash slots (4 on cs-ws) are global: one merchant's login burst or a credential-stuffing run against one tenant throttles and queues logins at every merchant, and behind a proxy everyone is one IP (review-h #4). New with pools: the Sign in with Shop back channel calls the app over `INTERNAL_URL`, so every merchant's Shop code exchange lands in **one loopback bucket**; a burst of Sign in with Shop across merchants above 50/s gets 429 on the back channel and the user sees `upstream_login_failed`. Lockout counters are correctly per pool and group (probed by the builder; re-read). | `ratelimit.go`, `users.go` `hashSlots`, `federation.go` `backChannel` | By reading; h2.md notes the first two | open: limits per pool as well as per IP (a pool may hold at most half the hash slots; a per-pool bucket in front of the per-IP one), trusted-proxy config, shared store; exempt or separately bucket the back channel (or call the shop pool in process behind the same interface while both live in one binary) |
| 4 | low | A code issued just before a suspension could be redeemed after it (code TTL 60 s). The app still refuses the token (`merchant_suspended`), so no access, but the pool shouldn't mint. | `storage.go` `AuthRequestByCode` | `TestCodeRefusedAfterSuspension` fails on `1d3cd26` | **fixed**: the code claim requires the pool active |
| 5 | low | Any pool-shaped `iss` (in a bearer token) or path segment costs one indexed DB read before anything is verified, with no negative cache and no rate limit on `/api`. An unauthenticated caller can turn requests into DB reads 1:1. | `pools.go` `directory.get`, `oidcpool.go` `Verify` | By reading (h2.md "new" row) | open: negative-cache misses for a few seconds (safe: tenant pool ids are random, so nobody probes a pool id before it exists unless they guessed it) or count misses per IP |
| 6 | low | Pool lifecycle is incomplete. `idp_pools.merchant_id` is opaque (no FK, by design), there is no delete path for a merchant or its pool, and a merchant created before pools existed (an upgraded DB) has none: `GET /identity` → 404, `SetMerchantSuspended` silently does nothing. | `pools.go` | By reading | open: backfill job on upgrade (provision missing pools); a merchant delete/offboarding story (pool status `deleted`, keys retired, identities kept for the retention period) in the same tx as the merchant |
| 7 | info | Unclean paths (`/oidc//platform/…`, `/./`, `/../`) get Go `ServeMux`'s 307 to the cleaned path, which is then routed normally (the library callback stays closed there too). Not a bypass; `route`'s `RawPath` check and the pool-id shape check hold for encoded and case variants. | `pools.go` `route` | probes (curl `--path-as-is`) | open, acceptable |
| 8 | info | `Verify` doesn't check that the token's user is in the group its client logs in (staff via `merchant-admin`, customers via `storefront`). The login step and Sign in with Shop enforce it, so this is depth only; and a mismatched token would still map to that user's own principal. | `oidcpool.go` `Verify` | By reading | open |
| 9 | info | Carried from h unchanged, now per pool: loopback redirect looseness (review-h #7), discovery advertises unserved grants (#10), stateless access tokens outlive disable/suspension for 15 min (#8, the app covers suspension), one `ISSUER_SECRET` for every pool's keys and federation secrets (h2.md says so), login CSRF/session for the password step (19). | | | open |

Checked and fine:
- **Codes across pools**: M1's code at M2's and the shop pool's token endpoints → 400, and still redeemable at M1 afterwards (not burned by the foreign attempt).
- **Refresh tokens across pools**: M1's refresh token at M2 and at shop → 400; `/revoke` at M2 with M1's token leaves M1's family alive; M1 refresh still 200.
- **Userinfo / API**: M1's access token at M2's `/userinfo` → 401; on M2's merchant endpoint → 403.
- **Clients across pools**: `platform-cli` at a tenant `/authorize` → 400; staff via `storefront` and customers via `merchant-admin` → 401; M1 staff at M2 → 401; a platform account at workforce → 401; an agent's `client_credentials` at tenant, shop and workforce pools → 401, at platform → 200.
- **Issuer-shaped paths**: upper-case pool ids (`PLATFORM`, `PL_…`), `%2F`, `%70latform`, unknown `pl_…`, trailing dot, space → 404. Forged tokens (another pool's key, another pool's `iss`, trailing `/`, unknown pool) are the builder's `TestTokensStayInTheirPool`; re-read, sound.
- **Sign in with Shop**: the shop pool refuses M1's federation client with M2's callback (exact redirect); M1's upstream code at M2's callback with M2's own state and cookie → 401 (the code belongs to `fed_M1`, M2's RP authenticates as `fed_M2`); M1's full callback replayed at M2 → 400 and still completes at M1; no cookie / another round trip's cookie → 400 without burning the state; a staff auth request can't take the Shop path; M1's auth request id at M2's `/login/shop` and `/login` → 400; `/login/shop` at the shop pool → 404. Upstream leg: state 256-bit, stored hashed, single-use, pool- and cookie-bound; PKCE S256; nonce checked by `rp` and again explicitly; ID token verified against the shop JWKS with `iss`, `aud`, `azp`; the back channel goes only to the shop issuer (no caller-controlled URL); every redirect is to a registered URI or the shop authorize URL built from config, so **no open redirect**. Linking is by `(pool, shop subject)` only; a local customer with the same email stays separate (suite rule 7).
- **Provisioning atomicity**: verified. `createMerchant` runs `ProvisionMerchant` with the executor's tx in ctx (`db.WithTx` before `op.Run`); pool row, federation client and first key all go through `db.TxOr`; the directory cache only caches committed rows it read itself; `TestProvisioningIsTransactional` re-run. Suspension writes the pool status in the same tx as the merchant's; login, Shop start/callback and refresh re-read it from the DB, so a suspension is effective on every instance at once (the 30 s directory cache is advisory only).
- **Pool-selecting headers**: `Host`, `X-Forwarded-Host`, `Forwarded`, `x-zitadel-*` don't change discovery or the principal (builder's probe, re-run).

## Security checklist per pool (h's 20 + review-h's 21–23), after this review

| # | item | h2.md | now |
|---|---|---|---|
| 1 | issuer from headers | holds per pool | holds; re-probed |
| 2 | exact redirect | holds | holds; federation client swap refused live; loopback looseness unchanged (#9) |
| 3 | PKCE S256 only | holds, upstream too | holds |
| 4 | encoded-path bypass | holds | holds; unclean paths 307 to the clean path (#7) |
| 5, 21 | single-use codes, code only to the login | holds per pool | holds; cross-pool code attempts don't burn it; **no code redeemed at a suspended pool (#4, fixed)** |
| 6 | machine refresh tokens | holds | holds |
| 7, 8 | key race, rotation | per pool | holds |
| 9 | timing | holds | holds |
| 10, 22, 23 | rate limits | lockout per pool; IP bucket shared | **shared IP bucket, hash slots and back-channel bucket across pools (#3, open)** |
| 11 | revocation | suspension refuses refresh | plus: **disabled Shop account refuses refresh of its linked identities (#1, fixed)** |
| 12 | ID token as access token | holds, clients per pool | holds; re-probed clients per pool |
| 13, 14 | CORS, grants | unchanged | unchanged |
| 15 | keys at rest | one secret | unchanged |
| 16 | machine client secrets | per pool and kind | holds |
| 17 | refresh theft | holds per pool | holds; family revoke now pool-filtered |
| 18 | hashing as DoS | slots shared | shared (#3) |
| 19 | login CSRF, sessions | open; Shop leg bound | unchanged |
| 20 | test mode | `login-hint` added | unchanged (test-only endpoint, behind the test secret) |
| new | pool from unverified `iss` | one DB read | open (#5) |
| new | cross-pool confusion | query filters | **filters + composite keys + lint (#2, fixed)**, on top of subject qualification and per-pool keys |
| new | federation | state/cookie/pool/nonce | holds; deprovisioning gap (#1) fixed |

New items for the list: **24** upstream account status reaches federated sessions (#1); **25** cross-pool rows refused by the schema, unfiltered queries fail CI (#2); **26** limits per pool, not only per IP (#3).

## Spec conformance and module boundaries

- **Suite:** 401/401; no test looked wrong against §16. §16.3: `201 {status: "active"}`, atomic, no failure window: verified by code and test. §16.1 "the app picks the pool, never the caller": holds (path → directory; `iss` → directory; headers ignored).
- **Modules don't know the issuer.** They see opaque subjects and, in one place, an issuer string: `merchants` `GET /identity` returns `TenantPools.MerchantIssuer` (the spec asks for it). What leaked or changed shape, for the record:
  - **Port semantics changed:** `identity.Token.MerchantID` was "an extra tenant check only"; for pool-per-merchant adapters it is now the pool's merchant and the Authenticator *requires* it for home-merchant principals. Doc comment updated in this review; stack `i` must fill it from the instance the same way.
  - **Two styles of wiring `TenantPools`:** `merchants` gets it injected, `platform` type-asserts its `IdP` field to `identity.TenantPools`, and `testsupport` duck-types `LoginHint`. Works; pick injection everywhere if this graduates.
  - **Module → module:** `orders` imports `customers` (`EnsureShopCustomer` on a Shop-token order). A domain dependency, not identity knowledge, but the first cross-module call in this direction.
  - **Spec-driven, shared with stack i:** memberships table, `HomeMerchantID`, `ShopAccountID`, `merchant_customer_id`, `MULTI_MERCHANT`. Not issuer knowledge.
- **Migration 003 is shared and one-way** (renames `users.merchant_id`, nulls the old column's successor): once h2 merges, a/a2/h databases migrate on their next start, and main's code from before the merge can't run on a migrated DB. Merge all Go stacks together; don't point an older image at a migrated volume (this review ran the regression on fresh volumes for that reason).

## Pattern verdicts

| pattern | verdict |
|---|---|
| pools as rows, issuer per pool at `PUBLIC_URL/oidc/<pool>` | **works**; one provider serves every issuer (`IssuerFromRequest` + pool in ctx), discovery/JWKS/token/userinfo per pool all correct. Path-based issuers keep one TLS name; custom domains are an alias table later |
| per-pool signing keys | **keep**; the pool's keys and `iss` must agree, so a merchant's key leak or rotation stays that merchant's |
| subject qualified by the verified pool (`<pool>:<sub>`) | **the best idea in h2**: the app can't map a token to another pool's principal without any module knowing pools; it's what makes a missed query filter harmless |
| pool filters in storage | necessary but not sufficient on their own; with composite keys and the lint test they're now hard to get wrong |
| tenant pool as a confidential OIDC client of the shop pool | **works and is honest**: a real round trip over HTTP, same code if Shop moves to global services. Needs the upstream-status rule (#1) and its own limiter budget (#3) |
| provisioning in the merchant's transaction | **the strongest property vs stack i**: no provisioning state, no compensation, ~35 ms; 10 000 merchants is just rows |
| limits | the one place pools made things weaker; needs per-pool budgets |

## Verdict: h2 as the custom-identity option

**Agree with the builder: the multi-pool model is the cheap part of owning identity, and h2 carries it well.** After this review:

- Cross-pool isolation is sound in depth: subject qualification + per-pool keys + home-merchant check in the app, now with schema-level composite keys and a lint that fails on an unfiltered query. 42 live attacks and the suite found no way across.
- The real gaps were lifecycle, not protocol: what a Shop account's deletion does to its links (fixed for sessions; the app's records still need a policy) and what a merchant's deletion or an upgraded DB does to pools (open). Both are product decisions that Zitadel instances would also force.
- Still owed before production, beyond everything review-h listed (login page + CSRF, MFA/passkeys, reset, admin UI, trusted proxy): **per-pool limits** (#3) and a pool offboarding story (#6).
- So h2 stays the stronger option against `i` on cost and atomicity (rows vs instances, one transaction vs provisioning states), with the same caveat as h: it's an auth server we own, and each new login feature needs an auth-focused review. The structural guards from this review should go in with it.

## Fixed in this review (commits on `review-h2`)

1. `6a35df1` review probes (`stacks/h2/review-probe.mjs`, 42/42 hold).
2. `6e95307` composite keys against cross-pool rows (`schema/102_pool_guards.sql`) and the pool lint (#2); Shop account disable ends tenant sessions and can't revive a disabled tenant identity (#1); no code redeemed at a suspended pool (#4). Tests: `review_test.go` (4 tests, each fails on `1d3cd26`).
3. `06f886f` `identity.Token.MerchantID` doc: load-bearing for pool-per-merchant adapters.
4. This report.
