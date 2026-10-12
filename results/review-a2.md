# Review of stack a2 (Go + Zitadel, one organization per merchant + SpiceDB)

Reviewed 2026-10-13 on branch `review-a2` (from main b5c545f). Read the spec (§15 in full), `results/a2.md`, `results/a.md`, `results/review-a.md`, the a2 diff (`4f5ea6d..b5c545f` over `go/`, `stacks/a2`, `conformance/stacks/a2.ts`), the Zitadel adapter, the relay and the invitations module. Probed the running stack with ad-hoc scripts (Zitadel API with the bootstrap PAT, a headless login like the driver's, the app API), including a Zitadel outage and an app crash with identity rows pending.

**Suite after fixes:** `STACK=a2` **390/390** (full, incl. the 65 s break-glass expiry, 88 s), `ps-a2` rebuilt from this branch. The fix touches shared module code, so `ps-a` was rebuilt from this branch too: `STACK=a` **362/362** (28 `idp-tenancy` skipped); `ps-a` left running. `go test ./...` passes (`zed validate` ran; `fga model test` skipped: no `fga` CLI on the Mac, the stack b image build runs it).

## Findings, by severity

### High

1. **A member added while the merchant was being suspended could log in to the suspended merchant (fixed).** `go/internal/modules/merchants/merchants.go` `addMember`.
   The executor's suspension check reads `merchants.status` without a lock. An add that passed it before the suspend committed, but committed after, wrote its `member.added` row after `merchant.suspended` (or committed it after the suspend's drain). The identity sync then applied the suspension fan-out first (it deactivates the authorizations it finds), then created the new member's authorization, active, in the deactivated org. Zitadel's login check reads only the authorization's own state: a user whose only authorization comes from a **deactivated** org logs in (checked directly against Zitadel). The new member's `account` authorization was never touched either.
   Probe: 20 concurrent `POST /members` + a suspend: 18 adds got 201, all 18 outbox rows landed after `merchant.suspended`, and **18/18 new members could log in** to the suspended merchant until reinstate. The API still answered 403 `merchant_suspended` (no data exposed); §15.3 was broken silently for the whole suspension.
   Fix: `addMember` locks the merchant row `FOR SHARE` and refuses a suspended merchant, as invitation accept already did. A suspend either waits for the join (its row then lands after `member.added`) or wins (the add gets 403). After the fix: 0 leaks in 11 probe runs at different timings (adds all refused, or all committed before the suspend and covered by its fan-out).

2. **Test mode still hands out password-less login for any identity, including the Zitadel IAM owner (not fixed: spike config, P5).** `zitadel.go` `DriverConfig`, `stacks/a2/compose.yaml` (`TEST_MODE: "1"`, `TEST_SECRET` default `test-secret`).
   `GET /api/_test/driver-config` returns the `IAM_LOGIN_CLIENT` PAT. With it, a session created with a user check alone (no password) finalizes an auth request: checked, tokens for a merchant user with no password. The first-instance human `zitadel-admin@platform.<host>` exists with Zitadel's default password `Password1!` (the password check passes) and is IAM owner, and port 8089 publishes all of Zitadel (console at `/ui/console/`, management/admin APIs). In a2 the IAM owner controls every merchant org, so the blast radius is every tenant's identity side. The app's own `/api/_test/users` still mints `platform_admin`s too. Same as review-a 7; nothing changed.

### Medium

3. **Suspend answers 200 while the merchant's people and agents can still get tokens (not fixed: P6).** `core/executor.go` (drain after commit, failures only logged).
   Checked with Zitadel stopped: `DELETE /members/:uid` → 204, suspend → 200 (both fast: connection refused). The identity rows stayed pending in order (`member.removed` with attempts climbing, `merchant.suspended` behind it); old tokens got 403 `merchant_suspended` from the DB. Then the app was killed with the rows pending, Zitadel started, the app started: pending rows went to 0 within seconds, the owner's login was refused (`GrantRequired`), the agent's `client_credentials` refused (`User.NotActive`), the removed member could still log in (correct: no longer a member). So retry-forever, in-order and crash recovery hold; the only gap is the response. Fail-open at the IdP, closed at the API for the whole outage. With a **hanging** Zitadel (not refusing), each call waits for the 15 s HTTP timeout inside the request.

4. **The suspension fan-out reads Zitadel's projection, not the app's members (not fixed).** `orgs.go` `merchant.suspended`: `ListAuthorizations` (eventually consistent, `limit: 1000`, no pagination). `member.added` doesn't wait for its authorization to show in that projection, so a member added just before a suspend can be missing from the list and keep login. Not reproduced (the suspend's org-state wait comes first and usually covers the lag; 0 misses over ~160 members added in the probes). A merchant with more than 1000 members leaves the rest active. Fixes: wait for the projection in `member.added` (as `grantAccount` does), page the list, or carry the member subjects from the app DB in the event.

5. **The identity drain holds a DB transaction and the partition lock across Zitadel calls and projection polls (not fixed).** `outbox/relay.go` `batch` + `orgs.go` waits (up to 10 s per row, `retryLag` 5 s). The request that wrote the rows waits on it; the background loop drains partitions one after another, so one stuck merchant (a `not_found` that retries 5 s per pass) adds seconds to every other merchant's leftover drain. No deadlock: the request's own transaction is committed before its drain. Apply outside the lock (claim rows, call Zitadel, mark done) or drain partitions concurrently if it matters.

### Low

6. **The machine-client rule (username prefix `app_`/`ag_`) can't be abused through the API.** `zitadel.go` `machineClient`. Only a Zitadel admin can create machine users, OIDC client ids are generated (a human's token always names the login app), and the subject must still map to an app or agent row, so a foreign machine user named `app_x` gets 401. The rule is redundant with the subject lookup. The precise check (token `client_id` = the client id stored on the app/agent row) is still the cleaner one. Other P7 checks verified live: the ID token from the same login → 401 (it carries `at_hash`/`azp`); RS256 only; `aud` must contain the project.
7. **Tenant claim picks "the first" org** from the `member` role map (`tenantClaim`). With two authorizations (a `member.removed` still pending, plus the new merchant's), the choice is random: an intermittent 401 until the old one is deleted. Checked the main case: a token naming merchant 1, user now in merchant 2 → 401.
8. **Refresh tokens: latent in a2.** The conformance OIDC app has no refresh grant (`offline_access` returns no refresh token), so the "suspended member refreshes" gap the builder found (Zitadel doesn't re-check authorizations on refresh) can't be reached here. If refresh is enabled, the app's 403 is the only guard, as the builder says.
9. **`/healthz` fails when Zitadel is down** (pre-existing from a: it pings the IdP). During the outage the API kept serving with cached JWKS, but an orchestrator would restart healthy app instances. Spec §9 names app, DB and engine only.
10. **Apps' machine users are still created active before the insert** (review-a 12 for apps; agents fixed by create-disabled + `agent.registered`). Code-checked: a rollback leaves an inert, deactivated agent; a failed `DeactivateUser` returns before a secret exists.

### review-a findings, status in a2

| review-a | status |
|---|---|
| 6 2xx on failed drain (P6) | open, worse with an IdP consumer (finding 3) |
| 7 test mode / IAM_LOGIN_CLIENT (P5) | open (finding 2) |
| 8 ID-token verifier (P7) | **fixed** (verified live) |
| 10 last-owner deadlock | open (`roles.go` locks the target, then the owner set) |
| 11 GET routes lock rows before authz | open (`scope.go:75`, `catalog.go:31`, `delivery.go:34`) |
| 12 IdP writes outside the outbox | **fixed for agents**, open for apps |
| 13 role delete vs concurrent assign | open (no lock on the role) |
| 18 agents administer (P1) | open (`NotForApps` still apps-only) |
| ZedToken per process; global authz drain lock | open (the identity consumer is partitioned, authz is not) |

### Checked, no finding

- Cross-tenant invitations: another merchant's `member.manage` holder listing (404), cancelling through its own merchant's path (404), accepting as a non-invitee (404); accepting twice → 409; platform staff accepting → 403; email matches case-insensitively.
- A member removed while holding a token: `/api/me` drops `merchantId`, merchant reads 404.
- Suspended member login refused at finalize (`GrantRequired`); agent `client_credentials` refused (`NotActive`); reinstate restores both.
- Invitation accept into a suspended merchant → 403 (row locked `FOR SHARE`).
- Cross-partition ordering (a user removed from one merchant, added to another): different authorizations; recorded by the builder, harmless.
- Permanent-error classification: only `invalid_argument`/`unimplemented` dead-letter; `not_found`, `failed_precondition`, auth errors retry forever. Handlers are idempotent. Zitadel accepts `CreateAuthorization` and `ReactivateUser` in a deactivated org (probed), so an event that lands after a suspension doesn't wedge its partition; it applies, which is what made finding 1 a leak instead of a stall.

## Pattern verdicts (SPEC §1)

| # | pattern | verdict |
|---|---|---|
| 1 | Action = unit, one executor, outbox in tx | **holds**; the outbox now routes one row per consumer. Agent creation still calls the IdP inside the tx (mitigated: created disabled). |
| 2 | One `can()` in AuthZEN shape | **holds**: unchanged; Zitadel adds no authorization decision. |
| 3 | Custom roles are data | **holds**: Zitadel's project roles are used only as login entitlements (`account`, `member`), never for §3. |
| 4 | App DB truth + outbox + read-your-writes | **bent**: a second consumer with the same rules (verified under outage and crash). Read-your-writes for login comes from projection polls. Open: 2xx on failed drain, per-process ZedToken. The suspension check without a lock was a real ordering hole for the IdP consumer (fixed for member add). |
| 5 | Three checks | **holds**; the token's tenant claim is a fourth, optional check. |
| 6 | Tenant isolation twice | **holds**: SQL + engine unchanged; the IdP's org is a third, coarser fence (login, agent tokens), never the source. |
| 7 | Composition root by hand | **holds**: one more relay wired in `main`. |

## Verdict: do organizations per merchant make the spec cleaner? (§15, Zitadel)

**No, not for this platform.** The question was whether letting the IdP own tenancy removes work. In a2 it removed **nothing** (0 lines of app code deleted; +1250 lines including compose and driver, ~1000 in Go) and added a second copy of tenancy state.

- **What it removed:** nothing. `users.merchant_id`, `merchants.status` and the member/suspension logic stay in the app because the SQL tenant check, the one-merchant rule and the row locks (last owner, assign vs remove, and now add vs suspend) need them in the request's transaction. Zitadel can't join that transaction and serves eventually consistent reads, so "the IdP as single writer" was rightly rejected. Membership now lives in two places (app DB = truth, Zitadel = synced copy): the "kept in two places" smell §15.1 warns about for roles, here for membership.
- **What it pushed back:**
  - **sync:** a second outbox consumer with routing, per-merchant partitions, idempotent handlers, error classification, and projection polls for read-your-writes on login;
  - **fan-out:** suspension had to deactivate every member's authorizations one by one, because org deactivation doesn't reach cross-org authorizations (confirmed: a deactivated org's authorization still logs its user in). That is the same fan-out as per-user deactivation in stack a's single org; the org only covers the agents that live in it;
  - **residency workaround:** Zitadel can't move a user between orgs and the spec's users exist before joining, so merchant users live in a `people` org and membership is a cross-org authorization. Every human needs an `account` authorization from the platform org just so login can be policed by authorizations;
  - **a new race surface** (finding 1) and a failure window where the IdP is fail-open (finding 3).
- **What Zitadel gives that Ory OSS can't:** a tenant object with a lifecycle enforced at token issuance (an org's resident machine users get no tokens once it's deactivated, immediately, from the event store); "check authorization on authentication" (the IdP itself refuses the login); project grants and authorizations as a listable per-tenant membership record with the granting org in the token. Unused by a2 but the real reasons to pick orgs: **per-org identity providers (a merchant brings its own Okta/Entra SSO), per-org login and password policies, branding and domains (domain discovery), and delegated admin** (org managers run their own users in the console). Kratos/Hydra OSS have no organizations at all; Ory Network's organizations are a paid B2B-SSO feature, not membership.
- **Is it worth it here?** Not with the current spec: users exist before joining, belong to at most one merchant, and the app owns authorization. Org-per-merchant then costs a sync consumer, a fan-out and a workaround to deliver what stack a gets by deactivating a merchant's users and machine users in one org. It earns its keep when merchants need **their own SSO or login policy, or to administer their own staff in the IdP**, and when merchant people are **created resident** (sign-up through the merchant's invitation of a new email), so that deactivating the org actually covers them. Recommendation: keep `a`'s single org; switch to orgs per merchant when per-merchant SSO becomes a requirement, and design onboarding for resident users at that point.

## What I'd change in the spec

1. **§15.1 org residency.** "Members are users in the organization" can't hold when users exist before they join and the IdP can't move users. Say: membership is the IdP's grant to the user in the merchant's organization (Zitadel: an authorization; residency optional). Or require resident users (invite-new-email sign-up) and drop "add an existing user" for `a2`-style stacks. Record which.
2. **§15.3 "can't log in" = no new sessions.** Existing access tokens until `exp` and refresh tokens (Zitadel doesn't re-check authorizations on refresh) are covered by the API's 403, which stays the guarantee. Either say so, or require refresh disabled/short-lived for merchant users.
3. **§15.1 / §1 operational rules: writes that give a merchant's people IdP access are serialized against suspension.** Any membership add or agent enable locks the merchant row (or re-checks status under lock), so the IdP never learns of a join after the suspension's fan-out (finding 1). The executor's unlocked status check is fine for app reads, not for IdP side effects.
4. **§14 P6 applies to the identity consumer.** A suspend whose IdP sync failed answers 200 while the merchant's people still get tokens. Either 503 `sync_pending`, or state the window ("the API denies at once; the IdP follows when it's reachable").
5. **§15.2 invitations into a suspended merchant** → 403 `merchant_suspended` (a2 and d agree). Creating one is already blocked by §7.
6. **§15.2 invitation statuses:** `pending | accepted | cancelled`; accepting a non-pending one → 409 `invitation_not_pending`; someone else's → 404 (not revealed). Consider an expiry (invitations never expire today).
7. **§9 `/healthz`:** app, DB and engine only, as written. Go pings the IdP too, so an IdP outage marks working instances unhealthy.
