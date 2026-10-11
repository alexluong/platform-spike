# Review of stack a (Go + Zitadel + SpiceDB)

Reviewed 2026-10-11 on branch `review-a` (from `go-a` at 5350c88). Read the spec, AMBIGUITIES, `results/a.md`, all of `go/`, `stacks/a/`, `conformance/stacks/a.ts`. Probed the running stack with three new conformance tests (all failed before the fixes).

**Suite after fixes:** 344/344 (341 original + 3 new), full run including the 65 s break-glass expiry, stack rebuilt from this branch. Five more full runs: see the end of this file. `go test ./...` passes (new: `orders/mulAdd`, app-install precheck cases).

## Findings, by severity

### High

1. **Ex-member keeps access through an agent (fixed).** `go/internal/modules/agents/agents.go:96` (was: any `agent.grant` holder could grant *any* agent of the merchant).
   Scenario: staff member B registers an agent (B holds its client secret). Admin A grants that agent `order.view` at a store. B is removed from the merchant. The agent still acts on A's grant, so B, now outside the merchant, keeps reading orders with the secret. The grant check only follows the *grantor's* rights. Reproduced: new test `agents.test.ts` "an agent whose registrant left the merchant…" got 200 after removal.
   Fix: only the agent's registrant may grant it (403 otherwise). This also removes the `agent_grantor_conflict` check, which was a check-then-insert with no lock: two users granting the same agent at once both passed, and SpiceDB's set algebra then combined one user's grant with the other's roles (a refund limit of 100 could become unlimited). With one possible grantor per agent the race can't happen.

2. **Outbox dropped events after 10 failed attempts (fixed).** `go/internal/outbox/relay.go:83` (was: `attempts >= maxAttempts` → marked processed).
   Attempts were counted by *every* drain: the 1 s background loop and each write request's own drain. A SpiceDB outage of ~10 s, or a handful of concurrent writes during a short blip, used up the 10 attempts of the head row. That row was then marked processed and never applied. If it was `app.uninstalled`, `agent_grant.revoked`, `assignment.deleted` or `merchant.suspended`, the access stayed in SpiceDB **forever**, while the DB said it was gone. Nothing would ever reconcile it.
   Fix: transient errors are retried forever, in order, with a loud log at 10 attempts. Only errors marked `authz.ErrPermanent` are dead-lettered (`last_error` prefixed `dead:`). The SpiceDB adapter marks `InvalidArgument`, `FailedPrecondition`, unknown events and unknown platform roles as permanent (`spicedb.go:231`). The trade-off is written into the port's doc comment: a stuck event now blocks later events, which fails safe (loud) instead of silently diverging. Not covered by a test: the relay has no DB test harness. Verified by reading the code.

3. **Order total overflow (fixed).** `go/internal/modules/orders/orders.go:104`. `qty: 2^62` on a 1000-cent product created an order of 4.6e18 items with `totalCents: 96000` (int64 wrap). A customer chooses the total they pay; capture and refund then work on the wrapped amount. Fix: qty must be 1..1e6, and the total is overflow-checked (400). Regression: `orders.test.ts` "a quantity whose total overflows → 400", plus Go `TestMulAdd`.

### Medium

4. **Break-glass reads through `canMany` were not audited (fixed).** `go/internal/core/executor.go:137`. `GET /api/merchants/:mid/stores` is `AuthAny` + `canMany`, so the executor's audit hook (which only ran for `AuthAction` ops) never fired. Support staff listed a merchant's stores under break-glass with no audit entry (SPEC §7: "every request made under break-glass"). Fix: `Req.CanMany` audits the first allowed merchant-data check of a request, so any future list op gets audited too. Regression: `break-glass.test.ts` "listing stores … is audited too". `/api/me/permissions` under break-glass is now audited as well, which is consistent with the spec.

5. **Apps had only one tenant check (fixed).** `go/internal/core/executor.go:179`. Users and agents get a SQL merchant check before the engine. Apps (no merchant) went straight to SpiceDB, so one wrong `store#install` relationship would open another merchant's store. This is SPEC §1.6 "twice". Fix: the precheck requires an `app_installs` row for (app, store), and denies apps at merchant scope (AMBIGUITIES #34). Go cases added to `TestCanPrechecks`.

6. **Read-your-writes hole when the in-request drain fails (not fixed).** `executor.go:349`. The tx has committed, the drain fails (or is blocked behind a stuck event), and the request still returns 2xx. The next request doesn't see the change: a 204 on uninstall or revoke while the app or agent keeps access until the relay catches up. With fix 2, "until" is now bounded by engine availability instead of being "maybe never", but the response still lies. Options: return 503 `sync_pending` with the committed resource id, or make the next check for the affected subject fall back to DB truth. The spec should say which.

7. **Test mode is on by default, with a known secret (not fixed, spike config).** `stacks/a/compose.yaml:106`: `TEST_MODE: "1"`, `TEST_SECRET` defaults to `test-secret`, and port 8081 is published on the VM. Anyone on the tailnet can `POST /api/_test/users` with `kind: platform, platformRole: platform_admin`. They can also `GET /api/_test/driver-config`, which returns the **IAM_LOGIN_CLIENT PAT** (`zitadel.go:52`). With that token you can create sessions and finalize auth requests: log in as any user without their password. Fine for the spike. It must never ship this way; at minimum, generate the secret per stack.

8. **The access-token check is an ID-token verifier (not fixed).** `zitadel.go:44`. go-oidc's `IDTokenVerifier` checks signature (RS256), `iss`, `exp` and that `aud` contains the project id. It doesn't check `azp`/client or token type. Any client in the project (or any client allowed to request the project audience scope) mints tokens the API accepts, and ID tokens pass as access tokens. Only a known `sub` maps to a principal, so this isn't an escalation in the spike. In a real setup with third-party OAuth apps in the same project, it is a confused-deputy risk. Use a JWT access-token profile check (`typ: at+jwt` where the IdP sets it, an `azp` allowlist) or introspection.

### Low

9. **Concurrent member removal vs assignment (fixed).** `roles.go:299`. `assign` read the assignee's membership without a lock. A removal committing in between left an assignment (and a SpiceDB binding) on a non-member. The tenant precheck blocked it, but re-adding the user revived a role the remover meant to take away. Now `FOR SHARE`.
10. **Last-owner rule can deadlock (not fixed).** `roles.go:352` locks the target assignment, then `:379` locks all owner assignments. Two concurrent unassigns of two different owner assignments deadlock, and Postgres aborts one with a 500. The rule still holds. Lock the owner set first (or the merchant row).
11. **GET routes lock rows before authorization (not fixed).** `scope.go:75` (`orders … FOR UPDATE`), `catalog.go:28` productTarget, `delivery.go:30` shipmentTarget. Any authenticated principal, including another tenant's user, can hold a row lock on any order or product id for the duration of a SpiceDB round trip. Use `FOR UPDATE` only on mutating ops.
12. **IdP side effects inside the DB tx (not fixed).** `agents.go:61`, `platform.go:149`: `CreateClient` runs before the insert. If the tx fails, the Zitadel machine user is orphaned. This is an external write outside the outbox. Acceptable for registration, but it's the one place where §1.4's "outbox for external writes" isn't followed.
13. **Role delete vs concurrent assign (not fixed).** `roles.go:308` `Load` doesn't lock the role. An assign racing a delete leaves an assignment pointing at a deleted role id (no FK, since `role_id` holds system ids too). It grants nothing (empty `role:` object) but stays in the DB. Use `FOR SHARE` on the role row, or an FK for custom roles.
14. **Suspended merchants' public product lists stay visible**, and an `AuthAny` list (`/stores`) answers 200 `[]` instead of 403 `merchant_suspended` for a suspended member. Unspecified (AMBIGUITIES #29); worth a line in the spec.
15. **`expiresInSeconds` overflow (fixed)**: values above ~9.2e9 wrapped the `Duration`. Now capped at one year (400).
16. **500s echoed internal errors (fixed)**: `AsErr` put `err.Error()` (SQL, gRPC, Zitadel bodies) in the response. They are now logged only.
17. **Audit list order (fixed)**: sorted by `id` while the suite checks `at` newest first. Two concurrent requests commit out of `at` order. Now `ORDER BY at DESC, id DESC`.

## Concurrency and failure: what breaks with 2 app instances

- **ZedToken is per process** (`spicedb.go:35`). Instance B checks `at_least_as_fresh(B's last token)`. When A has just revoked something, B may answer from a revision before the revoke. Here the window is the configured quantization (`--datastore-revision-quantization-interval=100ms`). At SpiceDB's default (5 s), a revoked app or agent keeps working on the other instance for up to 5 s. Fix: store the token in the DB (a one-row table written in the drain tx, or per merchant) or send it back to the client as a header/cookie.
- **Relay:** correct with N instances: the advisory lock gives one drainer at a time, and events are applied in id order. But that same lock is **global**, so every write request's drain waits on every other's. Write latency scales with total write load. Partition the lock (per merchant) if that matters.
- **Out-of-commit-order ids:** `bigserial` ids are assigned at insert, not at commit. A drainer can apply id 11 before id 10 commits. This is safe today only because events carry full state and the conflicting writers are serialized by row locks (role UPDATE before Emit). A new module that emits before taking its row lock would break ordering silently. Write that rule down, or order the drain by `pg_xact_commit_timestamp` (already enabled: `track_commit_timestamp=on`).
- **System-role sync at startup:** each instance enqueues the system roles. Harmless (idempotent), just noise.

## Code quality (what a new teammate or agent would trip on)

- `Req.Decode` is called 2–3 times per request (in `Target`, `Context` and `Run`; `roles.update` decodes twice into different shapes), and some calls ignore the error (`_ = r.Decode(&in)`). Decode once into the op.
- `Op.CustomerAlt` plus `AuthAny` are escape hatches: the authorization decision moves into `Run`, and nothing enforces it there. `/api/agents`, `/api/stores/:sid/orders` and `/api/me/orders` each re-implement kind and suspension checks by hand. A typed "SQL-checked action" (`order.place`, `order.view_own`, `agent.register`) in the registry would keep every op visible in one table.
- The SpiceDB `Unlimited = 2^53` constant lives in `core` "so engines compare it correctly": engine knowledge in the kernel. The refund comparison belongs in the adapter.
- `gofmt -l` lists 3 files (`zitadel/bootstrap.go`, `stores.go`, `testsupport.go`), all pre-existing.
- `results/a.md` describes `agent_grantor_conflict`. That is now replaced by the registrant-only rule (finding 1).

## Pattern verdicts (SPEC §1)

| # | pattern | verdict |
|---|---|---|
| 1 | Action = unit, one executor, outbox in tx | **holds**, bent at the edges: `AuthAny`/`CustomerAlt` ops decide in `Run`; IdP client creation is a side effect outside the outbox |
| 2 | One `can()` in AuthZEN shape | **holds**: modules only call `r.Can`/`HoldsAll`; prechecks (kind, scope, tenant, suspension) run before the engine; port is engine-neutral |
| 3 | Custom roles are data | **holds**: schema generated from the catalog, golden-tested and `zed validate`d; merchants only write rows |
| 4 | App DB truth + outbox + read-your-writes | **was broken, now bent**: dropped events (fixed); 2xx on failed drain (open); ZedToken in memory = single instance only; global drain lock |
| 5 | Three checks | **holds**: kind/scope precheck, relationship in SpiceDB, refund condition as a caveat; agents get the grantor's limit through the delegate path |
| 6 | Tenant isolation twice; customers not in engine | **was bent for apps, now holds**: SQL install check added; customers never reach SpiceDB (`subjectType` has no customer) |
| 7 | Composition root by hand | **holds**: one `main`, two switches, no DI; package-level vars are read-only catalog data |

## What I'd change in the spec

1. **§6: who may grant an agent.** Say "only the user who registered the agent". Grants lend the grantor's rights to the credential holder, so lending them to someone else's credential outlives that person's membership. It also removes the multi-grantor case that set-algebra engines can't model (stack a's `agent_grantor_conflict`).
2. **§1.4: failure semantics.** State that sync events are never dropped on transient errors, define dead-lettering (permanent errors only, visible somewhere), and say what a write returns when its own drain fails (2xx vs 503). Today the spec only says "a background relay retries".
3. **§1.4: multi-instance read-your-writes.** Require the consistency token to survive across instances (DB or client round trip), or explicitly scope the spike to one instance. The test suite can't see this.
4. **§1.6: apps.** "Every query is scoped by merchant" has no meaning for merchant-less principals. Say that the app's SQL boundary is its install.
5. **§7: break-glass audit.** Say that list endpoints and `/api/me/permissions` count as requests under break-glass (one entry per request, action = the first merchant-data action checked).
6. **§9: input bounds.** `qty`, `priceCents`, `expiresInSeconds`, `minutes`, `refundLimitCents` need upper bounds (overflow), and the spec should name the 400 code.
7. **§11: test mode.** Require a random `TEST_SECRET` per stack (no default), and say that test-mode endpoints may expose IdP credentials, so the app port must not be reachable beyond the test host.
8. **§10: token validation.** Name the checks: `iss`, `aud`, `exp`, alg allowlist, **and** token type/`azp`. "JWT via JWKS" alone lets ID tokens and other clients' tokens through.
