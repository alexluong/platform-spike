# Review of stack b (Go + Ory Kratos/Hydra + OpenFGA)

Reviewed 2026-10-11 on branch `review-b` (from main at 912b572). Read the spec, AMBIGUITIES, `results/b.md`, `results/review-a.md`, `go/internal/adapters/{ory,openfga}`, the model and `.fga.yaml`, `stacks/b/`, `conformance/stacks/b.ts`. Shared modules/kernel not re-reviewed (review-a). Probed the running stack from the Mac (Hydra admin, ID tokens, login bursts) and OpenFGA from a curl container on `ps-b_b-net` (real error codes for each failure case).

**Suite after fixes:** 349/349 (71 s, full run incl. the 65 s break-glass expiry), stack rebuilt from this branch; the baseline before the fixes was also 349/349. Only b adapters changed, so stacks a and c were not rebuilt. `go test ./internal/adapters/...` passes (new: `ory/TestCheckAccessToken`, `openfga/TestApplyClassifiesErrors`, `openfga/TestSameModelSeesWildcardChange`; `fga model test` runs locally too). After the rebuild the bootstrap kept the same OpenFGA model id, so the model compare and the new model request still match the server.

## Findings, by severity

### High

1. **Hydra admin API is open to the LAN/tailnet: anyone can log in as anyone (not fixed, spike design).** `stacks/b/compose.yaml:78` publishes `4445:4445` on `0.0.0.0`; Hydra OSS admin has no auth. Verified from the Mac: `GET :4445/admin/clients` → 200, and `POST /admin/clients` with a chosen `client_id` → 201. With that API, a caller can:
   - accept any login challenge with any `subject` and get tokens for any user, `platform_admin` included, with no password and no test secret (the driver does exactly this; the app never sees Kratos);
   - rotate or delete app and agent clients (`PUT/DELETE /admin/clients/{id}`) and take over their identities;
   - create clients with any id (this is what made finding 2 exploitable).

   This is worse than review-a #7 (there you needed the test secret). `results/b.md` says "must never leave the test host", but the port is reachable beyond the host today. Fix (not small): a login/consent stand-in that runs inside `b-net` behind `X-Test-Secret` (a tiny service, or a test-mode route on the app that calls Hydra admin internally). Then 4445 stays unpublished.
2. **ID tokens were accepted as access tokens (fixed).** `go/internal/adapters/ory/ory.go:56` (`Verify`). It used go-oidc's `IDTokenVerifier` with `ClientID = API audience`, which checks signature (RS256 only), `iss`, `exp` and that `aud` contains `platform-spike`. Hydra lets the admin API choose client ids. I created an auth-code client with `client_id: "platform-spike"`, logged a user in through it, and **`/api/me` answered 200 with the ID token**. Its access token was correctly rejected (empty `aud`). Also, a token from *any* client with the audience whitelisted passed, because nothing checked `client_id`. Fix: require Hydra's access-token `client_id` claim (ID tokens never carry it), and accept it only when it is the login driver's client, or for client_credentials (`client_id == sub`; an unknown client maps to no principal). Re-ran the probe: ID token → 401. Unit test: `TestCheckAccessToken`.

### Medium

3. **A missing OpenFGA model or store was dead-lettered as "permanent" (fixed).** `openfga.go:391` (`Apply`). The code treated every 400 as permanent, and `results/b.md` says "404 (store or model not there yet) stay transient". In fact OpenFGA v1.22 answers **400** in those cases: `authorization_model_not_found` when the pinned model id is gone, `latest_authorization_model_not_found` when the store is gone. Scenario: the store is recreated or the datastore is reset while the app is up. The relay then dead-letters every event in a few seconds, revocations included, and nothing replays them after the restart. Fix: `permanent()` checks the error code. Missing model/store errors are transient (retried in order, loudly). Test: `TestApplyClassifiesErrors` sends the real v1.22 bodies, captured from the server, through the SDK.
4. **Model skew is still a permanent 400 (not fixed).** Each instance pins the latest model id at startup (`openfga.go:81`), and writes are validated against that pinned model. During a rolling deploy, or a bootstrap without an app restart, an old instance can drain an event from newer code. Example: a role edit that adds a new catalog permission and removes `order.refund`. The write fails with 400 `validation_error: relation … not found` and is dead-lettered. Because `syncRole` sends the whole edit in one request, the removal is dropped with it and **`order.refund` stays in OpenFGA while the DB says it's gone**. Fix: on `validation_error`, compare the latest model id with the pinned one. If they differ, the error is transient: re-pin the model and retry. Or store the model id the code expects with the code (a constant generated alongside `model.fga`).
5. **The Hydra pool fix raises the limit; the deadlock is still there (not fixed).** `compose.yaml:76` (`max_conns=50`). The builder's diagnosis is right, but a bigger pool only moves the threshold. A burst script (full driver flow, one user):

   | parallel logins | result |
   |---|---|
   | 40 | all ok in 1.0 s |
   | 100 | all ok in 1.9 s (one earlier run: 89 failed) |
   | 150 | 132 failed after 21 s; `pg_stat_activity`: hydra 50 × `idle in transaction` |
   | 200 | 188 failed |

   Hydra recovers once the clients time out. `idle_in_transaction_session_timeout=2s` on the hydra DB did not help (tried, reverted). The `/oauth2/auth` step alone is fine (300 parallel in 0.3 s), so the stall is in the login accept, consent or token steps. In production a login spike stalls every login for the client timeout. Mitigation: concurrency limit or rate limit in front of Hydra, a pool sized to peak concurrent logins, and tracking the upstream issue. The suite stays under the threshold, so the results don't show it.
6. **Expired tuples are never deleted (not fixed).** Expiry is enforced at check time (`not_expired` + `current_time`), but `agent_grant:*#agent|<perm>` and `user:U#delegate@agent_grant:G#agent` stay forever unless the grant is revoked. Cost on every agent check: the path `role_binding#subject → user:U#delegate` reads **every grant U ever created** (expired included) and evaluates the condition on each one, so each binding costs O(grants by U). Storage grows by (3 + perms) tuples per grant. After the suite runs: 130 `not_expired` tuples out of 5 195 total. Fix: a sweep that emits revoke events for grants past `expires_at` (hygiene only; correctness doesn't depend on it). SpiceDB garbage-collects these itself.
7. **The OpenFGA adapter is correct only because there is one drainer (not fixed; document it).** `syncRole` (`openfga.go:548`) reads the role's tuples and then writes the diff. `deleteObject` reads and then deletes. Two concurrent appliers for the same object could interleave and leave stale tuples. Today the relay's global advisory lock prevents that. SpiceDB's adapter needs no lock (TOUCH and delete-by-filter don't read first). If someone partitions the drain lock (review-a suggests per merchant), keep every object in one partition. The shared system roles `role:owner` etc. are global objects and are written from startup sync in every instance. The `RelationSync` port doc should state this requirement.

### Low

8. **The model compare missed wildcard-only changes (fixed).** `prune` (`openfga.go:159`) dropped empty objects, including `"wildcard": {}` and `"this": {}`. So `[user:*]` and `[user]` compared equal, and a change that only toggles a wildcard would never be written. Combined with finding 4, every write to the new shape would then be dead-lettered. Fix: keep those two keys. Test: `TestSameModelSeesWildcardChange`.
9. **The SDK JSON "mismatch" was a misdiagnosis (cleaned up).** The OpenFGA protos set `json_name` (`type_definitions`, `computedUserset`). Default protojson, or `transformer.TransformDSLToJSON`, already produces the SDK's field names; the problem only came from `UseProtoNames: true`. `modelRequest` is now `TransformDSLToJSON` → `json.Unmarshal` (−38 lines, rename hack gone). The old fix was also fragile: it renamed those keys anywhere in the tree, relation names included.
10. **Delete-then-write window: only a deny is possible (verified by reading, no change).** The only non-atomic replacements are a refund-limit change on a role (`syncRole` second request) and a re-opened break-glass (`upsert`). In both, the tuple is absent between the two requests, so a concurrent check sees **deny**. No allow is possible: removed permissions go out in the same request as plain writes, which is atomic. If the second request fails, the relay retries the whole event (re-read, re-diff). If it fails permanently, the end state is deny.
11. **Cascade deletes fail safe (verified, no change).** Each cascade first cuts access in one request: `scope#binding`, `store#install`, `store#grant` + `user#delegate`. Leftover object tuples are deleted after that, so a partial failure only leaves inert tuples, and the retry is idempotent (`on_missing: ignore`). OpenFGA does not validate deletes against the model (probed: deleting an unknown relation or type → 200), so a cascade can't turn into a permanent 400 after a model change. Role delete emits the assignment deletes before `role.deleted`.
12. **A conflicting-condition write is a 409, and 409 is classed transient.** Writing a tuple that exists with another condition context → 409 `Aborted` (probed), even with `on_duplicate: ignore`. That would block the outbox head forever. It can't happen today: `syncRole` compares condition contexts, break-glass uses `upsert`, and grant ids are unique. Keep it that way, or mark this error permanent with a log.
13. **`HIGHER_CONSISTENCY` costs nothing today.** The check cache is off (the default) and there is one Postgres with no replicas. The cost comes later: once `--check-query-cache-enabled` or read replicas are on, every check bypasses both, so they are useless as long as the app wants read-your-writes on every request. In return, it is stateless: two app instances get read-your-writes, unlike a's per-process ZedToken. A cheaper variant: HIGHER only for subjects or objects touched in the last N seconds (needs a DB lookup, so not adapter-only).
14. **Smaller identity notes (not fixed).**
    - `TEST_SECRET` defaults to `test-secret` (same as review-a #7). b's `driver-config` returns no credentials, which is better than a.
    - The driver client allows `offline` + `refresh_token`, and JWT access tokens can't be revoked for their 1 h lifetime. Fine here, because the app maps `sub` to a DB principal on every request.

## Pattern verdicts for b (SPEC §1)

| # | pattern | verdict |
|---|---|---|
| 1 | Action = unit, one executor, outbox in tx | **holds**: same shared code as a; b adds nothing outside the executor |
| 2 | One `can()` in AuthZEN shape | **holds**: Check/BatchCheck behind the port; `current_time` is added inside the adapter, so the executor doesn't know about it |
| 3 | Custom roles are data | **holds**: model generated from the catalog, golden-tested, `fga model test` in `go test` and in the Docker build; the compare bug (8) is fixed |
| 4 | App DB truth + outbox + read-your-writes | **bent**: read-your-writes is stateless and multi-instance safe (better than a); but error classification decides what is lost (3 fixed, 4 open), correctness needs a single drainer (7), expired tuples pile up (6) |
| 5 | Three checks | **holds**: kind precheck, relationship, `refund_limit` and `not_expired` conditions; the token check is now an actual access-token check (2) |
| 6 | Tenant isolation twice | **holds**: same SQL prechecks as a; customers never reach OpenFGA |
| 7 | Composition root by hand | **holds**: one `case "ory"` and one `case "openfga"` in each `main` |

## SpiceDB vs OpenFGA (from the code)

- **Semantics: a tie.** The model is a 1:1 translation: role objects with wildcard permissions, bindings, store inheriting from merchant, the delegate path with a time condition, installs, suspension as a wildcard exclusion, break-glass on views only. It passes the same 33 assertions. I found no semantic gap.
- **Sync glue: SpiceDB wins.** TOUCH replaces a caveated relationship atomically, `DeleteRelationships(filter)` is one call, and expiring relationships are garbage-collected. OpenFGA needs a read-diff-write for role edits, read-then-delete for cascades (both depend on a single drainer), a non-atomic upsert for condition changes, and a sweeper for expired tuples. About 180 more adapter lines, and every one of them is a failure window to reason about.
- **Consistency: OpenFGA wins.** `HIGHER_CONSISTENCY` needs no token, so there is no per-process ZedToken problem. Its `on_duplicate`/`on_missing` write options also make replays clean.
- **Ops traps: OpenFGA has more.** Missing model/store comes back as 400 (3), immutable models pinned per process (4), and the condition clock is the app's (`current_time` from each instance; skew between instances shifts expiry).
- **Verdict:** for this design (outbox-driven sync, frequent role edits, expiring grants), SpiceDB means less glue and fewer windows. OpenFGA works, but only with a sweeper, model-id discipline and an explicit single-drainer contract.

## The "swap engines by adapter only" claim

It holds for code: no module, kernel, port or migration changed. What `results/b.md` doesn't say:
- The OpenFGA adapter silently relies on a property of the shared relay (one serialized drainer). SpiceDB's adapter doesn't need it. The port contract says nothing about it (7).
- Error classification is part of the port's semantics (`ErrPermanent`), and getting it right needed engine-specific knowledge the builder got wrong (3). A wrong classification loses events, which is a correctness property, not just an adapter detail.
- A model change is live in a (SpiceDB `WriteSchema`), but in b every instance has to restart (4). That is a deploy-procedure change.
- The test driver only works because Hydra admin is published (1), so the swap needed a security-relevant config change.
- `core.Unlimited` (2^53) is still engine knowledge in the kernel (review-a); b happens to tolerate it.

## What I'd change in the spec

1. **§10 token validation:** name the checks, including "reject ID tokens; allowlist `client_id`/`azp`" (review-a #8). In b this was exploitable, not theoretical (finding 2).
2. **§10/§11 test mode:** drivers must not need unauthenticated IdP admin APIs on the network. Login/consent stand-ins run inside the stack, behind the test secret.
3. **§1.4 failure semantics:** "permanent" means the event can never apply against the code's own model. Environment errors (store/model missing, model skew) are transient, whatever HTTP status the engine uses.
4. **§1.4 RelationSync contract:** say whether adapters may assume one serialized drainer (b needs it; a doesn't).
5. **§6 expiry:** expiry is enforced at check time (as now), **and** expired grants are cleaned up eventually, to bound storage and check fanout.
6. **§12 results:** add a login burst (e.g. 200 parallel logins) and record the threshold. Hydra's pool deadlock is invisible to the suite.
