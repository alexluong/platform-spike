# Stack b results: Go + Ory Kratos v26.2.0 + Hydra v26.2.0 + OpenFGA v1.22.0

Run 2026-10-11 against `DOCKER_HOST=ssh://cs-ws` (4 CPU / 11 GB VM, stacks a and c up at the same time, a's reviewer running load), branch `go-b`. Same Go app as stack a; `IDP=ory AUTHZ=openfga`.

## Conformance

`cd conformance && STACK=b HOST=cs-ws.lab.alexluong.com pnpm test`

| run | result |
|---|---|
| full, before merging main (8193c26) | **341 passed / 341**, 78 s (72 s on a second run from `down -v`) |
| `SKIP_SLOW=1`, before the merge | 340 passed, 1 skipped, 26 s |
| full, after merging main (suite now 349 tests) | **348 passed / 349**, 71 s |

The one failure after the merge is not stack b's: `orders.test.ts` "an absurd quantity or price is a 400" (added with review-c's fixes) sends `qty: 1_000_000` on a 100 000-cent product. The shared Go orders module allows `qty` up to 1 000 000 and the 1e11 total fits `int64`, so it answers 201. Stack a runs the same module and would fail the same way. Fix belongs in shared code or the test (lead's call), not in an adapter.

First full run: 17 passed / 164 failed. One cause, fixed in compose: **Hydra's DB pool deadlocks under parallel logins.** The default pool is 2×CPUs (8). During the burst all 8 connections sat `idle in transaction` waiting for a second connection; Hydra requests hung until the driver's 15 s timeout, then logged `transaction has already been committed or rolled back` and `the OAuth 2.0 Authorization request must be aborted`. `?max_conns=50&max_idle_conns=20` on Hydra's DSN (and 30 on Kratos) fixed it. Kratos's bcrypt cost was lowered up front (see Ops), so password hashing was never the bottleneck here (stack a's was).

**Pool burst (lead's check, stack c's deadlock):** 60 parallel `/api/me/permissions` (half `?storeId=`, half `?merchantId=`) + 15 product creates + 15 custom-role creates on one merchant, all at once, run 3 times: all 90 returned 2xx each time, in 1.2–1.9 s. The b adapters hold no Postgres connections: OpenFGA and Ory are HTTP calls, so a request still uses only its own tx connection (review-a finding 19 applies unchanged).

## What changed in Go between a and b

`git diff --stat origin/main...HEAD -- go/` (main at 8193c26, after the merge):

| file | lines | inside the allowed area? |
|---|---|---|
| `internal/adapters/openfga/*` (adapter, model generator, generated `model.fga`, `model.fga.yaml`, tests) | +1506 | yes |
| `internal/adapters/ory/*` (verifier, provisioner, bootstrap) | +217 | yes |
| `cmd/server/main.go` | +15 −1 | yes: one `case "ory"` and one `case "openfga"` (+ imports, comment) |
| `cmd/bootstrap/main.go` | +29 | yes: one `case "openfga"` and one `case "ory"` (+ imports) |
| `go.mod`, `go.sum` | +44 −16 | **no, unavoidable:** new deps `openfga/go-sdk`, `openfga/language/pkg/go` (DSL → model JSON; pulls `antlr4`, `openfga/api/proto`, otel) |

**No module, kernel, port or migration changed.** The ports from stack a were enough: `Verifier`/`Provisioner` for Ory, `Authorizer`/`RelationSync` for OpenFGA, and the opaque `DriverConfig()` for the test driver. Things that would have tempted a change, and how they stayed inside the adapter:
- **Expiry needs `current_time` on every check.** The adapter adds it itself (`c.now()`); the executor doesn't know.
- **OpenFGA store and model ids.** The server's adapter finds the store by name and pins the latest model at startup (`openfga.New`), so the bootstrap writes nothing extra to `stack.json` and `main.go` needs no config plumbing.
- **The relay's new permanent/transient split (from main).** `ErrPermanent` is in the port; the adapter classifies (below).

Outside `go/`, all inside the allowed area: `stacks/b/` (compose, Ory configs baked into images, Postgres init, and a Dockerfile for the app) and `conformance/stacks/b.ts`.
- **Finding (small):** `go/Dockerfile` is stack a's, not shared: its first stage runs `zed validate`. Stack b uses its own `stacks/b/Dockerfile` (same build, `fga model test` stage instead) with `context: ../../go`. Both images are built from the same source. A neutral `go/Dockerfile` plus a per-stack check stage would remove the duplication.

What merging main forced in the b adapters: only the error classification in `openfga.Apply` (the relay now retries forever unless the error wraps `authz.ErrPermanent`). The other main changes (registrant-only agent grants, SQL install check, input bounds, break-glass list audit) are module code and needed nothing from b.

## Lines of code (non-blank, non-comment)

| area | LOC | stack a equivalent |
|---|---|---|
| OpenFGA adapter: Authorizer, RelationSync, bootstrap (`openfga.go`) | 510 | SpiceDB `spicedb.go` ~330 |
| OpenFGA model generator (`model.go`) | 134 | `schema.go` ~120 |
| generated `model.fga` / `model.fga.yaml` | 239 / 358 lines | `schema.zed` 231 / `validation.yaml` 99 |
| Ory adapter (`ory.go`, `bootstrap.go`) | 180 | Zitadel 265 |
| Go tests (golden model, every action has a relation, model request keeps rewrites, model compare, `fga model test`) | 104 | 60 |
| `stacks/b` (compose, Dockerfiles, Kratos/Hydra config, identity schema, Postgres init) | 250 | 143 |
| login driver `conformance/stacks/b.ts` | 156 | 136 |

## Glue code for custom roles: OpenFGA vs SpiceDB

Same model shape as a (custom-roles style B: `role` objects hold wildcard permission tuples, `role_binding` ties `user` and `user#delegate` to a role at a scope, store inherits merchant bindings), generated from `perm.Catalog` and golden-tested like `schema.zed`. The DSL translated 1:1 (`&` → `and`, `-` → `but not`, `->` → `from`), except that `but not X from Y` needs a helper relation (`merchant_suspended: suspended from merchant`). The `fga model test` file runs the same 33 assertions as a's `validation.yaml`, in `go test` (when `fga` is installed) and in the Docker build.

Where the glue differs:
- **No TOUCH, so idempotency comes from write options.** Every write sends `on_duplicate: ignore` and `on_missing: ignore` (OpenFGA v1.22 here; Go SDK `ClientWriteConflictOptions`). Re-applying an outbox event is a no-op, the same as SpiceDB TOUCH/DELETE.
- **But a changed condition is not a duplicate.** Writing an existing tuple with another condition context fails even with `ignore`, and one request may not delete and write the same tuple. So:
  - role edits (`syncRole`) compare tuples *including* the condition context, delete the extras and changed ones together with the plain writes, then write the changed ones in a second request;
  - a second break-glass by the same staff member (new expiry) is delete-then-write.
  Both leave a short window (one round trip) where the tuple is missing. SpiceDB TOUCH replaces a caveated relationship atomically.
- **No delete-by-filter.** SpiceDB's `DeleteRelationships(filter)` becomes `deleteObject`: `Read` the object's tuples in pages of 100 (HIGHER_CONSISTENCY), then delete them in requests of ≤ 100 tuples (OpenFGA's default per-write limit). Used for `role.deleted`, `assignment.deleted`, `app.uninstalled`, `agent_grant.revoked`. A cascade bigger than 100 tuples is no longer one transaction (none here comes close: a role is ≤ 46 tuples).
- **Expiry is a condition, not an expiring relationship.** `not_expired(current_time, expires_at)` sits on `agent_grant#agent`, each `agent_grant#<perm>` and `merchant#break_glass_viewer`; the adapter sends `current_time` on every check. No cleanup job (the agent-expiry and break-glass-expiry tests pass), but expired tuples stay in the store forever unless something deletes them. SpiceDB garbage-collects expired relationships.
- **Refund limit** is the `refund_limit(amount, limit)` condition on `role#order_refund@user:*` / `agent:*`, the same as the caveat. OpenFGA took `amount` and `limit` as `int` from JSON numbers, including 2^53. Unlike SpiceDB there is no "conditional" answer; the app always sends `amount` for `order.refund`.
- **Read-your-writes:** `HIGHER_CONSISTENCY` on every Check, BatchCheck and Read. No token to keep, so the per-process ZedToken problem from review-a (two instances) doesn't exist here. With the check cache off (the default) it changes nothing today; it matters once `--check-query-cache-enabled` is on.
- **Batch:** `EvaluateMany` → server-side `BatchCheck` with correlation ids (the SDK chunks by 50). `/api/me/permissions` is one request.
- **Error classification** (relay retries forever): `FgaApiValidationError` (400: the tuple doesn't fit the model) and unknown events / platform roles → `authz.ErrPermanent`; network errors, 404 (store or model not there yet), 429 and 5xx stay transient. Duplicates and missing deletes never surface as errors.
- **Model ids:** each `WriteAuthorizationModel` creates a new immutable model. The bootstrap writes only when the latest model differs from the generated one; the app pins the latest id at startup. After a model change the app must restart to see it.
- **Same agent delegate limit as a.** `user#delegate: [agent_grant#agent]` can't tie a grant to its grantor. Main's registrant-only rule (only one possible grantor per agent) closes it for b too. Review-a finding 18 (an agent's store-scope `role.manage`/`app.install` effects outlive the grant) applies to b unchanged; it is module/catalog level.

## Ops

| | |
|---|---|
| containers | 9: postgres (databases `kratos`, `hydra`, `openfga`, `app`), kratos, kratos-migrate, hydra, hydra-migrate, openfga, openfga-migrate, bootstrap (one-shot), app. No login/consent UI. |
| memory at idle (after the suite, then restart) | app 14 MB, openfga 24 MB, kratos 52 MB, hydra 28 MB, postgres 35 MB: about 155 MB idle. Right after a suite run: postgres 364 MB, kratos 77 MB, hydra 50 MB, openfga ~50 MB, app 34 MB, about 575 MB. |
| cold start from `down -v` | `up -d --wait`, images built: 15 s (migrations ~1.5 s, Ory health ~3 s, bootstrap 0.3 s). With `--build` (classic builder on the remote daemon, Go build cached): 46 s. |
| images | app 90 MB, kratos 105 MB, hydra 74 MB, openfga 114 MB, postgres 424 MB |
| bootstrap | idempotent; re-run takes ~0.1 s after migrations (store found by name, model unchanged so not rewritten, Hydra driver client found by `client_name` + redirect URI) |

Bootstrap pain:
- **Issuer is just config.** Hydra's issuer (`URLS_SELF_ISSUER=http://$STACK_B_HOST:4444`) only has to equal the `iss` string. The app fetches JWKS from `http://b-hydra:4444` inside the network and checks `iss` against the external URL, so no network alias or Host-header tricks (stack a needed both for Zitadel). Changing `STACK_B_HOST` needs no `down -v`.
- **Five Ory config pieces had to be right before anything ran:** identity schema with `ory.sh/kratos.credentials.password.identifier`, `--dev` (required for bcrypt cost < 12 and plain HTTP), `haveibeenpwned_enabled: false` (otherwise outbound calls per password), `strategies.access_token: jwt`, and DB pool size (above). None needs a UI or a click.
- **Three migrate one-shots** (Kratos, Hydra, OpenFGA) vs one in stack a. Cheap but more moving parts.
- The OpenFGA image is distroless (no shell, no wget), but it ships `grpc_health_probe` for the healthcheck. The `openfga/cli` image's binary is `/fga`, not on `PATH` for `RUN ["fga", …]`.

## DX notes

- **Ory.**
  - Docs and the v26.2.0 OpenAPI spec (`spec/api.json`) and config schema (`embedx/config.schema.json`, `spec/config.json`) matched the running server. Every endpoint and field used was there: Kratos `GET /self-service/login/api` + `POST /self-service/login?flow=` with `{method: password, identifier, password}`, Kratos admin `POST /admin/identities` with a plaintext password (Kratos hashes it), Hydra admin `/admin/clients`, `/admin/oauth2/auth/requests/{login,consent}/accept`.
  - The headless code + PKCE flow worked first try: the driver keeps a cookie jar across the three Hydra redirects (login CSRF cookie, then consent CSRF cookie).
  - `client_credentials` with Hydra: `sub` is the client id. `audience` must be whitelisted on the client and requested explicitly (`audience=` on the token and authorize requests, `grant_access_token_audience` on consent), otherwise `aud` is empty and the verifier rejects the token. Client secrets work immediately (no eventual consistency, unlike Zitadel's machine-user secrets).
  - **The pool deadlock is the trap.** The default `max_conns` (2×CPUs) deadlocks Hydra under ~10 parallel logins with no error until timeouts. Nothing in the docs warns about it for `serve all`.
  - Config validation is strict and clear (unknown keys fail at start). Kratos warns when `version` is missing in the config; harmless.
- **OpenFGA.**
  - The DSL (`schema 1.1`, conditions, wildcards with conditions, nested `(a and b) but not c`) did everything the SpiceDB schema did. `fga model test` is as good as `zed validate`: same assertions, readable output.
  - **The official Go SDK can't take the language package's output.** `language/pkg/go/transformer` returns a proto; `protojson` gives either camelCase or proto names, while the SDK's JSON tags mix both (`type_definitions` but `computedUserset`, `tupleToUserset`). The first bootstrap was rejected (`invalid userset rewrite definition`) because the rewrites were silently dropped. Fix: proto names, then rename those two keys (`modelRequest`), with a test that every relation keeps its rewrite.
  - **Comparing models needs pruning.** The server echoes empty fields (`module: ""`, `relations: {}`, `generic_types: []`) that the request omits, so a naive compare rewrote the model on every bootstrap.
  - `on_duplicate` / `on_missing` write options removed most of the idempotency glue from the authz-landscape notes. The remaining glue is the condition-change case and delete-by-filter.
  - OpenFGA v1.22 has an `authzen` experimental flag (an AuthZEN endpoint). Not used: the app calls `can()` in-process.
- **What the agent got wrong first:**
  - the model JSON conversion (above);
  - `fga` not on `PATH` in the CLI image;
  - the model compare (rewrote the model on every bootstrap);
  - Hydra/Kratos pool size: found from `pg_stat_activity` showing 8 Hydra connections `idle in transaction` during the run.
  Everything else (Ory endpoints, login driver, OpenFGA conditions) worked on the first run, because the Ory API spec and config schema at the exact release tag were read before writing code.

## Spec issues (choices made)

Same as stack a (shared code), plus:
1. **Test mode:** `GET /api/_test/driver-config` hands the driver Hydra's public client id, redirect URI and API audience. The driver reaches Kratos public (4433), Hydra public (4444) and **Hydra admin (4445)** on published ports. Hydra admin has no auth in OSS: publishing it is a dev-only stand-in for the login UI (spec §10) and must never leave the test host.
2. **No login UI:** `urls.login` / `urls.consent` / Kratos `ui_url` point at an unserved `http://localhost:3999/…`; the driver reads the challenge from the redirect.
3. **Kratos registration is disabled**; identities are created only through the admin API (`/api/_test/users`).
