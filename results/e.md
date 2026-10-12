# Stack e results: the stack-d app (TypeScript, Hono, Better Auth + organization plugin) with SpiceDB

Run on 2026-10-13 against `ps-e` on cs-ws (`docker compose -p ps-e --profile e up -d --build`), branch `stack-e` (main 275420c + stack e, then main e6ddc0e with review-d's fixes merged in). Same app as `d` (`ts-org/`), `AUTHZ=spicedb` in the composition root; `d` is `AUTHZ=cerbos` (the default).

## Conformance

| run | result |
|---|---|
| **e**, full suite incl. the slow break-glass expiry, fresh volumes | **392 / 392** (78 s) |
| **e** and **d** run at the same time on the same host | **392 / 392** each (e 86 s, d 83 s) |
| **d regression**: `ps-d` rebuilt from this branch | **392 / 392** (left running) |

392 = 362 shared + 30 `idp-tenancy` (28 + review-d's 2 race tests). No failures by design. Unit tests (vitest, `ts-org`): 38 (d: 35 after review-d), all pass; the schema test runs `zed validate` (zed 1.2.1 from the repo `mise.toml`).

Before the final build, two runs failed (see DX notes): a SpiceDB outage held one request ~70 s (no gRPC deadline), and running e and d suites at the same time timed out 10 tests (concurrent settles polled the request pool dry). Both fixed in the relay/client; no test changed.

## d → e: what changed outside the adapter, the relay and the composition root

`git diff --stat origin/main -- ts-org/` (after the merge): 16 files, +2,232 −17, of which 1,234 are drizzle-kit's generated snapshot. New code: `adapters/spicedb/` (authorizer, client, sync, schema, tests, validation), `outbox/relay.ts`. The composition root (`main.ts`, +61 −7) picks the engine from `AUTHZ`.

| change outside adapter/relay/root | lines | why (finding) |
|---|---|---|
| `modules/platform.ts`: `emit({ type: 'break_glass.opened', breakGlassId })` | +2 −1 | **d emitted no event for opening a break-glass**: Cerbos reads the `break_glass` table per check, so nothing needed one. A state change without an event is invisible to any relationship engine. Go's `a` has `EvBreakGlassOpened`. The only module change. |
| `db/schema.ts` + migration `0002_outbox_relay.sql`: `outbox.processed_at`, `attempts`, `last_error`, partial index on pending rows; table `authz_consistency` (one row: the latest ZedToken) | +29 −5 | d's outbox had no consumer, so it had no delivery state. The token table is how read-your-writes holds across instances (below). Engine-neutral names; for d the columns stay empty. |
| `package.json`: `@authzed/authzed-node` 1.6.1 | +1 | the client |
| `mise.toml`: `github:authzed/zed` 1.2.1 | +1 | `zed validate` in unit tests |

Kernel (`kernel/*`), executor, every other module, the PIP (`modules/access.ts`), the Better Auth glue and the Cerbos adapter: **unchanged**. Compare a → b in Go: zero module/kernel/port changes. Here one module line, because d's events were shaped by what Cerbos needed (nothing).

What the kernel's shape pushed into the SpiceDB adapter instead of the kernel (no change, but a finding): **d's executor lets the engine decide two things Go's executor decides itself.** The deny reason `merchant_suspended` (only for the merchant's own principals) and the break-glass marker (`breakGlass`, `merchantId`) that the executor audits come back from Cerbos as rule outputs. SpiceDB answers yes/no. So `authorizer.ts` reads the facts from the DB through d's PIP (`pip.resource`, `pip.subject`), only on the paths that need them: a deny on a suspended merchant, and an allow for platform staff. In Go these are SQL prechecks in `core/executor.go`, before the engine. The port is engine-neutral in signature but Cerbos-shaped in contract.

## How the relay works, and how it differs from Go's

`outbox/relay.ts` (117 LOC) + `adapters/spicedb/sync.ts` (214).

**d's events are thin, Go's carry full state.** d emits `{type: 'role.assigned', assignmentId}`; Go emits the whole assignment (user, role, scope). The TS relay therefore **reconciles**: each event names an object, the sync reads that object's current state from the app DB *inside the relay's transaction* (no second connection) and makes SpiceDB match, deleting what the DB no longer has (scope unknown after a delete → delete by subject filter at both scope types). Consequences:
- Idempotent and **order-insensitive**: the latest DB state wins, so review-a's "out-of-commit-order ids are safe only because writers hold row locks" caveat doesn't apply.
- Role delete removes the role's bindings too (d deletes the assignments in the same tx without per-assignment events; the sync reads `role_binding#role@role:<id>` and reconciles each). Go deletes the role's relationships and leaves the bindings pointing at nothing.
- Costs more SpiceDB calls per event (reads before writes on roles, users, staff).

Rules (SPEC §1 Operational rules), same as Go's fixed relay:
- One drainer at a time, rows in id order, a failing row blocks the rows after it, transient errors retried forever, loud log at 10 attempts (and every 100).
- Dead-letter only `PermanentSyncError`: gRPC `InvalidArgument`/`FailedPrecondition`, unknown event types, an event missing its id, an unknown platform role. Events SpiceDB doesn't care about (orders, products, invitations, registrations) are an explicit no-op list; anything else unknown is dead-lettered, loudly. Unit-tested (`sync.test.ts`); the relay itself has no DB test, like Go's.
- **Draining after commit:** the composition root's `transact` asks Postgres whether the request's transaction wrote anything (`pg_current_xact_id_if_assigned()`), and if so settles the outbox after commit, before the response. No kernel change was needed for this (Go drains in the executor).
- **Better than Go's on waiting:** `pg_try_advisory_xact_lock` and poll, so a waiter holds no connection (Go blocks on `pg_advisory_xact_lock` with a pool connection: review-a 19). Within one process, concurrent settles share one drain pass (single flight): a complete pass that started after the caller's commit has applied its rows. The relay has its own 3-connection pool.
- **Worse than Go's now:** main's Go relay (a2) partitions the lock per merchant and supports several consumers; the TS relay has one global lock and one consumer.

System roles: at every start the app writes an outbox row `system_roles.sync` and settles it (Go enqueues them too). Platform roles (`platform_admin`, `support`) are `platform:main#admin|support@staff:<id>`; the test-user endpoint writes a `platform_role.granted` outbox row in the same transaction as the `app_users` row (composition root code).

## How org-plugin membership reaches SpiceDB

d writes merchant, member and invitation rows through Better Auth's organization adapter **in the app's transaction** (d finding 1), together with the outbox row. So there is no dual write: membership, assignments and the outbox event commit or roll back as one.

| change | event | SpiceDB |
|---|---|---|
| merchant create (org + owner member + owner assignment) | `merchant.created {merchantId, ownerUserId}` | `merchant#platform`, `merchant#any_user@user:*`; then the owner's membership and bindings |
| member add (direct or invitation accept) | `member.added {userId, merchantId}` | `merchant:<m>#member@user:<u>` |
| member remove (member + its assignments) | `member.removed` | membership deleted; every binding of the user reconciled against `role_assignments` (all gone → all deleted) |
| suspend / reinstate | `merchant.suspended` / `merchant.active` | `merchant#suspended@{user,agent,app}:*` touched / deleted |

**Schema difference from Go (the one):** `merchant` gains `relation member: user` and `permission agent_register = member - suspended`. d's executor checks `agent.register` at the merchant through the engine ("any member"); Go's `a` checks it in SQL and its schema has no membership. Nothing else reads `member`: permissions still come from bindings, as in `a`, so a removed member loses access because their assignments are deleted in the same transaction. The test checks the generated schema minus these two lines equals Go's `schema.zed` byte for byte (header comment aside), and runs Go's `validation.yaml` plus e's own assertions (`validation-e.yaml`) with `zed validate` against e's schema.

**Failure window.** The DB side is atomic. The engine side lags by the settle: normally a few ms before the response. Measured with SpiceDB stopped: the request still commits and answers 201 after the 5 s settle timeout (6.2 s), checks meanwhile fail closed (500, `/healthz` 503), and the background relay applies the row within ~1 s of SpiceDB coming back. Still SPEC §14 P6: the 2xx after a failed settle claims something SpiceDB doesn't know yet (for a revoke: access until the relay catches up, but only while SpiceDB is up and the write isn't, which is a narrow case since checks need SpiceDB too).

## Read-your-writes

**ZedToken in the DB.** The relay stores SpiceDB's token from its last write in `authz_consistency` in the same transaction that marks the rows processed (under the drain lock, so tokens only move forward). Every `evaluate`/`evaluateMany`/`searchResources` reads it (one indexed single-row read on the PIP pool, a separate pool, so no second same-pool connection inside the request tx) and asks `at_least_as_fresh`; no token yet → `fully_consistent`. This removes `a`'s known limitation (per-process token): any instance sees every instance's writes. Cost: one extra DB round trip per check call (batch checks are one call). Alternative not taken: round-trip the token to the client.

## SpiceDB adapter vs Go (e vs a, same engine)

Non-blank, non-comment lines:

| part | TS (e) | Go (a) |
|---|---|---|
| authorizer (check, bulk check, lookup, suspension/break-glass facts) | 116 (`authorizer.ts`) | ~190 of `spicedb.go` |
| relationship writes (events → relationships) | 214 (`sync.ts`, reconciling) | ~140 of `spicedb.go` (full-state events) |
| client helpers | 61 (`client.ts`) | (in `spicedb.go`) |
| adapter total | **391** | **328** (`spicedb.go`) |
| schema generator | 102 | 126 |
| relay | **117** | 111 at 275420c; 231 on main now (partitions, consumers) |
| Cerbos adapter it replaces | 107 + PIP 127 (still used for the facts above) | |

The TS adapter is about the size of Go's; the extra is the reconciling sync (thin events) and the Cerbos-shaped extras (suspension reason, break-glass marker).

## Ops

- **Containers:** 4 (`e-postgres` with databases `ps` and `spicedb`, `e-spicedb-migrate` one-shot, `e-spicedb` v1.56.2 on Postgres, `e-app`), d has 3. No bind mounts; the app image is d's (`ts-org/`), the Postgres image adds one `CREATE DATABASE`.
- **Memory:** idle app 60 MiB, SpiceDB 49 MiB; after a full suite app 101 MiB, SpiceDB 145 MiB, Postgres 108 MiB (**~354 MiB**; d ~183 MiB: SpiceDB and its tables cost ~170 MiB more than Cerbos).
- **Cold start:** `down -v` then `up -d --wait`, images built: **11 s** (d 9.5 s): SpiceDB migrate, then the app writes the schema (retried until SpiceDB answers) and syncs the system roles before serving.
- **Images:** app 548 MB, SpiceDB 136 MB.
- **After a full run:** 2,701 outbox rows, 0 pending, 0 dead.
- **Bootstrap pain:** none beyond d's: the app owns migrations, schema write and system-role sync.

## DX

- **TS client vs Go's:** `@authzed/authzed-node` is generated protobuf-ts. Every message needs `X.create({...})`, oneofs are `{ oneofKind: 'atLeastAsFresh', atLeastAsFresh: … }`, structs go through `PbStruct.fromJson`, timestamps through `protobuf.Timestamp.fromDate`. More ceremony than Go's struct literals but fully typed; the `.promises` client returns streams as arrays (fine for `ReadRelationships`/`LookupResources` at this size, a memory trap at scale). gRPC status codes are plain numbers on the error (`@grpc/grpc-js` is only a transitive dependency under pnpm's strict layout, so I compare `3`/`9` directly). `PreconnectServices` isn't re-exported from `v1` although `NewClient` takes it.
- **What I got wrong first:**
  1. **No deadline on gRPC calls.** With SpiceDB stopped, each call waited ~20 s for the channel, so a request's 5 s settle took 72 s. Fixed with the client's `deadlineInterceptor` (3 s per call). Go's adapter has the same gap (no per-call deadline beyond the request context).
  2. **Settle polled per request.** Each waiting request ran its own try-lock + "is my row done" queries every 10 ms on the request pool; with the e and d suites running together, that starved the pool and 10 tests timed out at 30 s. Fixed with single-flight passes per process and a separate relay pool.
  3. Assumed d's outbox had delivery columns, and that d emitted an event for every state change (break-glass didn't).
- **What was hard:** the Cerbos-shaped contract of the port (reasons and audit markers come from the engine in d), and thin events. Both are invisible until you write the second adapter, which is the point of this stack.

## Spec issues

- **§1.2 / port contract:** say where `merchant_suspended` and the break-glass audit marker come from. Go: executor prechecks. d: engine outputs. A second TS engine had to read the DB in the adapter to reproduce them. Moving both into d's executor (as SQL prechecks, like Go) would make the TS port truly engine-neutral.
- **§1.4 events:** say whether outbox events carry full state (Go) or ids (d). With ids, the relay must read current state (works, and is order-insensitive, but couples the relay to the app schema); with full state, every module must emit it. Also: every state change emits an event, even when today's engine doesn't need one.
- **§14 P6** still open (2xx after a failed settle), now measured: 5 s settle timeout, ~1 s catch-up after recovery.
