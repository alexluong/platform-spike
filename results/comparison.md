# Comparison (2026-10-11)

Three stacks, one spec (`spec/SPEC.md` v2), one suite. All three pass **362/362** at `main` after building, review and alignment. Details per stack: `a.md`, `b.md`, `c.md`; reviews: `review-a.md`, `review-b.md`, `review-c.md`.

## At a glance

| | a: Go + Zitadel + SpiceDB | b: Go + Ory + OpenFGA | c: TS + Better Auth + Cerbos |
|---|---|---|---|
| Suite | 362/362 | 362/362 | 362/362 |
| Containers | 6 | 9 | 3 |
| Memory idle / after a run | ~300 MB / ~550 MB | ~155 MB / ~575 MB | ~113 MB / ~175 MB |
| Cold start (cached images) | 16 s | 15 s | 18 s |
| App code (non-blank, non-comment) | kernel 925 + modules 1622 (shared with b) | same | kernel 312 + modules 1130 |
| Identity adapter | 265 | 198 | ~115 (Better Auth is in-process) |
| Authz adapter | 452 + schema 231 | 626 (incl. model) | ~115 + PIP 133 + policies 183 |
| Data copied into the authz engine | relationships, via outbox | relationships, via outbox | none (attributes per request) |
| Read-your-writes | ZedToken, per process (gap with 2+ instances) | `HIGHER_CONSISTENCY` per check | n/a (reads the DB) |
| Worst review finding | ex-member kept access via an agent; outbox dropped events after 10 tries (fixed) | Hydra admin API open on the LAN (open) | pool deadlock hung the app for good (fixed) |

## What the swap a → b showed

- **Code:** zero changes to modules, kernel, ports or migrations. Outside the two new adapters: `go.mod`/`go.sum` and one `case` per switch in `cmd/*/main.go`. Pattern 3 (one `can()`) and pattern 7 (hand-wired root) did their job.
- **Not covered by the interfaces** (each one bit or nearly bit):
  - which engine errors are permanent vs transient decides which sync events get dropped (both a and b had a misclassification that would lose revocations);
  - the OpenFGA sync is correct only with a single drainer (read-then-write), held by the relay's global lock, not stated in the port;
  - deploy procedure (OpenFGA: restart every instance after a model change; old instances discard events the new model needs);
  - ops exposure (Hydra's admin API; Zitadel's login-client token in the driver-config endpoint).

## Engines

- **SpiceDB vs OpenFGA:** semantics tie (models translate 1:1; the same 33 assertions pass). SpiceDB needs less glue (upserts, delete by filter, expiring relationships that get garbage-collected, preconditions) and has fewer failure windows. OpenFGA's per-check consistency flag avoids SpiceDB's per-process token problem. Reviewer verdict for this design: **SpiceDB**.
- **Cerbos:** least to run and nothing to sync; role edits apply instantly because the app is the PIP. Costs: 3 queries per check (load once per request to fix), one rule per permission because conditions can't see the action (permission list duplicated YAML ↔ code; now a CI test, generate later), and only Cerbos (no SQL scope) guarding apps/platform staff until alignment added the SQL check. `PlanResources` turned a list into SQL cleanly. Good fit for shallow tenancy; custom roles work but by resolving them in app code.

## Identity providers

- **Zitadel:** headless login works through its session + OIDC callback APIs; issuer must equal the exact host; default bcrypt cost (14) costs ~1 s CPU per user; new client secrets take seconds to work.
- **Ory (Kratos + Hydra):** docs matched v26.2; login driver worked first try; issuer is plain config. Hydra's default DB pool deadlocks under parallel logins (raised, still fails at ~150 parallel); admin API must never be published.
- **Better Auth:** least ops; rate limiter and origin check had to be understood (limiter must stay on; origin check off is safe only for a bearer-only API); creating OAuth clients needs a user session.

## Patterns (SPEC §1), verdicts across the three stacks

| pattern | verdict | evidence |
|---|---|---|
| 1. Action + one executor | holds (bent in c early) | every mutation through the executor; c needed checks inside `run` to be audited |
| 2. One `can()`, AuthZEN shape | **holds** | a → b swap touched no module |
| 3. Custom roles are data | **holds** | same role-binding pattern in SpiceDB/OpenFGA; Cerbos via attributes |
| 4. App DB as source of truth + outbox | **bent** | dropped events (a, fixed), error classification (b, fixed), false-success on failed sync, per-process ZedToken |
| 5. Three checks | holds after fixes | token-type checks were loose in a and b (b fixed, a open) |
| 6. Tenant isolation twice | holds after fixes | apps were engine-only in a and c (both now SQL too) |
| 7. Composition root by hand | **holds** | swap = new adapters + one switch case |

## Spec gaps the build found (now in v2 or §14)

- Agents could turn temporary grants into permanent roles/installs (§14 P1, pending Alex).
- Registrant-only agent grants (now a rule).
- Unassigning a role needs the power to assign it (now a rule; Go lacked it).
- Input bounds, error codes, outbox failure semantics, pool usage, multi-instance read-your-writes (now rules / known limitations).

## Recommendation

- **Pattern set:** keep all seven; strengthen pattern 4 with explicit rules for sync failures (retry forever, classify permanent errors narrowly, don't report success on a failed revoke) and a stated single-writer assumption.
- **Platform default (deep relationships, custom roles, apps, agents):** Go + SpiceDB behind the AuthZEN-shaped `can()`; identity is the more open choice (Zitadel for built-in tenancy but patch fast; Ory if paying for multi-tenant or with Network).
- **Shallow apps (SoLex-scale):** in-process `can()`, or Cerbos if conditions pile up; no relationship engine.
