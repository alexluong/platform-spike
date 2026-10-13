# Comparison, round 2 (2026-10-13): identity-owned tenancy

Question (SPEC §15): if the identity provider owns tenancy (organizations, members, invitations, login policy), does the spec get cleaner, and what does it push back into the app? Three stacks, each built from a round-1 stack, then reviewed. Details: `d.md`, `e.md`, `a2.md`, `review-d.md`, `review-e.md`, `review-a2.md`. Round 1: `comparison.md`.

## At a glance

| | d: TS + Better Auth org plugin + Cerbos | e: d with SpiceDB | a2: Go + Zitadel org per merchant + SpiceDB |
|---|---|---|---|
| built from | c | d | a |
| suite (after review) | **392/392** (362 + 30 idp-tenancy) | **392/392**; d still 392/392 | **390/390** (362 + 28); a still 362/362 |
| containers | 3 | 4 | 6 |
| memory idle / after a run | ~112 / ~183 MB | — / ~354 MB | ~236 / ~784 MB |
| cold start | 9.5 s | 11 s | 16 s |
| code vs parent | `ts/src` → `ts-org/src` +588 −103; Better Auth glue 157 → 405 lines | 1 module line; adapter 391 + relay 117 | Go +926 −69; **nothing removed** |
| identity writes vs the app's transaction | **same transaction** (Better Auth shares the DB; through an internal API) | same as d | a second outbox consumer, per merchant, waiting on Zitadel's projections |
| custom roles in the IdP? | no: dynamic access control has no store scope, no assignments, no limits, partial guardrails | no | no: project roles are flat keys defined by the platform |
| worst open finding | tx-joining rests on Better Auth internals (an upgrade can silently move a write out); orphan OAuth clients | platform staff checked only by SpiceDB (no SQL check); P6 | test mode logs in as anyone; Zitadel admin with default password and console published (spike config) |

## Answer: no, IdP-owned tenancy did not make this spec cleaner

Neither IdP could take authorization (custom roles with store scope, limits, guardrails, agents, apps), so roles stayed in the app and engine. And the app still needed membership and merchant status in SQL for the tenant precheck, the one-merchant rule and row locks. So the IdP's organizations became one more place that holds tenancy.

- **Better Auth (d): the data model got cleaner, the code didn't.** One writer for tenancy data and no identity sync, because Better Auth's tables are in the app's Postgres and its writes can join the app's transaction. That gain comes from Better Auth being **in-process**, not from the organization plugin. The plugin gave invitation storage and accept rules, an org schema and a place for login hooks. It pushed back: the transaction bridge (internal AsyncLocalStorage), concurrency rules (one merchant per user, concurrent joins), read-only table mirrors plus a hand-written migration, two login hooks, and all authorization (its own endpoints enforce its role model, so they're unusable). Reviewer: "a storage library for three tables"; invitations in-app would be about the same size as the glue.
- **Zitadel (a2): more code, and a second sync.** Zitadel can't move a user between organizations, and users exist before they join a merchant, so membership became a cross-org authorization and every user lives in a `people` org. Deactivating an org only stops identities resident in it (agents), so suspension fans out over every member's authorization; refresh tokens keep working. Every identity write goes through a second, per-merchant outbox consumer that waits on Zitadel's lagging projections (suspend 12 ms → 184 ms). The review found a new race (a member added during a suspend could still log in; fixed).
- **What Zitadel gives that Ory OSS and Better Auth don't:** tenant lifecycle enforced at token issuance (agents cut off at once), login-time authorization checks, org-scoped machine users, and per-org SSO, login policy, branding and delegated admin. a2 used none of the last group. **Worth it only when merchants need their own SSO or to manage their own staff in the IdP**, and their users are created inside their org (invite a new email).

## What round 2 taught beyond the question

1. **An in-process IdP that shares the app's DB is a structural advantage.** One transaction covers identity and app state; an external IdP is another outbox consumer with all of pattern 2's rules (retry, classification, ordering, failure windows, projection lag).
2. **The TS engine swap held by line count but exposed a Cerbos-shaped contract** (e). d's executor let the engine supply the `merchant_suspended` reason and the break-glass audit marker, and d's events carried only ids and skipped state changes Cerbos didn't need (break-glass). The SpiceDB adapter had to rebuild both from the DB. Go's executor owns those as SQL prechecks, which is why a → b was cleaner. Rule: **the executor owns deny reasons, audit markers and a SQL check for every principal kind (staff included); every state change emits an event.**
3. **TS vs Go on SpiceDB is a tie on size, and e came out more correct** (second-pass learning, not the language): ZedToken stored in the DB (read-your-writes across instances, fixing a's limitation), a deadline on every gRPC call (Go has none: one request took 72 s with SpiceDB down), waiters that hold no connection, and a reconcile-from-DB relay that is order-insensitive and cleans up leftovers Go doesn't.
4. **Two relay designs, both valid:** full-state events (Go: modules must emit full state) vs events that name an object and a relay that reads current state (e: couples the relay to the schema, more engine calls, order-insensitive). Reviewer e prefers the second, plus a full-resync path.
5. **Error classification bit a third time:** SpiceDB's `FailedPrecondition` means "schema/relation not found" (a stale or missing schema), so treating it as permanent would dead-letter every event after a datastore reset. Fixed in e; **still wrong in Go (`spicedb.go:234`, stacks a/a2)**.

## Backports for the Go stacks (not done)

- `FailedPrecondition` → transient in the SpiceDB adapter.
- Per-call gRPC deadlines.
- ZedToken in the DB (or a2's per-merchant drain plus a shared token).
- Platform staff: keep the SQL break-glass check before the engine (e lacks it; check a).

## Recommendation (updated)

- **Authorization:** unchanged. SpiceDB behind the one `can()`, with the executor owning prechecks, deny reasons and audit; e's relay hardening (DB-stored ZedToken, deadlines, narrow permanent errors, non-blocking waits).
- **Identity:** keep the IdP to login and credentials; keep tenancy (merchants, members, invitations) in the app. An in-process library that shares the DB (Better Auth) is the least glue. Use IdP organizations (Zitadel) only when per-merchant SSO or delegated user admin is a real requirement, and design for invite-created users from the start.
- **Language:** open. e shows a TS app on SpiceDB is as small as Go's and can be as correct; Go's executor gave the cleaner seam. Pick on team and ecosystem, not on this spike.
- **Better Auth organization plugin:** optional, for invitations and the org schema; pin Better Auth exactly and run `tx-probe` in CI as an assertion.

## Spec changes the reviews propose (not applied)

- §15.1: membership is "the IdP's grant to the user" (not residency); serialize membership adds against suspension; a regression check that IdP writes stay in the transaction when claimed.
- §15.3: "can't log in" = no new sessions or tokens through any route, grant or client auth method; say what happens to refresh tokens and existing sessions.
- §1: the executor owns deny reasons and audit markers; every state change emits an event; say whether events carry full state or name an object; "permanent" = can never apply to the code's own schema; adapters may assume one drainer per object.
- §14 P6 → 503 `sync_pending`; each stack records its connection budget (two e instances exceed Postgres's 100 connections).
