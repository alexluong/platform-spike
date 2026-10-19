# Comparison, round 4 (2026-10-19): multi-pool identity

Question (SPEC §16): does the multi-pool identity model work end to end through one API? The pools are workforce, platform (merchant owners and partners), Shop, and one tenant pool per merchant, with Sign in with Shop, a pool provisioned when a merchant is created, and the gateway/app choosing the pool. And which implementation carries it better: **i**, Zitadel with one instance per merchant, or **h2**, our in-app issuer (`zitadel/oidc` `op`) with pools as rows?

Sources: `h2.md` and `review-h2.md` (branch `review-h2`), `i.md` and `review-i.md` (branch `review-i`), `zitadel-instances.md` (main; the standalone Zitadel bench, "bench" below). Design context: ctrl `docs/platform-architecture/identity-model.md`. Earlier rounds: `comparison.md`, `comparison-round2.md`, `comparison-round3.md`.

## Verdict

- **The model works.** Both stacks pass the full suite: 401/401, which is 362 core tests plus 39 multi-pool. Cross-pool isolation held against every attack the reviewers tried. Sign in with Shop works as a real OIDC round trip in both, and neither links accounts by email.
- **No stack wins outright. They fail in different places.** h2 wins on cost and atomicity: a merchant is 3 rows, created in ~35 ms inside the merchant's transaction. i wins on login features (MFA, passkeys, invites already exist) and on isolation by construction. i is heavy per merchant: ~1 MB of database and ~1–20 s to provision, and idle CPU, restart time and event-store size all grow with instance count. 10k instances is unproven. i also has the worst open finding: system keys with power over every pool sit in the internet-facing app.
- **Recommendation: a hybrid.** Zitadel carries the few platform-level pools (workforce, merchant users, Shop). h2-style rows carry the tenant customer pools. The 2026-10-19 decision moved merchant staff to the platform pool, so tenant pools now hold customers only, which makes this split cleaner. Round 5 should test the one seam the hybrid adds: Shop federation from Zitadel into the row pools.

## Side by side

Timings come from cs-ws, a shared 4-CPU host that ran at load 5–76. Compare rows within a stack. Across stacks, only differences of 2× or more mean anything.

| | **i**: Zitadel v4.19.x, instance per merchant | **h2**: in-app issuer, pools as rows |
|---|---|---|
| suite (after review) | **401/401** (188 s, 2950 instances). At load 58–76: 386–400, from timeouts and projection lag, none by design | **401/401** (109 s on ~600 pools). Regression run of the shared code on a, a2 and h: green (review-h2) |
| provisioning time | async (outbox). Create → `active`: p50 0.88 s / p95 1.1 s (one at a time, light load); 2.4 / 4.0 s (4 at a time); **8.7 / 16.8 s, max 51 s** during a suite run at 2k+ instances | **in the request**: p50 34 ms / p95 70 ms (one at a time); 95 / 146 ms (4 at a time) |
| provisioning atomicity | merchant row commits first, then 9 resumable steps. State `provisioning` until done. Zitadel down → merchant stays `provisioning`, retried until it finishes (became active 37 s after Zitadel came back). Orphan cases: duplicate Shop IdP on a lost response; a dead-lettered step leaves a half-built instance (review-i #12) | one transaction (pool row, signing key, federation client). Failure rolls everything back. **No failure window, nothing to compensate** |
| storage per merchant | **~1.1 MB** in Zitadel's Postgres (~620–670 events) + ~7 KB app. 2.67 GB at 2427 instances. **Deleting a merchant keeps its events**: the event store only grows | **~1.7 KB** identity, ~3.8 KB total. Heap ~2.2 KB per pool once used |
| idle CPU vs merchant count | defaults: grows linearly, ~0.7 core (Zitadel + PG) per 1k instances that have seen traffic, so ~7 cores at 10k. With `HandleActiveInstances` + `MaxActiveInstances` tuned: **~0.1 core, flat from 519 to 2427** (tuning is mandatory) | doesn't move with merchant count (10 → 500 measured) |
| login latency p50 / p95 | 519 instances, tuned, load ~4: pools 72–89 / 98–151 ms; Sign in with Shop **213 / 330**. At 1330, load ~15: 121–170 / 165–263; Shop 371 / 467 | ~500 merchants, load ~28: pools 53–79 / 72–141 ms; Sign in with Shop **78 / 99** |
| restart / cold start | Zitadel restart 30–34 s at 1k–2.4k instances (7 s at 20); ~5 min at 10k, extrapolated. Stack cold start 84 s | cold start 14.5 s; nothing scales with merchant count |
| LOC we own | adapter ~1,340 (provisioning ~650, resolution/gateway ~315, login stand-in + Shop ~320), plus a login UI (Login UI v2 or ours). Plus a Zitadel deployment to run | adapter 1,596 (h: 988; +608 for pools, provisioning, Shop), schema 86 + guards. **Plus everything h lacks**: MFA, passkeys, email codes, reset, login page + CSRF, admin UI |
| shared module/kernel changes | ~380 | ~340 |
| ops weight | 7 containers. Zitadel + PG at 2 GB each. Projection tuning; startup grows with instances; event-store purge is a manual SQL job; egress config for federation | app + Postgres + SpiceDB (no IdP container), image 93 MB. Per-pool rate limits still to build |
| security findings, worst first | **high, open**: two system API keys (instance owner and login client on every instance, workforce included) mounted in the app (#1). **high, fixed**: SSRF deny list opened to private ranges for Shop; narrowed to one /29 (#2). **medium, open**: MFA unenforced, no lockout, no login rate limit, and no `amr` in tokens (#3); a disabled user's tokens stay valid for 12 h (#4); i and h2 diverged on the shared module changes (#6). **medium, fixed**: tenant principal not tied to its pool (#5). **low, open**: Shop login CSRF (#10); JWKS refetch wakes idle instances (#11); provisioning edges (#12). **low, fixed**: path traversal through the gateway, block check failing open, readiness check (#7–9) | **medium, fixed**: disabling a Shop account didn't end tenant sessions (24 h via refresh) (#1); cross-pool rows had no structural guard, now composite keys + a lint (#2). **medium, open**: rate limits and hash slots shared by every pool (one merchant's burst throttles all) (#3). **low, fixed**: code redeemable after suspension (#4). **low, open**: DB read per pool-shaped `iss` (#5); no pool offboarding/backfill (#6) |
| blast radius | system keys span **every** instance. Stealing them = owning every account in every pool, workforce included. Needs a split (control plane / login UI / workforce on its own key or deployment) | one `ISSUER_SECRET` encrypts every pool's signing keys and federation secrets. DB + secret = all pools. Same shape, smaller tool (no admin API) |
| MFA / passkeys / invites | **exist**: TOTP, WebAuthn, OTP; invite codes and passkey setup links without SMTP (bench probe 4); SMTP/SMS/branding/policy per instance. MFA is enforced only by the login UI, not the API | **to build**, each with an auth review (go-webauthn, a one-time-code table, invitations). Invites can create identity + membership in one transaction |
| custom store domains | trusted domain + `x-zitadel-public-host`, verified in the bench. Tokens are bound to the issuer they were minted under, so the verifier accepts every issuer of a merchant | not built: verified-domain table, resolver branch, alias rule in `Verify` (~small) |
| Shop federation | generic OIDC IdP per tenant instance + one confidential app per merchant in the platform instance. Needs an egress path (deny list); #9535 doesn't bite across instances. A stock Login UI v2 needs Actions to tell the app about the link | tenant pool = confidential client of the Shop pool, real OIDC over HTTP, state + cookie binding, link by `(pool, shop subject)`. One loopback rate-limit bucket for every merchant's back channel (#3) |

## What both stacks taught about the model (implementation-independent)

| lesson | detail | source |
|---|---|---|
| **The shared app layer is spec-driven, not IdP-driven** | Both needed a `memberships` table (partners), `MerchantIDs`/`HomeMerchantID`/`ShopAccountID` on principals, a `customers` module (one record per merchant × Shop account), `/me` `merchantIds`/`shopLinked`, and agents naming their merchant. They forked it: two migration 003s and different order linking. Pick one layer (h2's `merchant_customer_id`) before merging; the merge is in progress on `round4-merge`. Migration 003 is one-way: merge all Go stacks together | review-i #6, review-h2 § modules |
| **Isolation patterns that worked (keep all)** | (1) subject qualified by the *verified* pool (`<pool>:<sub>`), which makes a missed query filter harmless; (2) home merchant must equal the issuing pool's merchant (`core.tokenFits`); `identity.Token.MerchantID` is now load-bearing; (3) issuer allowlist = directory: unknown or provisioning `iss` → 401 before any key fetch; (4) per-pool keys; (5) the app/gateway picks the pool and strips `x-zitadel-*`, **`Forwarded` and `X-Forwarded-Host`** (Zitadel selects instances from those too); (6) reject unclean or encoded paths before routing. Rows also need composite keys + a pool-filter lint | review-h2 #2, review-i #5, #7 |
| **Suspension must be enforced by the app** | i: Zitadel's instance block is read from a projection, so the next login could still pass. A blocked instance refuses its JWKS, so the app keeps the last good set to answer 403 `merchant_suspended` rather than 401. h2: pool status goes in the merchant's transaction, and codes are refused at a suspended pool. In both, access tokens outlive the suspension, so the app's check is the guarantee | i.md fixes 3–4, review-h2 #4 |
| **Eventual consistency (i only)** | Every write followed by a login (user, trusted domain, app, block) meets projection lag: seconds under load. A "ready" check must probe the real path (authorize must redirect to the login UI). A production login UI will meet this on fresh invites | i.md DX, review-i #9 |
| **Token lifetime and disable propagation** | A disabled user keeps access: 12 h in i (Zitadel default, no refresh), 15 min + 24 h refresh in h2 before its fix. A Shop disable must reach every linked tenant identity. Rule for both: access tokens 5–15 min, refresh checks upstream status, app-side `disabled` checked in `LookupPrincipal` | review-i #4, review-h2 #1 |
| **Limits per pool** | Hash slots, rate buckets and lockout must be budgeted per pool as well as per IP, or one merchant's login burst hurts all | review-h2 #3, review-i #3 |
| **MFA lives in the login UI** | Zitadel doesn't enforce `forceMfa` on the Session API, and its access tokens carry no `amr`. Whichever IdP is used, our login path enforces MFA, plus an app-side claim check for staff pools | bench probe 6, review-i #3 |
| **Passkeys bind to a domain** | rpId = the domain. With custom store domains, decide on one login domain or a passkey per domain before passkeys ship | h2.md, bench probe 4 |
| **Core suite `customerId`** | Core asserts an order's `customerId` == the caller, which splits a Shop buyer into two ids at a merchant (the Shop account and the linked record). Spec §8 should say `customerId` = the merchant's customer record, with a Shop exception in the suite | i.md finding, review-i #13, h2 R7 |

## Scale

| | proven | not proven |
|---|---|---|
| i | full suite at 2950 instances (review); multi-pool 39/39 at 1330; idle ~0.1 core flat to 2427 (tuned); bench to 1,034 instances under load, latency flat 250 → 1k | **10k**: extrapolated ~10 GB DB, ~6.2 M events before users, ~3 h to create, ~5 min restart, ~7 cores idle untuned. Whether a scheduler pass over 10k instances finishes in 60 s, and how cold instances behave after an incident, are unknown |
| h2 | full suite at ~570–600 merchants; nothing moved from 10 → 500 | 10k: just rows (~22 MB heap extrapolated), but not run. Shared limits (#3) matter more than count |

## Options

| option | what | for | against |
|---|---|---|---|
| **A. Zitadel everywhere (i)** | instance per merchant + workforce + platform | login features exist; no auth server of ours; per-merchant SMTP/branding | per-merchant cost and lag; 10k unproven; system-key blast radius; we still own MFA enforcement and the login UI. Under the 2026-10-19 decision, a whole instance per merchant buys only customer login |
| **B. Own issuer everywhere (h2)** | all pools as rows | cheapest, atomic, one DB, pools move with the cell | we build and review MFA for staff (forced MFA for merchant users), passkeys, invites, admin UI, workforce Google federation. Estimate ~3–5 engineer-months for v1 (identity-model §9) |
| **C. Hybrid (reviewer's)** | Zitadel: workforce, platform (owners, partners, **staff**), Shop: 2–3 instances. Rows: tenant customer pools | Zitadel goes where its features matter (forced MFA, Google upstream, invites, future enterprise SSO via orgs) and its per-instance cost doesn't (a handful of instances: no projection tuning, no 10k risk). Rows go where the count is (N merchants: 3 rows, atomic). The 2026-10-19 decision makes tenant pools customers-only: email codes, passkeys and Sign in with Shop are the narrowest login scope to build (~6–10 engineer-weeks estimate, identity-model §9) | two identity systems to run and review. Shop federation crosses them (Zitadel → rows, untested). Shop disable propagation needs a Zitadel event or a status check at refresh, since h2's fix reads the same DB. Customer login features remain ours |

**Recommendation: C.** It is the only option that avoids both i's per-merchant scaling cost and h2's job of building workforce and merchant-user MFA and SSO. What would change it:
- **→ A** if customer pools need much of what Zitadel has (social logins beyond Shop, SMS OTP, per-merchant customer SSO), *and* a 10k bench with tuned projections passes, *and* the key split is done.
- **→ B** if running Zitadel at all is unwanted, or the platform-level pools' needs shrink to what we'd build anyway (passkeys + email codes, no SAML/enterprise SSO).
- **Stronger C** if tenant pools go per store rather than per merchant (more pools).
- **Weaker C** if Shop federation from Zitadel into row pools proves awkward, e.g. per-merchant clients in the platform instance or disable propagation.

## Open items and round 5

Open after round 4 (whichever option):
- i: system-key split (#1), MFA in the login UI + lockout (#3), short token lifetimes + refresh (#4), Shop login CSRF (#10), offboarding (`deleted` pool status) (#12).
- h2: per-pool limits (#3), pool offboarding/backfill (#6), negative cache for unknown pools (#5).
- Both: one shared module layer (`round4-merge`); spec §8 `customerId`; remap to the 2026-10-19 decision (staff in the platform pool, tenant = customers).

**Round 5, only to test option C** (skip if A or B is picked outright):
1. **Hybrid stack**: Zitadel with 3 instances (workforce; platform with orgs `accounts` and `shop`) + h2 row pools for tenant customers. Staff remapped to the platform pool. Suite + multi-pool tests updated for customers-only tenant pools.
2. **Shop federation Zitadel → rows**: the tenant pool's `rp` against the Zitadel Shop issuer. Test one shared confidential client vs one per merchant; linking; **Shop disable reaching tenant sessions** (Actions v2 event vs a status check at refresh).
3. **Customer login without passwords**: email codes + passkeys in the row pools (rpId on the store domain), with an auth review. This is the expensive part of C and still unbuilt.
4. Key split for the 3-instance Zitadel (login UI vs control plane vs workforce).

The i 10k bench (`bench.ts grow --to 10000`, tuned) is needed only if option A stays in the running.
