# Round 4 merge: one shared layer for h2 and i

Branch `round4-merge` (from main `cc56fc1`), 2026-10-19. Inputs: `review-h2` (pools as rows, in-app issuer) and `review-i` (a Zitadel instance per merchant). Both forked the shared Go layer (review-i finding 6); this branch merges them onto one.

## Phase 1: one shared layer

### What was kept

| piece | from | why |
|---|---|---|
| migration 003 (`memberships`, `users.home_merchant_id` renamed from `merchant_id`, `shop_account_id`, email unique per platform level / per tenant pool + kind, `orders.merchant_customer_id`) | **h2** | `merchant_customer_id` is the design both reviews recommend (review-i #13, comparison-round4); platform-level emails stay globally unique, as in rounds 1–3 |
| `merchants.pool_ready` + `merchants.StatusSQL` ("provisioning" until ready) | **i**, added to h2's 003 | i provisions after the transaction; harmless elsewhere (default true) |
| i's `users.pool` column | dropped | redundant with `home_merchant_id`; nothing in i's adapter read it |
| core: `tokenFits` + `TestTokenFits`, `Principal.MemberOf` (agents by merchant, users by memberships) | **i** (same rule as h2) | h2's Authenticator dropped the round-3 "stale org claim" check for agents; i's keeps it, so a2 is unchanged |
| identity port | merged | one `identity.TenantPools` (below), `identity.ShopLinker`, `identity.ErrNotFound` |
| modules (merchants `CanJoin`, invitations, roles, agents with explicit `merchantId`, me, customers `EnsureShopCustomer`/`ShopLinker`, orders) | **h2** | `CanJoin` is one helper for add-member and accept-invitation; agents answer 403 for a non-member `merchantId` and 400 when ambiguous (i silently fell back) |
| orders `ShopLinks` gate | **i** | without it h2's orders created a linked customer record on every order in a/a2/b/f/h |
| outbox `Background` + `Workers` | **i** | additive, off by default |
| test support `/api/_test/home-realm` (kinds holding an email, from app records) | **i** | generic; h2's adapter-specific `LoginHint` and `/api/_test/login-hint` removed, h2 driver maps kind → pool |
| multi-pool switch | derived | `MultiMerchant`/`ShopLinks` on iff the adapter implements `TenantPools`; h2's `MULTI_MERCHANT` env removed |

### The port

```go
type TenantPools interface {
	ProvisionMerchant(ctx, merchantID) (ready bool, err error) // h2: rows in the tx → true; i: outbox → false
	SetMerchantSuspended(ctx, merchantID, suspended) error     // h2: in the tx; i: nil (pool-state consumer)
	PoolIdentity(ctx, merchantID) (map[string]any, error)      // ≥ {issuer}; ErrNotFound before the pool exists
	CreateTenantUser(ctx, merchantID, email, password, kind) (subject, error) // test mode
}
```

`platform.createMerchant` calls `ProvisionMerchant` in its transaction; not ready → `pool_ready=false`, the merchant answers `provisioning`, and i's adapter calls `platform.MarkPoolReady` when logins work. h2's `MerchantIssuer` became `PoolIdentity`; i's `CreatePoolUser` became `CreateTenantUser`, plus two one-line no-ops.

### Adapter ports

- **h2** (`oidcpool`): `ProvisionMerchant` returns `(true, …)` (tests call the inner `provisionMerchant`), `PoolIdentity` wraps the old issuer lookup, `LoginHint` removed. Driver: `home-realm` + `driver-config.issuerBase`. +48/−35 vs `review-h2`.
- **i** (`zitadel` instances): rename, two no-ops, `PoolIdentity` maps a missing directory row to `ErrNotFound`, `OnShopLink` typed `identity.ShopLinker` (wired to `customers.ShopLinker`, replacing i's `LinkShop`/`Linked`). Test-support tenant user creation checks `email_taken` **before** the IdP call (an external IdP's user can't roll back). +13/−3 vs `review-i`.

### LOC (shared layer: migrations, core, identity, modules, outbox, server main)

| | vs main |
|---|---|
| review-h2 | +462 −72 |
| review-i | +564 −74 |
| round4-merge (both adapters wired) | +649 −82 |

### Results (cs-ws, `MAX_WORKERS=2`, separate `ps-<x>-r4m` projects, fresh volumes, images tagged `-r4m`; main's ps-a/ps-h/ps-h2 stopped for the port and started again; everything r4m removed after)

| stack | result |
|---|---|
| h2 | **401/401** (362 core + 39 multi-pool), 99 s |
| i | **401/401**, 288 s (bench projection defaults in compose: `HandleActiveInstances=2m`, `MaxActiveInstances=200`) |
| a | **362/362** core |
| a2 | **392/392** (core + idp-tenancy) |
| h | **362/362** core |
| b | **362/362** core |
| f | 361/362, the 2 s grant-expiry test at load 26 (known: review-f); `agents.test.ts` rerun 20/20 |

`go build`, `go vet`, `go test ./...` green; the DB-backed issuer tests (`oidcpool`, `oidcop`) also pass against a throwaway Postgres (`OIDC*_TEST_DATABASE_URL`).

## Phase 2: option A remap (SPEC v4.1)

Decided 2026-10-19 (ctrl identity-model.md §1): merchant staff are platform accounts in the platform pool's one shared merchant-users org, with owners and partners; membership and roles per merchant stay in the app. **Tenant pools hold customers only.**

### Spec and suite

- SPEC §16 → v4.1 (changelog entry): pools table; §16.2 drops "tenant staff belong to exactly one merchant"; §16.3 tenant template = org `customers`; §16.4 tenant test endpoint `kind: "customer"` only (`user` → 400); **staff = core `POST /api/_test/users {kind: user}` + owner's `POST /api/merchants/:mid/members`**, logging in with `loginUser`; `loginTenant(merchantId, email, password)` is customers-only.
- Rules restated: 2 (staff are platform accounts: platform issuer, exact role, removal, not at non-member merchants, no `/api/platform/*`, no tenant login, `kind: user` → 400), 4 (same email as staff and as tenant customer = two accounts), 5 (staff of M1 on M2), 8 (a suspended merchant's staff still log in and get 403 `merchant_suspended` there, old and new tokens; act normally at their other merchants), 9 (tenant customer logins).
- `multi-pool.test.ts` still 39 tests (two v4 "staff vs customer login inside one pool" tests dropped; new: `kind: user` → 400, staff at the tenant login rejects, staff suspension login). Helpers: `newStaff`, `newTenantCustomer`, `createTenantCustomer`. AMBIGUITIES R3/R4/R6/R8/R9 restated, R14 new.
- Port: `CreateTenantUser(…, kind)` → `CreateTenantCustomer(ctx, mid, email, password)`.

### What changed per stack (LOC vs phase 1 `f1d54b8`)

| | added | removed | what |
|---|---|---|---|
| **h2** adapter (non-test) | 35 | 63 | staff login client (`merchant-admin`) and user groups gone: `idp_users.user_group` dropped (unique per pool + email), `loginGroup` switch → `isLoginClient` bool, rate-limit key per pool, `STAFF_CLIENT_ID` env gone |
| h2 adapter tests | 23 | 27 | `TestTenantGroupsApart` → `TestTenantPoolCustomersOnly` |
| h2 driver | 6 | 6 | one tenant client |
| **i** adapter + driver | 18 | 24 | tenant instance's first and only org is `customers` (one org-create call fewer per merchant, login app in `customers`), customer creation only |
| shared (core, identity, modules, migration comments) | 25 | 40 | `CanJoin` and merchant create lose the tenant-staff checks; test support loses the staff membership branch; `TestTokenFits` cases for staff as platform accounts |
| conformance (src, tests, docs) | 150 | 147 | above |

**Simpler:** tenant pools have one kind of user, so h2 needs no user groups or second client and i one org per instance; staff have one login, one issuer and one place for MFA (the platform pool: review-i #3 now applies there only); the app's tenant rule (`HomeMerchantID` = issuing pool) covers customers only. A merchant's staff list is memberships, as for partners.
**Harder / changed:** suspending a merchant no longer cuts staff logins at the IdP (they're platform accounts); only the app's `merchant_suspended` stops them at that merchant (already core §7 and enforced). In i, a wrong-pool login (staff at a tenant login) takes up to ~8 s to reject (the login stand-in retries the user search 40 × 200 ms for projection lag).

### Results (same setup as phase 1; everything r4m removed after)

| stack | result |
|---|---|
| h2 | **401/401**, 91 s (load ~27) |
| i | run 1 at load 39–51: 387/401, 14 timeouts (3 multi-pool, rest core logins); `multi-pool.test.ts` rerun **39/39**; full rerun at load 34–38: **400/401**, the 2 s grant-expiry test (known load flake), `agents.test.ts` rerun 20/20 |
| h (shared-layer regression) | **362/362** core |

`go vet`, `go test ./...` green; `oidcpool` DB tests 27/27 against a throwaway Postgres (fresh database: the edited `101` migration needs one).

### Open

- Review/bench tools still drive the v4 layout (staff in tenant pools): `stacks/h2/bench.mjs`, `stacks/h2/review-probe.mjs`, `conformance/review-i/probe.test.ts`. They reproduce round-4 evidence; not updated.
- h2's `101_pool_issuer.sql` was edited in place (no deployed databases outside the spike): an existing h2 volume must be recreated (`down -v`).
- Main's running `ps-h2` still runs the pre-merge image; rebuild after merging.
