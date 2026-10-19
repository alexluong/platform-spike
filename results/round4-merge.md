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
