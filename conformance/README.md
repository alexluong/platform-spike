# Conformance suite

Black-box tests for `spec/SPEC.md`. The same suite runs unchanged against stacks `a`, `b`, `c`, the round-2 stacks `d`, `e`, `a2` (SPEC §15), the round-3 stacks `f`, `g`, `h` and the round-4 stacks `i`, `h2` (SPEC §16); passing it is the definition of done for a stack. TypeScript + vitest, HTTP only.

## Run

```sh
mise install                      # node + pnpm from the repo's mise.toml
cd conformance && pnpm install
STACK=a HOST=cs-ws pnpm test      # or b, c, d, e, a2
pnpm typecheck                    # tsc --noEmit
```

| env | default | meaning |
|---|---|---|
| `STACK` | (required) | `a`, `b`, `c`, `d`, `e`, `a2`, `f`, `g`, `h`, `i` or `h2`: picks `stacks/<stack>.ts` |
| `HOST` | `localhost` | host where the stack's ports are published |
| `TEST_SECRET` | `test-secret` | sent as `X-Test-Secret` to `/api/_test/users` |
| `APP_URL` | `http://$HOST:<port>` | override the app base URL (ports: a 8081, b 8082, c 8083, d 8086, e 8087, a2 8088; a2's Zitadel 8089; h 8094, i 8096 (its Zitadel 8097), h2 8098) |
| `SKIP_SLOW` | unset | `1` skips the break-glass expiry test (waits ~65s) |
| `SKIP_PREFLIGHT` | unset | `1` skips the preflight (stub driver / `/healthz` check) |
| `REQUEST_TIMEOUT_MS` | `15000` | per-request timeout |
| `MAX_WORKERS`, `MAX_CONCURRENCY` | vitest default, `4` | parallel files / concurrent tests per file |

Run one file or one test: `STACK=a pnpm vitest run tests/agents.test.ts -t "expiry"`.

A **preflight** (`src/global-setup.ts`) runs first and aborts the whole run with one message if the driver is still a stub or `GET /healthz` is not 200 (connection refused, wrong host). Every request has a timeout, so nothing hangs.

Files run in parallel and tests inside a file run concurrently. There is no reset: every test builds its own merchant (unique names and emails per run), so tests are independent. Expected runtime on a healthy stack: about a minute, bounded by the break-glass expiry test (spec granularity is minutes).

## Implementing a driver

Each stack's builder fills in `stacks/<stack>.ts` (SPEC §10). The file exports a default `StackDriver`:

```ts
interface StackDriver {
  baseUrl: string
  loginUser(email: string, password: string): Promise<string>         // bearer token for /api
  loginClient(clientId: string, clientSecret: string): Promise<string> // apps and agents
  features?: string[]                                                  // opt-in test groups
  // SPEC §16.4, `multi-pool` stacks only:
  loginTenant?(merchantId: string, kind: 'user' | 'customer', email: string, password: string): Promise<string>
  loginWithShop?(merchantId: string, shopEmail: string, shopPassword: string): Promise<string>
}
```

`features: ['idp-tenancy']` (stacks `d`, `e`, `a2`) turns on `tests/idp-tenancy.test.ts`; without it that file is skipped. The `d`/`e` drivers start as copies of `c`, `a2` as a copy of `a` (ports changed); each builder adapts them to the stack's real login path. On these stacks `loginUser`/`loginClient` must reject when the IdP refuses a suspended merchant's people (SPEC §15.3).

`features: ['multi-pool']` (stacks `i`, `h2`) turns on `tests/multi-pool.test.ts` and requires `loginTenant` and `loginWithShop` (SPEC §16.4); the preflight checks they aren't stubs. `loginUser` logs into the pool of the `/api/_test/users` kind (`platform` → workforce, `user` → platform, `customer` → shop); `loginTenant` into the merchant's tenant pool (staff or customers); `loginWithShop` drives both legs of "Sign in with Shop" and returns the tenant-issued token. All three reject while the pool refuses (suspended merchant, wrong pool, wrong password). The `i`/`h2` files start as stubs naming what to build.

- Use the stack's **real** headless login path (the TODO in each stub names it). No shortcuts through the app.
- Add any IdP URLs the driver needs as exported constants with env overrides and defaults matching the ports the stack's compose file publishes (placeholders are in the stubs; fix them).
- `loginUser` is called once per user right after `POST /api/_test/users`, before the user joins a merchant. The token must keep working as memberships and roles change (the app reads permissions from its DB, not from token claims).
- `loginClient` gets the `clientId`/`clientSecret` returned by `POST /api/platform/apps` and `POST /api/agents`.
- Throw on failure (the preflight calls `loginUser` with bogus credentials and only cares whether it throws `DriverNotImplementedError`).
- Passwords the suite uses look like `Cf-<16 hex>-Aa1!` (upper, lower, digit, symbol, 22 chars); emails are `<label>-<run>-<pid>-<n>@example.com`. Configure the IdP's password policy to accept them.

## Layout

```
src/driver.ts        StackDriver interface (SPEC §10), DriverNotImplementedError
src/stack.ts         picks the driver from STACK
src/env.ts           env vars
src/client.ts        fetch client (Api.as(token)), assertions: ok, expectStatus, expectError,
                     expectDenied (403; 403|404 with crossTenant), expectConflict, expectUnauthenticated
src/world.ts         fixtures through the real API: newUser/newCustomer/newSupport/platformAdmin,
                     multi-pool: newTenantUser, loginTenant, loginWithShop, waitActive, tenantIssuer, jwtIssuer,
                     newMerchant → MerchantWorld (store, member, role, assign, memberWithRole,
                     memberWithPerms, product, order, paidOrder, ship, suspend, ...), apps, agents, break-glass
src/catalog.ts       SPEC §3/§4 as data (system roles, store/merchant-scope actions)
src/types.ts         response shapes
src/global-setup.ts  preflight
stacks/<stack>.ts    drivers: a, b, c; d, e, a2 (round 2); f, g, h (round 3); i, h2 (round 4, stubs)
tests/*.test.ts      the suite
AMBIGUITIES.md       spec readings the suite encodes where SPEC.md is unclear
```

## Tests

| file | tests | covers |
|---|---|---|
| `auth.test.ts` | 27 | `/healthz`; 401 without token / garbage / alg=none / non-Bearer, 401 before 404; test-secret guard; `/api/me` for platform, support, customer, user, owner, member, app, agent |
| `platform.test.ts` | 18 | admin creates/lists/suspends/reinstates merchants; support views only; non-platform principals denied on platform endpoints; platform_admin and support denied on merchant data without break-glass; suspension → `merchant_suspended` for users, apps, agents; customers can't order; reinstate restores; platform actions still work; isolation between merchants; staff listing stores without break-glass → 403 |
| `break-glass.test.ts` | 13 | who may open; `expiresAt`; grant audited; `*.view` reads succeed and each is audited (newest first); `/api/me/permissions` only `.view`; writes denied with no state change; only that merchant, only that opener; expiry after 1 minute (slow); `/api/me/permissions` audited |
| `system-roles.test.ts` | 101 | owner/admin/developer/staff × 21 HTTP probes (one per catalog action with an endpoint), expected result derived from §3; exact `/api/me/permissions` sets per role; system roles listed and immutable; store-scoped staff; only owner assigns/removes owner; last owner → 409 `last_owner`; 403 before 409 |
| `custom-roles.test.ts` | 32 | create/list; `not_grantable` for platform.* (create and PATCH); unknown ids; member with no roles; merchant vs store scope (incl. stores created later, store listing); union; unassign and member removal; adding/removing permissions effective on the next request; edits hit every holder; rename; delete; deny by default; refund limit under/at/over, per request, highest wins, no-limit wins, per-store roles, limit edits, system roles unlimited; duplicate assignment → 409 `already_assigned` |
| `guardrails.test.ts` | 23 | `escalation` on create/edit/rename/delete/assign of roles with permissions the caller lacks (custom and system roles, self-assignment); store-only holdings; limits ≤ own (create, absent limit, PATCH, assign); unlimited manager; store-scoped `role.manage` can't assign at merchant scope, other stores, or unassign merchant-scope; unassign runs the same guardrail (`escalation`) |
| `tenant-isolation.test.ts` | 68 | merchant A's owner, app and agent against every merchant/store endpoint of merchant B (403\|404); store listing and `/api/me/permissions` on B; cross-merchant assignment tricks; customers: own order only, `/api/me/orders` only own across stores, no merchant permissions; merchant users can't place orders; assignment scope at another merchant's store → 404 |
| `orders.test.ts` | 28 | prices from products (client prices ignored, snapshot at order time); invalid items; product update; full pending→paid→fulfilling→delivered; cancel rules; capture rules; partial refunds; `over_refund`; refund needs `paid`; shipment rules and `invalid_transition`; 403 (not 409) for forbidden callers, cross-tenant callers, and over-limit refunds; `qty` ≤ 1 000 000 |
| `apps.test.ts` | 21 | register (platform_admin only); each forbidden scope → `not_grantable_to_apps`; install with scopes ⊆ requested; installer must hold scopes at that store (`escalation`); app token does exactly its scopes on its store, nothing on other stores or merchant actions; `/api/me/permissions`; uninstall cuts access; one app on two merchants; `scope_not_requested`; unknown `appId` → 404 |
| `agents.test.ts` | 20 | register (merchant users only); grant subset of own permissions (`escalation` otherwise); store-bound; `/api/me/permissions`; revoke; expiry (2s grant, waits 3.5s); independent grants per store; granting user's role removal / permission removal / membership removal cuts the agent off; refunds use the granting user's limit, live; `not_grantable` before the registrant rule |
| `idp-tenancy.test.ts` | 28 | `idp-tenancy` stacks only (SPEC §15.2, §15.3): invitations create/list/cancel, `member.manage` required, other merchants 403\|404, invitee not a member until accept (assign 4xx, no `merchantId`), accept (case-insensitive email, no roles, then roles per §3), wrong user 403\|404, cancelled/accepted 404\|409, already a member 409, 401 without token; suspension: users and agents can't log in, earlier tokens 403 `merchant_suspended`, reinstate restores login, platform staff/customers/apps/other merchants unaffected |
| `multi-pool.test.ts` | 39 | `multi-pool` stacks only (SPEC §16.6 rules 1–9): distinct tenant issuers (`/identity`, token `iss`); tenant staff with exactly their role, removal, never at another merchant, no `/api/platform/*`; tenant customers at their merchant's stores only, own orders; same email in two pools = two accounts; cross-pool tokens 403\|404; partners in two merchants (`merchantIds`); Shop orders, Sign in with Shop, cross-merchant history, unlinked local customer; suspension at the pool (logins reject, old tokens 403, reinstate, others unaffected); provisioning (`active` ≤ 60 s, 10 in parallel) |
| `permissions.test.ts` | 11 | exact `/api/me/permissions` sets for a custom role at store vs merchant scope (both query forms), union, live edit, customer and platform admin get `[]`, missing query → 400 |

Total: 362 on every stack, plus 28 on `idp-tenancy` stacks and 39 on `multi-pool` stacks.
