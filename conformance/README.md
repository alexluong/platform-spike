# Conformance suite

Black-box tests for `spec/SPEC.md`. The same suite runs unchanged against stacks `a`, `b` and `c`; passing it is the definition of done for a stack. TypeScript + vitest, HTTP only.

## Run

```sh
mise install                      # node + pnpm from the repo's mise.toml
cd conformance && pnpm install
STACK=a HOST=cs-ws pnpm test      # or b, c
pnpm typecheck                    # tsc --noEmit
```

| env | default | meaning |
|---|---|---|
| `STACK` | (required) | `a`, `b` or `c`: picks `stacks/<stack>.ts` |
| `HOST` | `localhost` | host where the stack's ports are published |
| `TEST_SECRET` | `test-secret` | sent as `X-Test-Secret` to `/api/_test/users` |
| `APP_URL` | `http://$HOST:<port>` | override the app base URL (ports: a 8081, b 8082, c 8083) |
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
}
```

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
                     newMerchant → MerchantWorld (store, member, role, assign, memberWithRole,
                     memberWithPerms, product, order, paidOrder, ship, suspend, ...), apps, agents, break-glass
src/catalog.ts       SPEC §3/§4 as data (system roles, store/merchant-scope actions)
src/types.ts         response shapes
src/global-setup.ts  preflight
stacks/{a,b,c}.ts    drivers (stubs until each builder implements them)
tests/*.test.ts      the suite
AMBIGUITIES.md       spec readings the suite encodes where SPEC.md is unclear
```

## Tests

| file | tests | covers |
|---|---|---|
| `auth.test.ts` | 27 | `/healthz`; 401 without token / garbage / alg=none / non-Bearer, 401 before 404; test-secret guard; `/api/me` for platform, support, customer, user, owner, member, app, agent |
| `platform.test.ts` | 15 | admin creates/lists/suspends/reinstates merchants; support views only; non-platform principals denied on platform endpoints; platform_admin and support denied on merchant data without break-glass; suspension → `merchant_suspended` for users, apps, agents; customers can't order; reinstate restores; platform actions still work; isolation between merchants |
| `break-glass.test.ts` | 10 | who may open; `expiresAt`; grant audited; `*.view` reads succeed and each is audited (newest first); `/api/me/permissions` only `.view`; writes denied with no state change; only that merchant, only that opener; expiry after 1 minute (slow) |
| `system-roles.test.ts` | 101 | owner/admin/developer/staff × 21 HTTP probes (one per catalog action with an endpoint), expected result derived from §3; exact `/api/me/permissions` sets per role; system roles listed and immutable; store-scoped staff; only owner assigns/removes owner; last owner → 409 `last_owner`; 403 before 409 |
| `custom-roles.test.ts` | 30 | create/list; `not_grantable` for platform.* (create and PATCH); unknown ids; member with no roles; merchant vs store scope (incl. stores created later, store listing); union; unassign and member removal; adding/removing permissions effective on the next request; edits hit every holder; rename; delete; deny by default; refund limit under/at/over, per request, highest wins, no-limit wins, per-store roles, limit edits, system roles unlimited |
| `guardrails.test.ts` | 19 | `escalation` on create/edit/rename/delete/assign of roles with permissions the caller lacks (custom and system roles, self-assignment); store-only holdings; limits ≤ own (create, absent limit, PATCH, assign); unlimited manager; store-scoped `role.manage` can't assign at merchant scope, other stores, or unassign merchant-scope |
| `tenant-isolation.test.ts` | 67 | merchant A's owner, app and agent against every merchant/store endpoint of merchant B (403\|404); store listing and `/api/me/permissions` on B; cross-merchant assignment tricks; customers: own order only, `/api/me/orders` only own across stores, no merchant permissions; merchant users can't place orders |
| `orders.test.ts` | 25 | prices from products (client prices ignored, snapshot at order time); invalid items; product update; full pending→paid→fulfilling→delivered; cancel rules; capture rules; partial refunds; `over_refund`; refund needs `paid`; shipment rules and `invalid_transition`; 403 (not 409) for forbidden callers, cross-tenant callers, and over-limit refunds |
| `apps.test.ts` | 20 | register (platform_admin only); each forbidden scope → `not_grantable_to_apps`; install with scopes ⊆ requested; installer must hold scopes at that store (`escalation`); app token does exactly its scopes on its store, nothing on other stores or merchant actions; `/api/me/permissions`; uninstall cuts access; one app on two merchants |
| `agents.test.ts` | 17 | register (merchant users only); grant subset of own permissions (`escalation` otherwise); store-bound; `/api/me/permissions`; revoke; expiry (2s grant, waits 3.5s); independent grants per store; granting user's role removal / permission removal / membership removal cuts the agent off; refunds use the granting user's limit, live |
| `permissions.test.ts` | 10 | exact `/api/me/permissions` sets for a custom role at store vs merchant scope (both query forms), union, live edit, customer and platform admin get `[]`, missing query → 400 |

Total: 341.
