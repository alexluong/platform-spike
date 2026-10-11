# Spec ambiguities and the readings the suite encodes

Where `spec/SPEC.md` is unclear, the suite picks one reading and tests it. Each entry: spec section, the question, the reading, where it's tested. Fix the spec (or tell the suite to change) for any you disagree with.

## Permissions and scopes

1. **§9 `/api/me/permissions` scope semantics.** Which actions does `?merchantId=` vs `?storeId=` report? **Reading:** each action is reported at the resource type its §4 scope column names. `?storeId=` → store-scope actions held at that store (via store or merchant assignments). `?merchantId=` → merchant-scope actions (`merchant.view`, `merchant.update`, `member.manage`, `role.manage`, `store.create`) held via merchant-scope assignments. `role.manage` ("merchant or store") appears in both. Store-level actions are not reported at merchant level even when held at merchant scope. Tested: `permissions.test.ts`, `system-roles.test.ts`, `apps.test.ts`, `agents.test.ts`.
2. **§3 store-scoped assignment of a role containing merchant-scope permissions** (e.g. `staff` at a store contains `merchant.view`). **Reading:** a store assignment grants nothing on the merchant resource, so a store-scoped staff user can't `GET /api/merchants/:mid`, and `?merchantId=` reports `[]`. Tested: `permissions.test.ts` (`?merchantId= → []`). The suite never asserts the store-scoped user is denied `GET /api/merchants/:mid` directly.
3. **§3 guardrail "holds every permission in that role at that scope" when the role contains merchant-scope permissions and the assignment is at store scope.** **Reading:** the caller "holds" a permission at a store if a role containing it is assigned to the caller at that store or at the merchant, regardless of the permission's catalog scope. So an owner can assign `staff` (which contains `merchant.view`) at store scope. Tested: `system-roles.test.ts` (store-scoped staff), `permissions.test.ts`.
4. **§3 guardrail on edit: old or new permission set?** **Reading:** both. To edit a role (even just rename it), the caller must hold every permission currently in the role and every permission it will have. Tested: `guardrails.test.ts` ("cannot edit (even rename)…").
5. **§3 store-scoped `role.manage` and role CRUD.** Roles are merchant-level objects; can a store-scoped `role.manage` holder create/edit/delete them? **Not tested.** Only assignment at its store (allowed) and at merchant scope / another store / unassigning a merchant-scope assignment (denied) are tested.
6. **§3 escalation code on unassign.** The guardrail lists create/edit/assign/delete; unassign isn't mentioned. **Reading:** unassign needs `role.manage` at the assignment's scope (403); no `escalation` check is tested for unassign.
7. **§3 "only an owner can assign or remove the owner role": error code.** **Reading:** 403, any code (`forbidden` or `escalation`).
8. **§3/§9 admin removing an owner as a member** (`DELETE /members/:uid`, which also removes assignments). **Reading:** counts as removing the owner role → 403 for a non-owner. Tested: `system-roles.test.ts`.
9. **§3 system role ids.** **Reading:** the literal strings `owner`, `admin`, `developer`, `staff` are the role ids in every merchant, usable as `roleId` and in `/roles/:rid`; `GET /roles` lists them with `system: true` and the §3 permissions.
10. **§3 PATCH/DELETE of a system role: status.** **Reading:** any of 400/403/409; the role must be unchanged.
11. **§9 no endpoint lists role assignments**, so the owner assignment created with the merchant has no known id. The last-owner rule is tested through `DELETE /members/:uid` and through an owner assignment created via the API. Consider adding `GET /api/merchants/:mid/role-assignments` (and returning the owner assignment id from merchant creation).
12. **§4 `merchant.update` has no endpoint.** It is only checked through `/api/me/permissions`.
13. **§3 assigning a role to a user who isn't a member of the merchant** (e.g. a member of another merchant). **Reading:** any of 400/403/404/409; never 201.
14. **§3 deleting a role, then deleting one of its (now removed) assignments.** **Reading:** 404.

## Refund limits

15. **§3/§4 refund limit: per request or cumulative?** "amount ≤ role limit". **Reading:** per refund request. Two refunds of 400 under a 500 limit both succeed. Tested: `custom-roles.test.ts`.
16. **§9 over-limit refund code.** "403 when over the limit", no code. **Reading:** 403, any code. Suggest a specific code (e.g. `refund_limit`).
17. **§1.5/§8 order of checks: limit vs state.** **Reading:** the refund limit is a condition (part of authorization), so an over-limit refund that would also be `over_refund` returns 403, not 409. Tested: `orders.test.ts`.
18. **§3 limit across stores.** **Reading:** only roles applying at the order's store count (a no-limit role at another store doesn't lift the limit). Tested: `custom-roles.test.ts`.

## Orders, payments, delivery

19. **§8 409 codes other than `over_refund` and `invalid_transition` are unnamed** (cancel from a wrong status, capture on non-pending, refund on non-paid, shipment on non-paid). **Reading:** 409 with any code. Suggest `invalid_state`.
20. **§4/§8 refund status precondition.** **Reading:** the order must be exactly `paid`; refunds on `fulfilling`/`delivered` → 409. Status after a full refund is not specified and not asserted.
21. **§8 shipment transitions.** Backwards → 409 `invalid_transition` (tested). Same status again and skipping forward (`label_created` → `delivered`) are **not tested**. Unknown status value → 400 (tested).
22. **§9 order placement edge cases.** Client-supplied `unitPriceCents` is ignored; a product from another store → 400/404/409; empty items or `qty: 0` → 400; a later product price change doesn't alter an existing order; non-positive `amountCents` → 400.
23. **§2/§9 who may place orders.** **Reading:** only `customer` principals; a merchant user → 403. `GET /api/me/orders` by a non-customer → 403.
24. **§8 cancel response / refund response.** Cancel: any 2xx. Refund: 200 with the updated `Order` (`refundedCents`). Capture: 201 Payment. Shipment status: 2xx Shipment.

## Platform, break-glass, suspension

25. **§7 platform staff and `GET /api/merchants/:mid` without break-glass.** **Reading:** merchant data → 403 (they use `/api/platform/merchants`). Also `/api/me/permissions` for them is `200 {actions: []}`.
26. **§7 audit entry contents.** **Reading:** `actor` is the user id (the suite also accepts the email); the grant's `action` is `platform.break_glass`; each request under break-glass is audited with the catalog action id it ran (e.g. `order.view`, `merchant.view` for `GET /roles`). Whether **denied** writes under break-glass are audited is not specified; the suite only requires ≥ 1 entry per allowed read.
27. **§7 break-glass expiry granularity.** `minutes` is the only unit, so the expiry test waits 65s (skip with `SKIP_SLOW=1`). A `seconds` field (test mode only) would make this fast.
28. **§7 break-glass scope.** **Reading:** the grant covers only its opener and only that merchant; break-glass reads include `merchant.view` (`GET /api/merchants/:mid`, `GET /roles`) and `app.view`.
29. **§7 suspended merchant: customer order code.** **Reading:** 403, any code (suggest `merchant_suspended`). Public product listing of a suspended store: not tested.
30. **§7 suspension vs other denials.** Members of the suspended merchant get `merchant_suspended` on actions they would otherwise be allowed (tested on reads, writes, role creation, store creation). For users of *other* merchants nothing changes.
31. **§9 suspend/reinstate status codes.** **Reading:** 200 (the table shows a body, not 201).

## Apps and agents

32. **§5 install with scopes ⊄ requested.** **Reading:** 400, any code. Suggest `invalid_input`.
33. **§5 registering with a non-grantable (platform.*) scope.** **Reading:** 400 with `not_grantable`, `not_grantable_to_apps` or `invalid_input`.
34. **§5 app access to merchant-level endpoints** (role/store creation, agent registration). **Reading:** denied (apps act on stores only).
35. **§5 one app installed on several merchants.** **Reading:** allowed; installs are independent. Installing the same app twice on one store: not tested.
36. **§6 which agents a user may grant.** The suite only grants agents the granting user registered (plus: another merchant's agent → 400/403/404). Granting a teammate's agent is not tested.
37. **§6 who may register agents.** **Reading:** merchant users only; platform staff, customers and users with no merchant → 403.
38. **§6 expired/revoked grant.** **Reading:** the agent token stays valid (no 401); requests → 403.
39. **§6 agent's `/api/me`.** `{kind: "agent", merchantId}` of the registering user's merchant. App's `/api/me`: `kind: "app"`, `merchantId` not asserted.
40. **§6 granter's permission partially removed.** **Reading:** the agent loses exactly the actions the granter lost; restoring the permission restores the agent (grant itself unchanged).

## Auth and general

41. **§2/§10 token vs membership.** The suite logs each user in once, before they join a merchant. **Reading:** `merchantId` and permissions come from the app DB, so the same token reflects later membership and role changes.
42. **§9 401 before 404.** Protected endpoints without a valid token → 401 `unauthenticated` even for nonexistent ids. Non-Bearer `Authorization` → 401.
43. **§9 test-support guard.** Missing or wrong `X-Test-Secret` → 401 or 403.
44. **§9 nonexistent ids within one's own merchant.** **Reading:** 403 or 404 (an unknown id can't be attributed to a merchant).
45. **§9 cross-tenant `GET /api/merchants/:mid/stores` and `/api/me/permissions`.** **Reading:** 403/404, or 200 with an empty list.
46. **§9 `/api/me/permissions` without `storeId`/`merchantId`.** **Reading:** 400.
47. **§9 timestamps** (`expiresAt`, `at`). **Reading:** ISO 8601 strings parsable by `Date.parse`. `expiresAt` checked within ±2 minutes of now + duration (clock skew).
