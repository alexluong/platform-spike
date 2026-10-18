# Review: stack g (Hono + OpenAuth 0.4.3 + Cerbos + Postgres)

Reviewed on 2026-10-19, branch `stack-g`, against `ps-g` on cs-ws. Builder's claim: 362/362. After the fixes below: **362/362** (30 skipped: the opt-in `idp-tenancy` tests), including the slow break-glass expiry test. Unit tests: 30 (was 28). Stack c, rebuilt from this branch's shared `main.ts`: **362/362**.

The builder found the two big issuer traps (`iss` from headers, `allow()` redirecting anyway) and gated them. The gate itself could be walked around with one percent-encoded letter, which put back everything it was for. The rest of the findings are the parts OpenAuth leaves to whoever stores its data: refresh tokens for machine clients, code redemption, and keys cached per process.

cs-ws ran at load 15–37 on 4 CPUs during this review (other agents building). The default suite (`MAX_CONCURRENCY=4`) then times out on random tests in both g and c (c: 51 timeouts once). With `MAX_WORKERS=2 MAX_CONCURRENCY=2`, both pass in full; the failing file alone passes too.

## Findings, by severity

| # | sev | what | where | scenario | status |
|---|---|---|---|---|---|
| 1 | **high** | `/authorize` gate bypass. The gate compared the raw path (`u.pathname === '/authorize'`), but Hono routes on the `decodeURI`'d path, both in the app (the allow-list) and in the issuer. `/%61uthorize` passed the allow-list, skipped the gate and reached the issuer's `/authorize`. | `ts/src/adapters/openauth.ts` `handler` | `GET /%61uthorize?client_id=evil&redirect_uri=https://evil.example/cb&response_type=token` → **302 to evil.example** (the #299 open redirect). With `client_id=platform-cli`, `response_type=token` (implicit flow) and no PKCE were accepted again. Reproduced. | **fixed**: the handler decodes the path, gates and forwards the decoded path; malformed encoding → 400. Unit test pins the issuer's decoding. Re-probed: 400 for all variants (`/%61uthorize`, `/AUTHORIZE`, `//authorize`, `/./authorize`, `/password/../authorize`, `/%70assword/register`) |
| 2 | medium | Machine-client refresh tokens chain forever without the secret. OpenAuth returns a refresh token with every `client_credentials` token; its refresh grant checks neither the client nor the secret and hands out a new refresh token each time. The builder's 60 s TTL applies per link, not to the chain. | issuer `/token` (`refresh_token` branch), adapter `success` | Get a client token, **delete the client row**, refresh every 20 s: 200, 200, 200 (past 60 s). Secret rotation or client deletion never stops token issuance; only the app's own per-request checks on `apps`/`agents` still apply. Reproduced. | **fixed**: for `client_credentials`, the handler deletes the stored refresh row and drops `refresh_token` from the response. Re-probed: no `refresh_token`, refresh → `invalid_grant`, 0 client refresh rows |
| 3 | medium | Multi-instance key race, called "harmless" in g.md. Each instance caches its signing and encryption key list for the life of the process (issuer `lazy()`, client `jwksCache`, no refetch on an unknown `kid`). Two instances booting on an empty table can each create a key and keep only their own: tokens from one, and the encrypted `authorization` cookie, fail on the other until restart. | `openauth.ts` boot (keys warmed outside a lock); OpenAuth `keys.ts` | Not reproduced before the fix (by code reading; upstream #322 is the same race on KV). | **fixed**: keys are created at boot under `pg_advisory_lock`. Checked: 4 rounds of `down -v` + two app instances started together → 1 signing + 1 encryption key, same JWKS on both; cookie from A accepted by B; token from A accepted by B |
| 4 | medium | Key rotation needs every instance restarted at once. Expire the key and restart one instance: it signs with a new key that the others don't know. | OpenAuth `client.ts` / `issuer.ts` caches | Marked the key expired, restarted A only: token from A → **401 on B**. Reproduced. | open: rolling rotation needs a publish-then-sign step (add the new key, wait for every instance to reload, then sign with it), i.e. our own key code or a patched client that refetches on an unknown `kid` |
| 5 | medium | No rate limiting or lockout on `/password/authorize` and `/token`. Stack c has Better Auth's limiter on by default (review-c #7). | OpenAuth (none), adapter | Unlimited online password guessing. | open: middleware in front of the two paths (per IP and per account), shared store once there are 2+ instances |
| 6 | low | Login timing reveals which emails have a password. The password provider skips scrypt when no hash is stored. | OpenAuth `provider/password.ts` | Wrong password: known email 43 ms, unknown 9 ms (median of 10). | **fixed**: the `login` error callback runs scrypt against a dummy hash when the email has none. After: 107 vs 97 ms interleaved (x30), with the host at load ~35; the residual gap isn't explained by the code paths (same work on both) and is within noise here; re-measure on a quiet host |
| 7 | low | Authorization code redeemable more than once in parallel. The issuer does get-then-remove; the storage interface has no atomic take. | issuer `/token` (`authorization_code`) | 5 parallel `/token` calls with one code and its verifier: 4–5 got tokens (5 rounds). Needs the PKCE verifier, so only the client itself (or whoever holds the verifier). Reproduced. | **fixed**: the handler claims the code first (`insert … on conflict do nothing` on `oauth:code-claimed/<code>`, 5 min expiry); the loser gets `invalid_grant` |
| 8 | low | User refresh tokens (1 day) never re-check anything: `success` isn't re-run (#275), and there is no logout or revocation endpoint (#131, #249). | issuer | A leaked refresh token keeps minting 15-min access tokens for a day. Suspension, membership and deleted users are still enforced per request from Postgres. | open (builder noted). Production: a `disabled`/`tokens_valid_after` column checked in the resolver, and deleting `oauth:refresh/<sub>/*` on logout |
| 9 | low | Login CSRF on `POST /password/authorize`: no CSRF token, the `authorization` cookie has no `SameSite` over http. | OpenAuth password provider | A page could log a victim's browser into the attacker's account. The code still goes only to the registered loopback URI. | open: irrelevant for the headless CLI; matters with a browser UI |
| 10 | low | Storage prefix scan has no trailing separator: `invalidate(sub)` (refresh-token reuse detection) scans `oauth:refresh/<sub>` and would also delete tokens of any subject whose id starts with `<sub>`. OpenAuth's memory adapter does the same. | `openauth-pg-storage.ts` `scan` | No impact today: user and client ids are fixed-length (`usr_` + 14, `cli_` + 16). | open: note for any id scheme change |
| 11 | low | Test endpoint as in c (review-c #14, SPEC P5): `TEST_MODE=1`, `TEST_SECRET=test-secret` in compose, port 8093 on the lab network, compare with `!==`. | `stacks/g/compose.yaml` | Anyone on the tailnet can mint a `platform_admin`. | open (same as every stack) |
| 12 | info | `createUser` writes the provider's internal key `email/<email>/password` (undocumented layout) with a check-then-set race on "email taken". | `openauth.ts` | Test-only path. | open (builder noted) |
| 13 | info | Discovery advertises `response_types_supported: ["code", "token"]`; the gate refuses `token`. Issuer errors after the cookie is set redirect `err.message` (e.g. a DB error) to the registered redirect URI. | issuer | Cosmetic; loopback only. | open |

Checked and fine:
- **Client secret check:** SHA-256 of a 256-bit random secret, `timingSafeEqual` on two 32-byte digests; unknown client short-circuits (reveals only whether a random `cli_…` id exists). `client()` can't reject, and `success` returns 401 on `ok: false`. `provider=password` with `client_credentials` → 400.
- **Token verification:** `jwtVerify` with the pinned issuer, keys from the local JWKS (ES256 only), `mode: access`, subject schema, then `aud` (user tokens: `platform-cli`; client tokens: `aud == properties.clientId`). OpenAuth issues no ID tokens and signs nothing else with that key. Unknown `type` → schema lookup throws inside the `try` → 401. P7's `typ: at+jwt` isn't available (`typ: JWT`); `mode` does the job.
- **Duplicate query parameters:** gate and issuer both take the first value (`client_id=platform-cli&client_id=evil` stays `platform-cli`).
- **Unmounted routes:** `/password/register`, `/password/change`, `/client/*` → 404, encoded or not.
- **Host ports:** only 8093. Postgres and Cerbos are internal.
- **Storage adapter:** expired rows hidden on read (`expiry > now()`), upsert on set, swept every 10 min; parameterised queries; `LIKE` prefix escaped (backslash is the default escape); `collate "C"` makes the prefix scan use the primary key.
- **Shared `main.ts`:** c keeps `AUTH_SECRET` required (checked at start), the Better Auth handler and its allow-list. c rebuilt from this branch: 362/362.

## Ops (re-measured)

- **Cold start** (`down -v`, cached image, `up -d --wait`): 9–16 s (host load 15–37). Restart to healthy: 22 s. A token from before the restart still works (keys in Postgres).
- **Burst, 60 parallel, one user:** logins 60/60 in 4.0 s; `/api/me` 60 × 200 in 0.6 s; `/healthz` 200 after. Same as the builder's numbers.
- **Two instances on one database:** work after fix #3 (one key set, cookies and tokens cross over). Rotation still needs a full restart (#4). Each instance runs the KV sweep; harmless.

## Maintenance claims (checked on GitHub, 2026-10-19)

Accurate:
- 0.4.3 released 2025-03-04, still `latest` on npm; last snapshot `0.0.0-20250322224806`.
- Last commit on `master`: 2025-04-09.
- 100 open issues, 44 open PRs, 7.4k stars.
- #299 (open redirect, 2025-09-12): 0 comments.
- #326 ("still being maintained?", 2026-03-03): 5 comments, all from non-members, none from a maintainer.

Missed:
- An unreleased `1.0` branch has a commit from 2025-07-18 (the repo's last push). Nothing since.
- Forks: `swalker326/openauth` (announced in #326, 0 stars, last push 2026-03-16) and `kagii-dev/openauth` (11 stars, last push 2026-04-01). Neither is an obvious successor.

## Verdict on OpenAuth

**Agree with the builder: not for this platform**, and more firmly than g.md puts it.

- The in-process model and the numbers hold up (memory, login cost, bursts, cold start).
- The cost is in the gaps. Of the seven fixes in g (builder plus review), every one is in code OpenAuth leaves to the integrator: issuer pinning, the `/authorize` gate, the gate's own path handling, client refresh tokens, code redemption, key creation, login timing. Each was found by reading the issuer's 1.1k lines. A maintained library would have shipped or fixed most of them; here nobody will, and #299 shows reports go unanswered.
- What's left open (#4 rotation, #5 rate limiting, #8 revocation) is ordinary auth-server work. With OpenAuth you write it into a fork you then own.
- So the comparison is Better Auth (maintained, ships M2M, limiter, sessions you can revoke) or an external IdP. OpenAuth is a reasonable read for how small an issuer can be, and a fit for a users-only app on Workers whose owners accept a fork.

## Fixed in this review (commits on `stack-g`)

1. `5040338` Gate the decoded `/authorize` path (#1); drop client refresh tokens (#2); create keys under an advisory lock (#3); dummy scrypt for unknown emails (#6).
2. `ef94845` Claim authorization codes atomically (#7).
3. This report; g.md's "harmless" key-race line corrected.
