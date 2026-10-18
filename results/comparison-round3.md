# Comparison, round 3 (2026-10-19): identity providers not yet tried

Question: as the identity provider in its login-only role (tenancy, roles and membership stay in the app, per round 2), do **Logto** (external server) or **OpenAuth** (minimal issuer library) fit better than Zitadel, Ory or Better Auth? Two stacks, each an identity-adapter swap of a round-1 stack, then reviewed. Details: `f.md`, `review-f.md`, `g.md`, `review-g.md`. Earlier rounds: `comparison.md`, `comparison-round2.md`.

## At a glance

| | f: Go + Logto 1.45 + SpiceDB | g: TS + OpenAuth 0.4.3 + Cerbos |
|---|---|---|
| built from | a (Zitadel swapped out) | c (Better Auth swapped out) |
| suite (after review) | **362/362** | **362/362**; c still 362/362 |
| changes outside adapter / root / compose / driver | none (plus registering the stack in `conformance/src`) | none |
| identity adapter | 295 LOC (a: 265, b: 180) | 142 + 40 storage (c: 113) |
| containers (long-running) | 7: 3 Logto replicas + nginx edge + app + SpiceDB + Postgres | 3, same as c (issuer runs inside the app) |
| memory idle / after a run | ~800 MB / ~1.3 GB (~355 MB with 1 replica) | ~124 / ~164 MiB (c: 113 / 175) |
| cold start | 31–34 s | 11 s |
| images | Logto 1.98 GB | app 542 MB (c: 537) |
| CPU per user create + login | **~650 ms** (a: ~100 ms with Zitadel's hash cost lowered for dev) | lighter than c in every burst (logins 4.0 s vs 7.2 s for 60) |
| machine clients (apps, agents) | built in: M2M apps, 2 Management API calls, secret works at once | **not in OpenAuth**: client table + provider written (~35 LOC) |
| worst open finding | wrong-password attempts are a cheap CPU DoS and can lock users out (no rate limit in OSS) | signing-key rotation needs every instance restarted; no login rate limit |
| project health | monthly releases (last 2026-10-13), MPL-2.0; branding removal / custom sign-in UI need a paid Self-Hosted Pro licence (v1.45) | **dormant**: last release 2025-03, last commit 2025-07 (unreleased 1.0 branch); security reports unanswered |

## Answer: neither beats the current picks

- **Logto (f): cleanest tokens, heaviest runtime.** The verifier was the hardest to break of all stacks (typed `at+jwt`, audience = our API, ID tokens and other apps' tokens rejected), and credentials are immediate (Zitadel needed retries). Against it: ~6× Zitadel's CPU per login (Argon2 on a single Node event loop with a fixed cost), so 3 replicas just to pass the suite; a 2 GB image; the first Management API client has to be seeded with SQL into Logto's tables (upgrade risk); an unbranded customer-facing sign-in page needs the paid licence. Its organizations don't change round 2: org roles are tenant-wide templates (no per-merchant custom roles, no store scope, no limits) and orgs can't be suspended. Pick it only if per-merchant SSO or a ready-made sign-in page becomes a requirement.
- **OpenAuth (g): the right shape, an abandoned project.** In-process on the app's Postgres, lighter and faster than Better Auth, users stay in our DB. But about half its adapter (95 of 182 LOC) fills gaps: Postgres storage, machine clients, an `/authorize` gate, issuer pinning. The two reviews made 7 security fixes, every one covering something OpenAuth leaves to the app (issuer taken from Host headers, the open redirect #299, a gate bypass via `/%61uthorize`, machine refresh tokens that outlived their client, a two-instance key race, reusable auth codes, account enumeration by timing). Maintainers don't answer security reports. Not for this platform.

## What round 3 taught beyond the question

1. **The identity port swap held a fourth time** (a → b, a → f, c → g): zero module, kernel or migration changes. The port, though, has no delete: secrets of revoked apps and agents stay valid IdP credentials in every stack (the app still rejects them). Add `DeleteClient` to the port.
2. **JWKS caching hole in all Go stacks (a, b, a2, f):** go-oidc only re-fetches keys on an unknown `kid`, so a key deleted at the IdP keeps verifying tokens until restart. Fixed in f (rebuild the key set every 5 min); backport to a/b/a2.
3. **Cached admin tokens must drop on 401** (f: all Management API calls failed for up to 1 h after a key rotation).
4. **IdP writes need idempotency:** under load Logto created users after our 15 s timeout, leaving IdP users with no app row and the email stuck on 422 → 500. Adopt-on-conflict or pass our own id. Same class as round 2's orphan OAuth clients.
5. **Password hashing is a capacity and DoS question.** Login cost differs by ~6× between IdPs; none of the OSS IdPs rate-limit by default (Better Auth's limiter is the exception). Production needs an edge rate limit (and CAPTCHA for public sign-in) whatever the IdP.
6. **The OpenAuth shape is worth keeping without OpenAuth:** a certified protocol library mounted in the app, users and clients in our Postgres. Maintained options: `zitadel/oidc` (Go, OpenID Certified), `node-oidc-provider` (Node, certified), `cloudflare/workers-oauth-provider` (Workers, MCP-oriented). For Go, `zitadel/oidc` in-process would give Go what Better Auth gives TS (one transaction for identity + app data) — candidate stack h.
7. **Test conditions:** cs-ws ran at load 15–43 on 4 CPUs (other workspaces); f and g (and c) passed only with 2–4 workers. Timings in f/g are rough; CPU-per-login numbers come from container counters and hold.

## Backports and follow-ups (not done)

- Go stacks a/b/a2: periodic JWKS refresh; `DeleteClient` on the identity port.
- f: idempotent user create; per-stack generated admin client secret.
- g: none (not pursued).
- cs-ws dev proxy: extend the redirect-rewrite exemption to 8090–8099 (collielab) so f/g run without the 127.0.0.1 workaround.

## Addendum (2026-10-19): stack h, Go + in-process issuer (`zitadel/oidc`) + SpiceDB

Details: `h.md`, `review-h.md`. Stack a with Zitadel replaced by an issuer inside the app, on `zitadel/oidc` v3.51.16 `pkg/op` (OpenID Certified); users, codes, refresh tokens, signing keys and machine clients in the app's Postgres.

- **Suite:** 362/362 after review, also with two app instances on one DB.
- **Owned code:** issuer adapter ~930 LOC + 49 SQL + ~100 wiring, 588 LOC tests (Zitadel adapter 265, Better Auth 113, OpenAuth 182). Replaces a whole IdP server, its sync and its outbox.
- **Transactions:** identity writes join the request's transaction (tx in `ctx`, one executor line, no module changes). A rolled-back request leaves no identity; the IdP outbox and eventual-consistency retries are gone.
- **Ops:** ~80 ms CPU per user create + login at a real argon2id cost (a ~100 ms with dev hash cost, f ~650 ms); ~150 MiB idle; 15 s cold start; key rotation and retirement without restart.
- **The library does the protocol, we own the rules:** of a 20-item security checklist from reviews f/g, the library fully covers 3. Its defaults to override: accepts plain/no PKCE, read-then-delete code redemption (not single-use under parallel requests), access and ID tokens with the same `typ` and audience, open CORS, JWT-bearer grant always on.
- **Review's worst finding (high, fixed):** the library's `/authorize/callback?id=` handed the code to anyone holding the auth request id: an attacker could start a login, send the victim the link and redeem the victim's code with his own PKCE verifier. Plus rate-limit races and a client lockout DoS (fixed). Open: limits act globally behind one proxy address (needs trusted-proxy config and a shared store), 15-min access tokens not revocable.
- **Not in the library:** MFA, passkeys, SAML/SSO federation, resource indicators (RFC 8707), dynamic client registration / CIMD, DPoP.
- **Verdict (builder and reviewer):** the best Go option for login + machine clients, **if** the team owns the auth surface, including reviewing the library's flows as deployed whenever the login step or library version changes (three of four serious findings sat between the library and our code). Pick Zitadel if MFA, passkeys or merchant SSO are near.
