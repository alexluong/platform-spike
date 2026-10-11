# platform-spike

A mini Shopify (merchants with custom roles, customers, platform staff, apps, AI agents; orders, payments, delivery), built on three identity + authorization stacks and checked by one black-box test suite.

| stack | app | identity | authz | port |
|---|---|---|---|---|
| `a` | Go | Zitadel | SpiceDB | 8081 |
| `b` | Go (same code, other adapters) | Ory Kratos + Hydra | OpenFGA | 8082 |
| `c` | TypeScript (Hono) | Better Auth | Cerbos | 8083 |

- Spec: [`spec/SPEC.md`](spec/SPEC.md)
- Test suite: `conformance/` (362 tests; all three stacks pass)
- Per-stack results: `results/<stack>.md`

## Run

Docker runs on a remote host; no source bind mounts.

```sh
mise install
export DOCKER_HOST=ssh://cs-ws
docker compose -p ps-a --profile a up -d --build      # or b, c (-p ps-b / ps-c)
cd conformance && pnpm install && STACK=a HOST=cs-ws.lab.alexluong.com pnpm test
```

- `cs-ws` is an ssh alias: fine for `DOCKER_HOST`, but it doesn't resolve as a hostname on the Mac. `HOST` must be `cs-ws.lab.alexluong.com`.
- Zitadel (stack `a`) issues tokens for the exact host clients use (`STACK_A_HOST`, default `cs-ws.lab.alexluong.com`). Changing it needs `down -v`.
- `SKIP_SLOW=1` skips the 65 s break-glass expiry test.

## Layout

```
spec/          the spec
conformance/   vitest black-box suite + one login driver per stack
go/            Go app (stacks a and b)
ts/            TypeScript app (stack c)
stacks/<s>/    compose file, IdP/engine config and bootstrap for each stack
results/       findings per stack, and the comparison
```
