// Stack i measurements (results/i.md §16.7), not conformance tests:
//   STACK=i HOST=cs-ws.lab.alexluong.com BENCH=provision N=100 C=1 pnpm vitest run --config bench-i/vitest.config.ts
//   BENCH=login K=20 ...
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: { include: ['bench-i/*.bench-test.ts'], testTimeout: 3_600_000, hookTimeout: 600_000, fileParallelism: false },
})
