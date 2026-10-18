// Review probes for stack i (results/review-i.md):
//   STACK=i HOST=cs-ws.lab.alexluong.com [I_REVIEW=1] pnpm vitest run --config review-i/vitest.config.ts
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: { include: ['review-i/*.test.ts'], testTimeout: 300_000, hookTimeout: 120_000, fileParallelism: false },
})
