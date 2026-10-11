import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    globalSetup: ['./src/global-setup.ts'],
    // Files run in parallel; tests inside a file run concurrently too (each builds its own world).
    fileParallelism: true,
    maxWorkers: process.env.MAX_WORKERS ? Number(process.env.MAX_WORKERS) : undefined,
    sequence: { concurrent: true },
    maxConcurrency: Number(process.env.MAX_CONCURRENCY ?? 4),
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
})
