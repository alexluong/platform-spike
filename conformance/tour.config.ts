import { defineConfig } from 'vitest/config'

// `pnpm tour`: one narrated, sequential walk through the spike (tour/tour.tour.ts).
export default defineConfig({
  test: {
    include: ['tour/**/*.tour.ts'],
    globalSetup: ['./src/global-setup.ts'],
    disableConsoleIntercept: true,
    testTimeout: 300_000,
    hookTimeout: 60_000,
  },
})
