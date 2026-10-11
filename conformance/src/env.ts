// Environment for the suite. See README.md.
export type StackName = 'a' | 'b' | 'c'

function stackFromEnv(): StackName {
  const s = (process.env.STACK ?? '').trim()
  if (s === 'a' || s === 'b' || s === 'c') return s
  throw new Error(`STACK must be one of a|b|c (got ${JSON.stringify(s)}). Example: STACK=a HOST=cs-ws pnpm test`)
}

export const env = {
  get stack(): StackName {
    return stackFromEnv()
  },
  host: process.env.HOST ?? 'localhost',
  testSecret: process.env.TEST_SECRET ?? 'test-secret',
  /** Per-request timeout so a dead server fails fast instead of hanging. */
  requestTimeoutMs: Number(process.env.REQUEST_TIMEOUT_MS ?? 15_000),
  /** Skip tests that need to wait a minute or more (break-glass expiry). */
  skipSlow: process.env.SKIP_SLOW === '1',
}
