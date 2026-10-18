// Environment for the suite. See README.md.
export const stackNames = ['a', 'b', 'c', 'd', 'e', 'a2', 'f'] as const
export type StackName = (typeof stackNames)[number]

function stackFromEnv(): StackName {
  const s = (process.env.STACK ?? '').trim()
  if ((stackNames as readonly string[]).includes(s)) return s as StackName
  throw new Error(`STACK must be one of ${stackNames.join('|')} (got ${JSON.stringify(s)}). Example: STACK=a HOST=cs-ws pnpm test`)
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
