// Runs once before any test file. Fails the whole run fast, with one clear message, when the
// driver is still a stub or the stack is not reachable, instead of every test timing out.
import { describeFetchError } from './client'
import { DriverNotImplementedError } from './driver'
import { env } from './env'
import { getDriver } from './stack'

export default async function setup(): Promise<void> {
  const stack = env.stack // throws a clear error when STACK is missing
  if (process.env.SKIP_PREFLIGHT === '1') return
  const driver = getDriver()
  const problems: string[] = []

  // 1. Stub driver? (A real driver will fail this bogus login some other way; that is ignored.)
  let timer: NodeJS.Timeout | undefined
  try {
    await Promise.race([
      driver.loginUser('conformance-probe@example.com', 'not-a-real-password'),
      new Promise((r) => (timer = setTimeout(r, 5_000))),
    ])
  } catch (e) {
    if (e instanceof DriverNotImplementedError) problems.push(e.message)
  } finally {
    clearTimeout(timer)
  }

  // 2. Stack healthy?
  const url = `${driver.baseUrl.replace(/\/$/, '')}/healthz`
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(5_000) })
    if (r.status !== 200) problems.push(`GET ${url} → ${r.status} (stack ${stack} not healthy yet)`)
  } catch (e) {
    problems.push(`GET ${url}: ${describeFetchError(e)}`)
  }

  if (problems.length > 0) {
    throw new Error(`conformance preflight failed for stack ${stack}:\n  - ${problems.join('\n  - ')}`)
  }
}
