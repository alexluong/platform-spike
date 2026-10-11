// Small typed HTTP client + assertions. Every assertion message names the request and the actor,
// so a failing test reads like "POST /api/orders/o1/refund as staff: expected 403, got 200 {...}".
import { env } from './env'

export interface Res<T = any> {
  status: number
  body: T
  text: string
  method: string
  path: string
  actor: string
}

type Headers = Record<string, string>

export class Api {
  constructor(
    readonly baseUrl: string,
    readonly token?: string,
    readonly actor: string = 'anonymous',
  ) {}

  /** Same server, other credentials. */
  as(token: string, actor = 'token'): Api {
    return new Api(this.baseUrl, token, actor)
  }

  anon(): Api {
    return new Api(this.baseUrl, undefined, 'anonymous')
  }

  async request<T = any>(method: string, path: string, body?: unknown, headers: Headers = {}): Promise<Res<T>> {
    const url = this.baseUrl.replace(/\/$/, '') + path
    const h: Headers = { accept: 'application/json', ...headers }
    if (body !== undefined) h['content-type'] = 'application/json'
    if (this.token !== undefined && h.authorization === undefined) h.authorization = `Bearer ${this.token}`
    let r: Response
    try {
      r = await fetch(url, {
        method,
        headers: h,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(env.requestTimeoutMs),
      })
    } catch (e) {
      throw new Error(`${method} ${url} as ${this.actor}: ${describeFetchError(e)}`)
    }
    const text = await r.text()
    let parsed: any = undefined
    if (text.length > 0) {
      try {
        parsed = JSON.parse(text)
      } catch {
        parsed = undefined
      }
    }
    return { status: r.status, body: parsed as T, text, method, path, actor: this.actor }
  }

  get<T = any>(path: string, headers?: Headers) {
    return this.request<T>('GET', path, undefined, headers)
  }
  post<T = any>(path: string, body: unknown = {}, headers?: Headers) {
    return this.request<T>('POST', path, body, headers)
  }
  patch<T = any>(path: string, body: unknown, headers?: Headers) {
    return this.request<T>('PATCH', path, body, headers)
  }
  delete<T = any>(path: string, headers?: Headers) {
    return this.request<T>('DELETE', path, undefined, headers)
  }
}

export function describeFetchError(e: unknown): string {
  const err = e as { name?: string; message?: string; cause?: { code?: string; message?: string } }
  if (err?.name === 'TimeoutError' || err?.name === 'AbortError') return `timed out after ${env.requestTimeoutMs}ms`
  const code = err?.cause?.code
  if (code === 'ECONNREFUSED') return 'connection refused (is the stack running? check STACK/HOST)'
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return `host not found (${err.cause?.message ?? code}); check HOST`
  return `${err?.message ?? String(e)}${err?.cause?.message ? ` (${err.cause.message})` : ''}`
}

// ---------- assertions ----------

function show(res: Res): string {
  const t = res.text.length > 400 ? res.text.slice(0, 400) + '…' : res.text
  return `${res.method} ${res.path} as ${res.actor}`.concat(t ? ` → ${res.status} ${t}` : ` → ${res.status}`)
}

export class ConformanceError extends Error {
  constructor(msg: string) {
    super(msg)
    this.name = 'ConformanceError'
  }
}

function fail(res: Res, expectation: string): never {
  throw new ConformanceError(`${expectation}; got: ${show(res)}`)
}

export function errorCode(res: Res): string | undefined {
  const c = res.body?.error?.code
  return typeof c === 'string' ? c : undefined
}

/** Assert the status is one of `statuses`. Returns the body. */
export function expectStatus<T>(res: Res<T>, ...statuses: number[]): T {
  if (!statuses.includes(res.status)) fail(res, `expected status ${statuses.join('|')}`)
  return res.body
}

/** Assert a 2xx (or exactly `status`) and return the body. */
export function ok<T>(res: Res<T>, status?: number): T {
  if (status !== undefined) return expectStatus(res, status)
  if (res.status < 200 || res.status > 299) fail(res, 'expected 2xx')
  return res.body
}

/** Assert an error response with the SPEC §9 shape `{error: {code}}`. `code` may list alternatives. */
export function expectError(res: Res, status: number | number[], code?: string | string[]): void {
  const statuses = Array.isArray(status) ? status : [status]
  if (!statuses.includes(res.status)) fail(res, `expected status ${statuses.join('|')}${code ? ` with code ${[code].flat().join('|')}` : ''}`)
  const got = errorCode(res)
  if (got === undefined) fail(res, `expected an error body {"error":{"code":...}}`)
  if (code !== undefined) {
    const codes = Array.isArray(code) ? code : [code]
    if (!codes.includes(got)) fail(res, `expected error code ${codes.join('|')}`)
  }
}

export interface DeniedOpts {
  /** Resource belongs to another merchant: 403 or 404 accepted (SPEC §9). */
  crossTenant?: boolean
  /** Require a specific error code (e.g. `escalation`, `merchant_suspended`). */
  code?: string | string[]
}

/** Authorization denial: 403 (any code unless `code` is given), or 403|404 across tenants. Never 2xx, never 409. */
export function expectDenied(res: Res, opts: DeniedOpts = {}): void {
  expectError(res, opts.crossTenant ? [403, 404] : [403], opts.code)
}

export function expectUnauthenticated(res: Res): void {
  expectError(res, 401, 'unauthenticated')
}

/** State-rule violation: 409, optionally with a code. */
export function expectConflict(res: Res, code?: string | string[]): void {
  expectError(res, 409, code)
}

export function sortedSet(xs: readonly string[]): string[] {
  return [...new Set(xs)].sort()
}
