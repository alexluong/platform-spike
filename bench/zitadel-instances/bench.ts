// Scale bench (TASK-62): many instances on one Zitadel deployment. Rerunnable; state in out/.
//   mise exec -- node bench/zitadel-instances/bench.ts grow --to 1000 [--conc 4] [--every 10]
//   mise exec -- node bench/zitadel-instances/bench.ts measure --label 1k-default [--logins 50] [--jwks 100]
//   mise exec -- node bench/zitadel-instances/bench.ts restart --label 1k-default   (restart + catch-up timing)
// grow: creates instances (System API) up to --to; every --every-th also gets a login setup (project,
//   PKCE app, user). Records create latency per instance in out/state.jsonl.
// measure: DB size and rows, Zitadel/Postgres CPU+RSS idle, login latency on random login-ready
//   instances (authorize → session → finalize → token), JWKS + discovery latency on random instances,
//   docker host load. Appends to out/measure.jsonl.
// Env knobs for the Zitadel side are applied with ./up.sh (ZBENCH_HANDLEACTIVEINSTANCES, ...).
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createInstance, here, host, login, pct, pool, provisionLogin, psql, round, sleep, z, type Instance, type LoginCfg } from './lib.ts'

const OUT = join(here, 'out')
mkdirSync(OUT, { recursive: true })
const STATE = join(OUT, 'state.jsonl')
const MEASURE = join(OUT, 'measure.jsonl')
const GROW = join(OUT, 'grow.jsonl')

type Rec = Instance & { login?: LoginCfg & { ms: number } }
const args = process.argv.slice(2)
const cmd = args[0]
const flag = (n: string, d?: string) => {
  const i = args.indexOf(`--${n}`)
  return i >= 0 ? args[i + 1] : d
}
const load = (): Rec[] => (existsSync(STATE) ? readFileSync(STATE, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [])
const pick = <T>(xs: T[]) => xs[Math.floor(Math.random() * xs.length)]
const stat = (xs: number[]) => ({ n: xs.length, p50: round(pct(xs, 50)), p95: round(pct(xs, 95)), max: round(Math.max(...xs)) })
const hostLoad = () => host('cat /proc/loadavg').split(' ').slice(0, 3).join(' ')
const pcBench = () => Number(host('docker ps --format "{{.Names}}" | grep -c "^pc-bench" || true'))

async function grow() {
  const to = Number(flag('to', '1000'))
  const conc = Number(flag('conc', '4'))
  const every = Number(flag('every', '10'))
  const have = load()
  const todo = Array.from({ length: Math.max(0, to - have.length) }, (_, k) => have.length + k)
  console.log(`grow: have ${have.length}, creating ${todo.length} (conc ${conc}, login setup every ${every}); load ${hostLoad()}`)
  const t0 = performance.now()
  const create: number[] = []
  const prov: number[] = []
  let errors = 0
  let done = 0
  await pool(todo, conc, async (n) => {
    const name = `zb-${n}`
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        // Domains are unique; a retried create after a timeout may have succeeded: suffix the attempt.
        const inst = await createInstance(name, `zb-${n}${attempt ? '-r' + attempt : ''}.idp.internal`)
        const rec: Rec = { ...inst }
        create.push(inst.createMs)
        if (n % every === 0) {
          rec.login = await provisionLogin(inst)
          prov.push(rec.login.ms)
        }
        appendFileSync(STATE, JSON.stringify(rec) + '\n')
        break
      } catch (e: any) {
        errors++
        console.log(`  ${name} attempt ${attempt}: ${String(e.message).slice(0, 200)}`)
        await sleep(2000)
      }
    }
    if (++done % 100 === 0) {
      const last = create.slice(-100)
      console.log(`  ${have.length + done}: last100 create p50 ${round(pct(last, 50))}ms p95 ${round(pct(last, 95))}ms; ${round((performance.now() - t0) / 1000)}s; load ${hostLoad()}`)
    }
  })
  const res = { at: new Date().toISOString(), from: have.length, to: load().length, conc, wallS: round((performance.now() - t0) / 1000), createMs: stat(create), provisionLoginMs: stat(prov), errors, load: hostLoad(), pcBench: pcBench() }
  appendFileSync(GROW, JSON.stringify(res) + '\n')
  console.log(JSON.stringify(res))
}

function dockerStats(samples = 6, everyS = 5) {
  const cpu: Record<string, number[]> = {}
  const mem: Record<string, string> = {}
  for (let i = 0; i < samples; i++) {
    const out = host('docker stats --no-stream --format "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}" ps-zbench-zb-zitadel-1 ps-zbench-zb-postgres-1')
    for (const l of out.split('\n')) {
      const [n, c, m] = l.split('|')
      ;(cpu[n] ??= []).push(parseFloat(c))
      mem[n] = m.split(' / ')[0]
    }
    if (i < samples - 1) host(`sleep ${everyS}`)
  }
  const avg = (xs: number[]) => round(xs.reduce((a, b) => a + b, 0) / xs.length)
  return {
    zitadelCpuPct: avg(cpu['ps-zbench-zb-zitadel-1'] ?? []),
    zitadelMem: mem['ps-zbench-zb-zitadel-1'],
    postgresCpuPct: avg(cpu['ps-zbench-zb-postgres-1'] ?? []),
    postgresMem: mem['ps-zbench-zb-postgres-1'],
  }
}

function dbStats() {
  const q = psql(`
SELECT pg_size_pretty(pg_database_size('zitadel')), pg_database_size('zitadel');
SELECT count(*) FROM eventstore.events2;
SELECT count(DISTINCT instance_id) FROM eventstore.events2;
SELECT count(*) FROM eventstore.fields;
SELECT count(*) FROM projections.current_states;
SELECT string_agg(r, ' ') FROM (SELECT n.nspname||'.'||c.relname||'='||pg_size_pretty(pg_total_relation_size(c.oid)) r
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname IN ('eventstore','projections','system','auth','adminapi','cache')
  ORDER BY pg_total_relation_size(c.oid) DESC LIMIT 6) t;
SELECT count(*) FROM pg_stat_activity WHERE datname='zitadel';
`)
  const [size, bytes] = q.split('\n')[0].split('|')
  const [, events, instances, fields, currentStates, top, conns] = q.split('\n')
  return { dbSize: size, dbBytes: Number(bytes), events: Number(events), eventInstances: Number(instances), fields: Number(fields), currentStates: Number(currentStates), topTables: top, pgConns: Number(conns) }
}

async function latencies() {
  const recs = load()
  const ready = recs.filter((r) => r.login)
  const nLogin = Number(flag('logins', '50'))
  const nJwks = Number(flag('jwks', '100'))
  const conc = Number(flag('lconc', '1'))
  const parts: Record<string, number[]> = { authorize: [], session: [], finalize: [], token: [], total: [] }
  let loginErr = 0
  await pool(Array.from({ length: nLogin }), conc, async () => {
    const r = pick(ready)
    try {
      const l = await login(r, r.login!)
      for (const k of Object.keys(parts)) parts[k].push((l.ms as any)[k])
    } catch (e: any) {
      loginErr++
      if (loginErr < 4) console.log(`  login error ${r.domain}: ${String(e.message).slice(0, 200)}`)
    }
  })
  const jwks: number[] = []
  const disc: number[] = []
  let jErr = 0
  for (let i = 0; i < nJwks; i++) {
    const r = pick(recs)
    const k = await z('/oauth/v2/keys', { instance: r.domain })
    if (k.status === 200) jwks.push(k.ms)
    else jErr++
    const d = await z('/.well-known/openid-configuration', { instance: pick(recs).domain })
    if (d.status === 200) disc.push(d.ms)
    else jErr++
  }
  // Baseline RTT: an unknown instance 404 (no DB work beyond the domain lookup).
  const rtt: number[] = []
  for (let i = 0; i < 20; i++) rtt.push((await z('/debug/healthz')).ms)
  return {
    loginReady: ready.length,
    loginMs: Object.fromEntries(Object.entries(parts).map(([k, v]) => [k, stat(v)])),
    loginErr,
    jwksMs: stat(jwks),
    discoveryMs: stat(disc),
    healthzMs: stat(rtt),
    jwksErr: jErr,
  }
}

async function measure() {
  const label = flag('label', 'unlabelled')
  const recs = load()
  const before = { load: hostLoad(), pcBench: pcBench() }
  console.log(`measure ${label}: ${recs.length} instances; load ${before.load}; pc-bench containers ${before.pcBench}`)
  const env = host('docker inspect ps-zbench-zb-zitadel-1 --format "{{range .Config.Env}}{{println .}}{{end}}" | grep -E "HANDLEACTIVE|MAXACTIVE|CACHES_CONNECTORS_MEMORY|INSTANCE_CONNECTOR|MAXOPENCONNS" | tr "\\n" " "')
  const idle = dockerStats(Number(flag('samples', '6')))
  const db = dbStats()
  const lat = await latencies()
  const res = { label, at: new Date().toISOString(), instances: recs.length, zitadelEnv: env, hostLoadBefore: before.load, hostLoadAfter: hostLoad(), pcBench: before.pcBench, idle, db, ...lat }
  appendFileSync(MEASURE, JSON.stringify(res) + '\n')
  console.log(JSON.stringify(res, null, 1))
}

/** Restart Zitadel; time to ready, to first login, and until its CPU settles (projection catch-up). */
async function restart() {
  const label = flag('label', 'unlabelled')
  const recs = load().filter((r) => r.login)
  const t0 = performance.now()
  host('docker restart ps-zbench-zb-zitadel-1 >/dev/null')
  const restartS = round((performance.now() - t0) / 1000)
  let readyS = NaN
  for (;;) {
    try {
      const r = await z('/debug/ready')
      if (r.status === 200) {
        readyS = round((performance.now() - t0) / 1000)
        break
      }
    } catch {}
    await sleep(500)
  }
  let firstLoginS = NaN
  for (let i = 0; i < 240; i++) {
    try {
      const r = pick(recs)
      await login(r, r.login!)
      firstLoginS = round((performance.now() - t0) / 1000)
      break
    } catch {
      await sleep(500)
    }
  }
  // CPU decay: sample every 5s until 3 consecutive samples under the threshold (or 15 min).
  const thr = Number(flag('cpu', '15'))
  const trace: number[] = []
  let settledS = NaN
  let under = 0
  for (let i = 0; i < 180; i++) {
    const c = parseFloat(host('docker stats --no-stream --format "{{.CPUPerc}}" ps-zbench-zb-zitadel-1'))
    trace.push(round(c))
    under = c < thr ? under + 1 : 0
    if (under >= 3) {
      settledS = round((performance.now() - t0) / 1000)
      break
    }
    host('sleep 5')
  }
  const mem = host('docker stats --no-stream --format "{{.MemUsage}}" ps-zbench-zb-zitadel-1').split(' / ')[0]
  const res = { label, at: new Date().toISOString(), instances: load().length, restartS, readyS, firstLoginS, cpuSettledS: settledS, cpuThresholdPct: thr, cpuTrace: trace, memAfter: mem, load: hostLoad(), pcBench: pcBench() }
  appendFileSync(join(OUT, 'restart.jsonl'), JSON.stringify(res) + '\n')
  console.log(JSON.stringify(res))
}

if (cmd === 'grow') await grow()
else if (cmd === 'measure') await measure()
else if (cmd === 'restart') await restart()
else {
  console.log('usage: bench.ts grow|measure|restart [--to N] [--label L]')
  process.exit(1)
}
