// Probes 1 + 2 (TASK-62): instance selection by x-zitadel-instance-host, issuer by x-zitadel-public-host.
//   mise exec -- node bench/zitadel-instances/probe-routing.ts > bench/zitadel-instances/evidence/probe-routing.txt
// Every request goes to the published port with Host = cs-ws.lab.alexluong.com:8099 (the DEFAULT
// instance's domain), so a request that lands on the merchant instance proves the header won.
import { execFileSync } from 'node:child_process'
import { BASE, createInstance, decodeJwt, login, ok, provisionLogin, systemToken, z } from './lib.ts'

const tag = Date.now().toString(36)
const log = (...a: unknown[]) => console.log(...a)
const short = (s: string, n = 160) => (s.length > n ? s.slice(0, n) + '…' : s)
// Host-header tests run curl ON cs-ws against localhost:8099 (the Mac's dev proxy rewrites
// requests that carry a foreign Host header). Args are single-quoted for the remote shell.
const q = (a: string) => `'${a.replace(/'/g, `'\\''`)}'`
function curl(args: string[]): string {
  return execFileSync('ssh', ['cs-ws', ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', ...args].map(q).join(' ')], { encoding: 'utf8' })
}
function curlBody(args: string[]): string {
  return execFileSync('ssh', ['cs-ws', ['curl', '-s', ...args].map(q).join(' ')], { encoding: 'utf8' })
}

log(`# probe-routing ${new Date().toISOString()} base=${BASE}`)
const A = await createInstance(`pa-${tag}`, `pa-${tag}.idp.internal`)
const B = await createInstance(`pb-${tag}`, `pb-${tag}.idp.internal`)
log(`instances: A=${A.id} (${A.domain}, create ${Math.round(A.createMs)}ms)  B=${B.id} (${B.domain}, create ${Math.round(B.createMs)}ms)`)
const ca = await provisionLogin(A)
const cb = await provisionLogin(B)
log(`provisioned login (project, app, user, IAM_LOGIN_CLIENT) via header only: A ${Math.round(ca.ms)}ms, B ${Math.round(cb.ms)}ms`)

log('\n## 1. Does every API honour x-zitadel-instance-host?')
const def = await z('/.well-known/openid-configuration')
const da = await z('/.well-known/openid-configuration', { instance: A.domain })
log(`discovery, no header (Host=default): issuer=${def.json.issuer}`)
log(`discovery, header A:                 ${da.status} issuer=${da.json.issuer} jwks_uri=${da.json.jwks_uri}`)
const ka = await z('/oauth/v2/keys', { instance: A.domain })
const kb = await z('/oauth/v2/keys', { instance: B.domain })
const kd = await z('/oauth/v2/keys')
const kids = (r: any) => (r.json?.keys ?? []).map((k: any) => k.kid).join(',')
log(`JWKS header A: ${ka.status} kids=[${kids(ka)}]  header B: kids=[${kids(kb)}]  default: kids=[${kids(kd)}]`)

const ma = await z('/management/v1/orgs/me', { instance: A.domain, token: A.pat })
log(`Management v1 GET /management/v1/orgs/me (A PAT, header A): ${ma.status} org=${ma.json?.org?.id} name=${ma.json?.org?.name} (A org ${ca.orgId})`)
const adm = await z('/admin/v1/orgs/_search', { instance: A.domain, token: A.pat, json: {} })
log(`Admin v1 POST /admin/v1/orgs/_search (header A): ${adm.status} orgs=${adm.json?.result?.map((o: any) => o.name).join(',')}`)
const ua = await z(`/v2/users/${ca.userId}`, { instance: A.domain, token: A.pat })
log(`User v2 GET /v2/users/{id} (header A): ${ua.status} user=${ua.json?.user?.username}`)
const ucon = await z('/zitadel.user.v2.UserService/GetUserByID', { instance: A.domain, token: A.pat, json: { userId: ca.userId } })
log(`User v2 over Connect POST /zitadel.user.v2.UserService/GetUserByID (header A): ${ucon.status} user=${ucon.json?.user?.username}`)
const la = await login(A, ca)
const at = decodeJwt(la.accessToken)
log(`OIDC authorize → Session v2 → OIDC v2 finalize → token (header A): ok, iss=${at.iss} sub=${at.sub} ms=${JSON.stringify(Object.fromEntries(Object.entries(la.ms).map(([k, v]) => [k, Math.round(v)])))}`)
const ui = await z('/oidc/v1/userinfo', { instance: A.domain, token: la.accessToken })
log(`userinfo (header A, A token): ${ui.status} sub=${ui.json?.sub} email=${ui.json?.email}`)
const uiB = await z('/oidc/v1/userinfo', { instance: B.domain, token: la.accessToken })
log(`userinfo (header B, A token): ${uiB.status} ${short(uiB.text)}`)
const mB = await z('/management/v1/orgs/me', { instance: B.domain, token: A.pat })
log(`Management (header B, A PAT): ${mB.status} ${short(mB.text)}`)
const mD = await z('/management/v1/orgs/me', { token: A.pat })
log(`Management (no header = default instance, A PAT): ${mD.status} ${short(mD.text)}`)
const sysB = await z('/system/v1/instances/_search', { instance: B.domain, token: systemToken(), json: { queries: [{ idQuery: { id: A.id } }] } })
log(`System API with header B (aud = default issuer): ${sysB.status} ${short(sysB.text, 100)}`)

const env = await z('/ui/console/assets/environment.json', { instance: A.domain })
log(`Console environment.json (header A): ${env.status} ${short(env.text, 200)}`)
const lv1 = await z('/ui/login/login', { instance: A.domain })
log(`Login v1 /ui/login/login (header A): ${lv1.status} location=${lv1.headers.get('location')}`)

log('\n### Host header vs instance header (curl, Host set explicitly)')
const u = 'http://localhost:8099/.well-known/openid-configuration'
log(`Host=${A.domain}, no header:                 ${curlBody(['-H', `Host: ${A.domain}`, u]).match(/"issuer":"[^"]+"/)?.[0]}`)
log(`Host=unknown.example, header A:              ${curlBody(['-H', 'Host: unknown.example', '-H', `x-zitadel-instance-host: ${A.domain}`, u]).match(/"issuer":"[^"]+"/)?.[0]}`)
log(`Host=${A.domain}, header B (header wins?):   ${curlBody(['-H', `Host: ${A.domain}`, '-H', `x-zitadel-instance-host: ${B.domain}`, u]).match(/"issuer":"[^"]+"/)?.[0]}`)
log(`Host=default, header unknown (fallback?):    HTTP ${curl(['-H', 'x-zitadel-instance-host: nope.idp.internal', u])}`)
log(`header A with :8099 port:                    ${curlBody(['-H', `x-zitadel-instance-host: ${A.domain}:8099`, u]).match(/"issuer":"[^"]+"/)?.[0]}`)
log(`header A upper-case:                         ${curlBody(['-H', `x-zitadel-instance-host: ${A.domain.toUpperCase()}`, u]).match(/"issuer":"[^"]+"|Instance not found/)?.[0]}`)
log(`generated domain (${A.name}-*.<ExternalDomain>) also selects A: ${(await z('/system/v1/instances/' + A.id + '/domains/_search', { token: systemToken(), json: {} })).json?.result?.map((d: any) => `${d.domain}${d.primary ? '(primary)' : ''}${d.generated ? '(generated)' : ''}`).join(', ')}`)

log('\n## 2. x-zitadel-public-host')
const disc = async (pub: string) => {
  const r = await z('/.well-known/openid-configuration', { instance: A.domain, pub })
  return r.status === 200 ? `issuer=${r.json.issuer} authz=${r.json.authorization_endpoint}` : `${r.status} ${short(r.text)}`
}
log(`pub=shop-a-${tag}.brand.test (NOT registered anywhere): ${await disc(`shop-a-${tag}.brand.test`)}`)
try {
  const l = await login(A, ca, { pub: `shop-a-${tag}.brand.test` })
  log(`login with pub=shop-a-${tag}.brand.test: ok, access iss=${decodeJwt(l.accessToken).iss} id_token iss=${l.idToken ? decodeJwt(l.idToken).iss : '-'}`)
} catch (e: any) {
  log(`login with pub=shop-a-${tag}.brand.test: FAIL ${short(e.message, 300)}`)
}
log(`pub=shop-a-${tag}.brand.test:8443 (with port): ${await disc(`shop-a-${tag}.brand.test:8443`)}`)
log(`pub=${B.domain} (another instance's domain): ${await disc(B.domain)}`)

// Register public hosts: as instance custom domain (System API) and as trusted domain (Admin API).
const addDom = await z(`/system/v1/instances/${A.id}/domains`, { token: systemToken(), json: { domain: `shop-a2-${tag}.brand.test` } })
log(`System API add instance domain shop-a2-${tag}.brand.test to A: ${addDom.status} ${short(addDom.text, 120)}`)
const addTrusted = await z('/admin/v1/trusted_domains', { instance: A.domain, token: A.pat, json: { domain: `shop-a3-${tag}.brand.test` } })
log(`Admin API add trusted domain shop-a3-${tag}.brand.test to A: ${addTrusted.status} ${short(addTrusted.text, 120)}`)
await new Promise((r) => setTimeout(r, 2000)) // projections
log(`pub=shop-a2-${tag}.brand.test (instance domain, not trusted): ${await disc(`shop-a2-${tag}.brand.test`)}`)
log(`pub=shop-a3-${tag}.brand.test (trusted domain):  ${await disc(`shop-a3-${tag}.brand.test`)}`)
log(`Host=shop-a2-${tag}.brand.test, no headers → selects A by Host: ${curlBody(['-H', `Host: shop-a2-${tag}.brand.test`, u]).match(/"issuer":"[^"]+"|Instance not found/)?.[0]}`)
log(`Host=shop-a3-${tag}.brand.test (trusted only), no headers:     ${curlBody(['-H', `Host: shop-a3-${tag}.brand.test`, u]).match(/"issuer":"[^"]+"|Instance not found/)?.[0]}`)

// One instance, several public hosts: two trusted domains, issue under each, compare iss and keys.
await z('/admin/v1/trusted_domains', { instance: A.domain, token: A.pat, json: { domain: `shop-a4-${tag}.brand.test` } })
await new Promise((r) => setTimeout(r, 1000))
const l1 = await login(A, ca, { pub: `shop-a4-${tag}.brand.test` })
const l2 = await login(A, ca, { pub: `shop-a3-${tag}.brand.test` })
const h1 = JSON.parse(Buffer.from(l1.accessToken.split('.')[0], 'base64url').toString())
const h2 = JSON.parse(Buffer.from(l2.accessToken.split('.')[0], 'base64url').toString())
log(`two pubs, one instance: iss1=${decodeJwt(l1.accessToken).iss} kid1=${h1.kid}  iss2=${decodeJwt(l2.accessToken).iss} kid2=${h2.kid}`)
const k2 = await z('/oauth/v2/keys', { instance: A.domain, pub: `shop-a4-${tag}.brand.test` })
log(`JWKS via pub shop-a4: kids=[${kids(k2)}] (same as header-only A: ${kids(k2) === kids(ka)})`)
// A token issued under pub X, presented to userinfo under pub Y.
const cross = await z('/oidc/v1/userinfo', { instance: A.domain, pub: `shop-a3-${tag}.brand.test`, token: l1.accessToken })
log(`userinfo under pub shop-a3 with token iss=shop-a4: ${cross.status} ${short(cross.text, 120)}`)
const intro = await z('/oidc/v1/userinfo', { instance: A.domain, token: l1.accessToken })
log(`userinfo with no pub (issuer = instance domain) with token iss=shop-a4: ${intro.status}`)
// Mixed flow: authorize under pub X, token exchange under pub Y.
log(`authorize location (pub shop-a4): ${(await z('/oauth/v2/authorize?client_id=' + ca.clientId + '&redirect_uri=' + encodeURIComponent('http://localhost:3999/callback') + '&response_type=code&scope=openid&code_challenge=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq&code_challenge_method=S256', { instance: A.domain, pub: `shop-a4-${tag}.brand.test` })).headers.get('location')}`)
log('\ndone')
