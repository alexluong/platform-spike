// Probe 5 (TASK-62): federation between instances on ONE deployment ("Sign in with Shop").
// Instance S (Shop/platform, domain shop.idp.internal = a network alias of the Zitadel container)
// is a generic OIDC IdP in tenant instances B and C. A Shop user logs in headless into B, gets
// auto-created + linked, logs in again (link found), then does the same at C (same S user).
//   mise exec -- node bench/zitadel-instances/probe-federation.ts > bench/zitadel-instances/evidence/probe-federation.txt
// Needs ZBENCH_DENYLIST without 192.168.0.0/16 (see compose.yaml); run once without to see the failure.
import { BASE, createInstance, decodeJwt, eventually, login, ok, pkce, PASSWORD, provisionLogin, REDIRECT, systemToken, z, type Instance, type LoginCfg } from './lib.ts'

const tag = Date.now().toString(36)
const log = (...a: unknown[]) => console.log(...a)
const short = (s: string, n = 260) => (s.length > n ? s.slice(0, n) + '…' : s)
const SHOP_HOST = 'shop.idp.internal'
// Port 8080 = the container port the other instances' servers dial; the driver sends the same
// value as instance header so the issuer is identical on both paths.
const SHOP_ISSUER_HOST = `${SHOP_HOST}:8080`
const LT = () => systemToken('zlogin')

log(`# probe-federation ${new Date().toISOString()}`)

// S may exist from an earlier run (instance domains are unique): remove it first.
const prev = await z('/system/v1/instances/_search', { token: systemToken(), json: { queries: [{ domainQuery: { domains: [SHOP_HOST] } }] } })
for (const i of prev.json?.result ?? []) {
  const d = await z(`/system/v1/instances/${i.id}`, { method: 'DELETE', token: systemToken() })
  log(`removed earlier shop instance ${i.id}: ${d.status}`)
}
await new Promise((r) => setTimeout(r, 2000))
const S = await createInstance(`shop-${tag}`, SHOP_HOST)
const Sx: Instance = { ...S, domain: SHOP_ISSUER_HOST }
const sCfg = await provisionLogin(Sx, 'buyer@shop.test')
log(`S (shop) instance ${S.id}; Shop user ${sCfg.userId} buyer@shop.test`)
const sDisc = await z('/.well-known/openid-configuration', { instance: SHOP_ISSUER_HOST })
log(`S issuer seen by the driver: ${sDisc.json.issuer}`)

async function tenant(name: string) {
  const T = await createInstance(`${name}-${tag}`, `${name}-${tag}.idp.internal`)
  const cfg = await provisionLogin(T, `staff@${name}.test`)
  const o = { instance: T.domain, token: T.pat }
  const cust = await ok('customers org', z('/v2/organizations', { ...o, json: { name: 'customers' } }))
  return { T, cfg, o, customersOrg: cust.json.organizationId ?? cust.json.id }
}
const B = await tenant('fb')
const C = await tenant('fc')
log(`B ${B.T.id} (${B.T.domain}), C ${C.T.id} (${C.T.domain})`)

// S: one confidential web app whose redirect URIs are every tenant's /idps/callback.
const sp = await ok('S project', z('/management/v1/projects', { instance: SHOP_ISSUER_HOST, token: S.pat, json: { name: 'shop-federation' } }))
const sApp = await ok(
  'S app',
  z(`/management/v1/projects/${sp.json.id}/apps/oidc`, {
    instance: SHOP_ISSUER_HOST,
    token: S.pat,
    json: {
      name: 'tenants',
      redirectUris: [`http://${B.T.domain}/idps/callback`, `http://${C.T.domain}/idps/callback`],
      responseTypes: ['OIDC_RESPONSE_TYPE_CODE'],
      grantTypes: ['OIDC_GRANT_TYPE_AUTHORIZATION_CODE'],
      appType: 'OIDC_APP_TYPE_WEB',
      authMethodType: 'OIDC_AUTH_METHOD_TYPE_BASIC',
      devMode: true,
      version: 'OIDC_VERSION_1_0',
    },
  }),
)
log(`S app clientId=${sApp.json.clientId}`)

async function addIdp(t: typeof B) {
  const r = await ok(
    'generic oidc idp',
    z('/admin/v1/idps/generic_oidc', {
      ...t.o,
      json: {
        name: 'Shop',
        issuer: `http://${SHOP_ISSUER_HOST}`,
        clientId: sApp.json.clientId,
        clientSecret: sApp.json.clientSecret,
        scopes: ['openid', 'profile', 'email'],
        providerOptions: { isLinkingAllowed: true, isCreationAllowed: true, isAutoCreation: true, isAutoUpdate: true, autoLinking: 'AUTO_LINKING_OPTION_UNSPECIFIED' },
        // false = map from userinfo (Zitadel's ID token carries no profile claims unless the app asserts them).
        isIdTokenMapping: false,
      },
    }),
  )
  return r.json.id as string
}
const bIdp = await addIdp(B)
const cIdp = await addIdp(C)
log(`instance-level generic OIDC IdP "Shop" in B (${bIdp}) and C (${cIdp}), issuer http://${SHOP_ISSUER_HOST}, autoLinking off`)

/** Full "Sign in with Shop" at tenant t, headless. Returns the tenant token's sub and what happened. */
async function shopLogin(t: typeof B, idpId: string) {
  const T = t.T
  // 1. Tenant authorize → auth request id at T.
  const { verifier, challenge, state } = pkce()
  const q = new URLSearchParams({ client_id: t.cfg.clientId, redirect_uri: REDIRECT, response_type: 'code', scope: 'openid profile email', code_challenge: challenge, code_challenge_method: 'S256', state })
  const a = await z(`/oauth/v2/authorize?${q}`, { instance: T.domain })
  const authRequest = new URL(a.headers.get('location')!, 'http://x').searchParams.get('authRequest')!
  // 2. Start IdP intent at T.
  const st = await z('/v2/idp_intents', { instance: T.domain, token: LT(), json: { idpId, urls: { successUrl: 'http://localhost:3999/idp/success', failureUrl: 'http://localhost:3999/idp/failure' } } })
  if (st.status >= 300) throw new Error(`start intent: ${st.status} ${short(st.text)}`)
  const authUrl = new URL(st.json.authUrl)
  log(`  start intent at ${T.domain}: authUrl host=${authUrl.host} redirect_uri=${authUrl.searchParams.get('redirect_uri')}`)
  // 3. Browser goes to S's authorize (driver: same Zitadel, instance header = S issuer host).
  const sa = await z(authUrl.pathname + authUrl.search, { instance: SHOP_ISSUER_HOST })
  const sAuthReq = new URL(sa.headers.get('location')!, 'http://x').searchParams.get('authRequest')!
  // 4. Shop login at S (Session API with the shop user's password) and finalize S's auth request.
  const ss = await ok('S session', z('/v2/sessions', { instance: SHOP_ISSUER_HOST, token: LT(), json: { checks: { user: { loginName: 'buyer@shop.test' }, password: { password: PASSWORD } } } }))
  const sf = await ok('S finalize', z(`/v2/oidc/auth_requests/${sAuthReq}`, { instance: SHOP_ISSUER_HOST, token: LT(), json: { session: { sessionId: ss.json.sessionId, sessionToken: ss.json.sessionToken } } }))
  const cbUrl = new URL(sf.json.callbackUrl)
  // 5. Browser returns to T's /idps/callback; T exchanges the code with S over the backchannel.
  const cb = await z(cbUrl.pathname + cbUrl.search, { instance: T.domain })
  const loc = cb.headers.get('location') ?? ''
  if (!loc.startsWith('http://localhost:3999/idp/success')) throw new Error(`idp callback at ${T.domain}: ${cb.status} location=${loc} ${short(cb.text)}`)
  const succ = new URL(loc)
  const intentId = succ.searchParams.get('id')!
  const intentToken = succ.searchParams.get('token')!
  // 6. Retrieve the intent: external identity + linked user (if any).
  const ri = await ok('retrieve intent', z(`/v2/idp_intents/${intentId}`, { instance: T.domain, token: LT(), json: { idpIntentToken: intentToken } }))
  let userId: string = ri.json.userId ?? ''
  const ext = ri.json.idpInformation
  let action = 'existing link'
  if (!userId) {
    // 7. Auto-create in T's customers org with the IdP link (what Login UI v2 does with addHumanUser).
    const add = ri.json.addHumanUser ?? {}
    log(`  retrieve intent: no linked user; idpInformation.userName=${ext.userName}; addHumanUser suggestion: ${JSON.stringify({ username: add.username, profile: add.profile, email: add.email })}`)
    const cu = await z('/v2/users/human', {
      ...t.o,
      json: {
        ...add,
        organization: { orgId: t.customersOrg },
        profile: { givenName: add.profile?.givenName || 'Shop', familyName: add.profile?.familyName || 'Buyer', displayName: add.profile?.displayName },
        email: { email: add.email?.email ?? 'buyer@shop.test', isVerified: true },
        idpLinks: [{ idpId, userId: ext.userId, userName: ext.userName }],
      },
    })
    if (cu.status >= 300) throw new Error(`create linked user at ${T.domain}: ${cu.status} ${short(cu.text)}`)
    userId = cu.json.userId
    action = 'auto-created + linked'
  }
  // 8. Session at T with the idpIntent check, finalize T's auth request, token.
  const ts = await eventually('T session', () => z('/v2/sessions', { instance: T.domain, token: LT(), json: { checks: { user: { userId }, idpIntent: { idpIntentId: intentId, idpIntentToken: intentToken } } } }))
  const tf = await ok('T finalize', z(`/v2/oidc/auth_requests/${authRequest}`, { instance: T.domain, token: LT(), json: { session: { sessionId: ts.json.sessionId, sessionToken: ts.json.sessionToken } } }))
  const code = new URL(tf.json.callbackUrl).searchParams.get('code')!
  const tok = await ok('T token', z('/oauth/v2/token', { instance: T.domain, form: { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: t.cfg.clientId, code_verifier: verifier } }))
  const at = decodeJwt(tok.json.id_token)
  return { action, userId, extUserId: ext.userId, iss: at.iss, sub: at.sub, email: at.email }
}

for (const [label, t, idp] of [
  ['B first', B, bIdp],
  ['B again', B, bIdp],
  ['C first (same Shop user)', C, cIdp],
  ['C again', C, cIdp],
] as const) {
  try {
    const r = await shopLogin(t, idp)
    log(`${label}: OK ${r.action}; tenant user ${r.userId}, external (S) sub ${r.extUserId}; id_token iss=${r.iss} sub=${r.sub} email=${r.email}`)
  } catch (e: any) {
    log(`${label}: FAIL ${short(e.message, 600)}`)
  }
}

// #9535 inside one instance: link the same Shop identity to a second user in another org of B.
const staffUser = await ok('B staff user', z('/v2/users/new', { ...B.o, json: { organizationId: B.cfg.orgId, username: 'other@fb.test', human: { profile: { givenName: 'O', familyName: 'U' }, email: { email: 'other@fb.test', isVerified: true } } } }))
const link2 = await z(`/v2/users/${staffUser.json.id}/links`, { ...B.o, json: { idpLink: { idpId: bIdp, userId: sCfg.userId, userName: 'buyer@shop.test' } } })
log(`B: link the same Shop identity to a 2nd user in another org (staff): ${link2.status} ${short(link2.text, 200)}`)
// Local customer at B with the Shop buyer's email: not linked (autoLinking off).
const local = await ok('B local same email', z('/v2/users/new', { ...B.o, json: { organizationId: B.customersOrg, username: 'local-buyer', human: { profile: { givenName: 'L', familyName: 'B' }, email: { email: 'buyer@shop.test', isVerified: true }, password: { password: PASSWORD } } } }))
const links = await z(`/v2/users/${local.json.id}/links/_search`, { ...B.o, json: {} })
log(`B: local customer with the same email ${local.json.id}: idp links=${links.json?.result?.length ?? 0}`)
log('\ndone')
