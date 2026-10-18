// Probe 6 (TASK-62): are SMTP, SMS, Actions v2 (targets/executions), branding and the login policy
// (forced MFA) per instance? Set each on instance B, read it back on B and on C.
//   mise exec -- node bench/zitadel-instances/probe-settings.ts > bench/zitadel-instances/evidence/probe-settings.txt
import { createInstance, decodeJwt, eventually, login, ok, provisionLogin, z } from './lib.ts'

const tag = Date.now().toString(36)
const log = (...a: unknown[]) => console.log(...a)
const short = (s: string, n = 200) => (s.length > n ? s.slice(0, n) + '…' : s)

log(`# probe-settings ${new Date().toISOString()}`)
const B = await createInstance(`sb-${tag}`, `sb-${tag}.idp.internal`)
const C = await createInstance(`sc-${tag}`, `sc-${tag}.idp.internal`)
const bCfg = await provisionLogin(B)
const cCfg = await provisionLogin(C)
const ob = { instance: B.domain, token: B.pat }
const oc = { instance: C.domain, token: C.pat }
log(`B=${B.domain} C=${C.domain}`)

// SMTP
const smtp = await z('/admin/v1/smtp', { ...ob, json: { description: 'merchant-b', senderAddress: 'no-reply@b.test', senderName: 'Merchant B', host: 'smtp.b.test:587', user: 'u', password: 'p', tls: true } })
log(`\nSMTP: POST /admin/v1/smtp on B: ${smtp.status} id=${smtp.json?.id}`)
if (smtp.json?.id) log(`  activate: ${(await z(`/admin/v1/smtp/${smtp.json.id}/_activate`, { ...ob, json: {} })).status}`)
const smtpList = async (o: any) => {
  const r = await z('/admin/v1/smtp/_search', { ...o, json: {} })
  return (r.json?.result ?? []).map((c: any) => `${c.description ?? c.senderAddress}:${c.state}`).join(',') || '(none)'
}
log(`  B smtp configs: ${await smtpList(ob)}   C smtp configs: ${await smtpList(oc)}`)

// SMS
const sms = await z('/admin/v1/sms/twilio', { ...ob, json: { sid: 'ACxxxx', token: 'tok', senderNumber: '+15550001111', description: 'merchant-b sms' } })
log(`\nSMS: POST /admin/v1/sms/twilio on B: ${sms.status} id=${sms.json?.id}`)
const smsList = async (o: any) => {
  const r = await z('/admin/v1/sms/_search', { ...o, json: {} })
  return (r.json?.result ?? []).map((c: any) => `${c.description ?? c.id}:${c.state}`).join(',') || '(none)'
}
log(`  B sms providers: ${await smsList(ob)}   C sms providers: ${await smsList(oc)}`)

// Actions v2: a target + an execution on B.
const tgt = await z('/v2/actions/targets', { ...ob, json: { name: 'merchant-b-hook', restWebhook: { interruptOnError: false }, endpoint: 'https://example.com/zitadel-hook', timeout: '5s' } })
log(`\nActions v2: POST /v2/actions/targets on B: ${tgt.status} ${tgt.json?.id ? 'id=' + tgt.json.id : short(tgt.text)}`)
if (tgt.json?.id) {
  const ex = await z('/v2/actions/executions', { ...ob, method: 'PUT', json: { condition: { event: { event: 'user.human.added' } }, targets: [tgt.json.id] } })
  log(`  PUT /v2/actions/executions (event user.human.added → target) on B: ${ex.status} ${ex.status >= 300 ? short(ex.text) : ''}`)
}
const tl = async (o: any) => {
  const r = await z('/v2/actions/targets/search', { ...o, json: {} })
  return r.status >= 300 ? `${r.status} ${short(r.text, 100)}` : (r.json?.targets ?? r.json?.result ?? []).map((t: any) => t.name).join(',') || '(none)'
}
const el = async (o: any) => {
  const r = await z('/v2/actions/executions/search', { ...o, json: {} })
  return r.status >= 300 ? `${r.status} ${short(r.text, 100)}` : String((r.json?.executions ?? r.json?.result ?? []).length)
}
log(`  B targets: ${await tl(ob)} executions: ${await el(ob)}   C targets: ${await tl(oc)} executions: ${await el(oc)}`)

// Branding (instance default label policy).
const lab = await z('/admin/v1/policies/label', { ...ob, method: 'PUT', json: { primaryColor: '#ff0066', backgroundColor: '#101010', warnColor: '#cd3d56', fontColor: '#ffffff', primaryColorDark: '#ff0066', backgroundColorDark: '#000000', warnColorDark: '#ff3b5b', fontColorDark: '#ffffff', hideLoginNameSuffix: true } })
log(`\nBranding: PUT /admin/v1/policies/label on B: ${lab.status} ${lab.status >= 300 ? short(lab.text) : ''}`)
log(`  activate: ${(await z('/admin/v1/policies/label/_activate', { ...ob, json: {} })).status}`)
const br = async (o: any) => {
  const r = await z('/v2/settings/branding', o)
  return `primary=${r.json?.settings?.lightTheme?.primaryColor}`
}
log(`  GET /v2/settings/branding: B ${await br(ob)}   C ${await br(oc)}`)

// Login policy: force MFA on B.
const cur = await ok('get login policy', z('/admin/v1/policies/login', ob))
const p = cur.json.policy
const upd = await z('/admin/v1/policies/login', {
  ...ob,
  method: 'PUT',
  json: {
    allowUsernamePassword: p.allowUsernamePassword,
    allowRegister: p.allowRegister,
    allowExternalIdp: p.allowExternalIdp,
    forceMfa: true,
    forceMfaLocalOnly: false,
    passwordlessType: p.passwordlessType,
    hidePasswordReset: p.hidePasswordReset,
    ignoreUnknownUsernames: p.ignoreUnknownUsernames,
    defaultRedirectUri: p.defaultRedirectUri,
    passwordCheckLifetime: p.passwordCheckLifetime,
    externalLoginCheckLifetime: p.externalLoginCheckLifetime,
    mfaInitSkipLifetime: p.mfaInitSkipLifetime,
    secondFactorCheckLifetime: p.secondFactorCheckLifetime,
    multiFactorCheckLifetime: p.multiFactorCheckLifetime,
    allowDomainDiscovery: p.allowDomainDiscovery,
    disableLoginWithEmail: p.disableLoginWithEmail,
    disableLoginWithPhone: p.disableLoginWithPhone,
  },
})
log(`\nLogin policy: PUT /admin/v1/policies/login {forceMfa:true} on B: ${upd.status} ${upd.status >= 300 ? short(upd.text) : ''}`)
const lp = async (o: any) => (await eventually('settings/login', () => z('/v2/settings/login', o))).json.settings.forceMfa
log(`  GET /v2/settings/login forceMfa: B ${await lp(ob)}   C ${await lp(oc)}`)
// Effect on a password-only login (Session API + finalize): does Zitadel itself enforce MFA?
for (const [n, I, cfg] of [['B', B, bCfg], ['C', C, cCfg]] as const) {
  try {
    const l = await login(I, cfg)
    log(`  password-only login at ${n}: token issued; id_token amr=${JSON.stringify(decodeJwt(l.idToken!).amr)}`)
  } catch (e: any) {
    log(`  password-only login at ${n}: REJECTED ${short(e.message, 220)}`)
  }
}
log('\ndone')
