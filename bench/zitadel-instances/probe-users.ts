// Probe 4 (TASK-62): invite a human with a pre-verified email; password-setup code and passkey
// registration code through the v2 User API, no SMTP. Then use both (set password, register a
// passkey with a software authenticator, log in with each through the Session API).
//   mise exec -- node bench/zitadel-instances/probe-users.ts > bench/zitadel-instances/evidence/probe-users.txt
import { createInstance, eventually, ok, systemToken, z } from './lib.ts'
import { SoftAuthenticator } from './webauthn.ts'

const tag = Date.now().toString(36)
const log = (...a: unknown[]) => console.log(...a)
const short = (s: string, n = 220) => (s.length > n ? s.slice(0, n) + '…' : s)

log(`# probe-users ${new Date().toISOString()}`)
const I = await createInstance(`pu-${tag}`, `pu-${tag}.idp.internal`)
const o = { instance: I.domain, token: I.pat }
const org = await eventually('orgs/me', () => z('/management/v1/orgs/me', o))
const store = `store-${tag}.brand.test`
await ok('trusted domain', z('/admin/v1/trusted_domains', { ...o, json: { domain: store } }))

// 1. Human user, verified email, NO password (an invited staff member).
const u = await ok(
  'create user',
  z('/v2/users/new', {
    ...o,
    json: {
      organizationId: org.json.org.id,
      username: 'staff@merchant.test',
      human: { profile: { givenName: 'Sam', familyName: 'Staff' }, email: { email: 'staff@merchant.test', isVerified: true } },
    },
  }),
)
const uid = u.json.id
log(`POST /v2/users/new (human, email.isVerified=true, no password): ${u.status} id=${uid}`)
const g = await z(`/v2/users/${uid}`, o)
log(`GET /v2/users/{id}: state=${g.json.user.state} email.isVerified=${g.json.user.human.email.isVerified} passwordChanged=${g.json.user.human.passwordChanged ?? '-'}`)

// 2a. Invite code (the "set up your account" code Login UI v2 consumes).
const inv = await z(`/v2/users/${uid}/invite_code`, { ...o, json: { returnCode: {} } })
log(`POST /v2/users/{id}/invite_code {returnCode:{}}: ${inv.status} ${short(inv.text)}`)

// 2b. Password-setup code.
const pr = await ok('password_reset', z(`/v2/users/${uid}/password_reset`, { ...o, json: { returnCode: {} } }))
log(`POST /v2/users/{id}/password_reset {returnCode:{}}: ${pr.status} verificationCode=${pr.json.verificationCode ? '<' + pr.json.verificationCode.length + ' chars>' : 'none'}`)
// The user (via our UI or Login UI v2) sets the password with the code, called with the login client token.
const sp = await z(`/v2/users/${uid}/password`, {
  instance: I.domain,
  token: systemToken('zlogin'),
  json: { newPassword: { password: 'Password1!-set', changeRequired: false }, verificationCode: pr.json.verificationCode },
})
log(`POST /v2/users/{id}/password {newPassword, verificationCode} (zlogin token): ${sp.status} ${short(sp.text, 120)}`)
const s1b = await z('/v2/sessions', {
  instance: I.domain,
  token: systemToken('zlogin'),
  json: { checks: { user: { loginName: 'staff@merchant.test' }, password: { password: 'Password1!-set' } } },
})
log(`POST /v2/sessions (user + new password): ${s1b.status} ${s1b.json?.sessionId ? 'session ' + s1b.json.sessionId : short(s1b.text)}`)
const reuse = await z(`/v2/users/${uid}/password`, {
  instance: I.domain,
  token: systemToken('zlogin'),
  json: { newPassword: { password: 'Password1!-again' }, verificationCode: pr.json.verificationCode },
})
log(`reuse the same code: ${reuse.status} ${short(reuse.text, 120)}`)

// 3. Passkey registration code → register with a software authenticator, on two rpIds.
for (const domain of [I.domain, store, `unregistered-${tag}.brand.test`]) {
  const link = await ok('registration_link', z(`/v2/users/${uid}/passkeys/registration_link`, { ...o, json: { returnCode: {} } }))
  log(`\nPOST /v2/users/{id}/passkeys/registration_link {returnCode:{}}: ${link.status} code.id=${link.json.code?.id} code.code=<${link.json.code?.code?.length} chars>`)
  // The passkey setup page (no session) registers with the code; uses the login client token.
  const reg = await z(`/v2/users/${uid}/passkeys`, {
    instance: I.domain,
    token: systemToken('zlogin'),
    json: { code: link.json.code, authenticator: 'PASSKEY_AUTHENTICATOR_UNSPECIFIED', domain },
  })
  if (reg.status >= 300) {
    log(`POST /v2/users/{id}/passkeys {code, domain: ${domain}}: ${reg.status} ${short(reg.text)}`)
    continue
  }
  const opts = reg.json.publicKeyCredentialCreationOptions
  log(`POST /v2/users/{id}/passkeys {code, domain: ${domain}}: ${reg.status} passkeyId=${reg.json.passkeyId} rp.id=${opts.publicKey.rp.id}`)
  const auth = new SoftAuthenticator()
  const cred = auth.create(opts, `http://${domain}`)
  const ver = await z(`/v2/users/${uid}/passkeys/${reg.json.passkeyId}`, {
    instance: I.domain,
    token: systemToken('zlogin'),
    json: { publicKeyCredential: cred, passkeyName: `soft-${domain}` },
  })
  log(`POST /v2/users/{id}/passkeys/{passkeyId} (verify attestation, origin http://${domain}): ${ver.status} ${short(ver.text, 160)}`)
  if (ver.status >= 300) continue
  // Passkey login: session with a WebAuthN challenge, then the assertion.
  const s = await ok(
    'session+challenge',
    z('/v2/sessions', {
      instance: I.domain,
      token: systemToken('zlogin'),
      json: {
        checks: { user: { userId: uid } },
        challenges: { webAuthN: { domain, userVerificationRequirement: 'USER_VERIFICATION_REQUIREMENT_REQUIRED' } },
      },
    }),
  )
  const req = s.json.challenges.webAuthN.publicKeyCredentialRequestOptions
  const assertion = auth.get(req, `http://${domain}`)
  const upd = await z(`/v2/sessions/${s.json.sessionId}`, {
    method: 'PATCH',
    instance: I.domain,
    token: systemToken('zlogin'),
    json: { checks: { webAuthN: { credentialAssertionData: assertion } } },
  })
  const det = await z(`/v2/sessions/${s.json.sessionId}`, { instance: I.domain, token: systemToken('zlogin') })
  log(`passkey login (rpId ${domain}): session update ${upd.status}; factors=${Object.keys(det.json?.session?.factors ?? {}).join(',')} webAuthN.userVerified=${det.json?.session?.factors?.webAuthN?.userVerified}`)
}
log('\ndone')
