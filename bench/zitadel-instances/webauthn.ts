// Minimal software WebAuthn authenticator (ES256, "none" attestation) so probes can finish a passkey
// registration and a passkey login headless. Test-only; no security properties.
import { createHash, createSign, generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto'

const sha256 = (b: Buffer | string) => createHash('sha256').update(b).digest()
const b64u = (b: Buffer) => b.toString('base64url')
const fromB64u = (s: string) => Buffer.from(s.replace(/=+$/, ''), s.includes('+') || s.includes('/') ? 'base64' : 'base64url')

// --- tiny CBOR encoder (uints, negints, bytes, text, maps) ---
function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n])
  if (n < 256) return Buffer.from([(major << 5) | 24, n])
  if (n < 65536) return Buffer.from([(major << 5) | 25, n >> 8, n & 255])
  const b = Buffer.alloc(5)
  b[0] = (major << 5) | 26
  b.writeUInt32BE(n, 1)
  return b
}
type C = number | string | Buffer | Map<C, C>
function cbor(v: C): Buffer {
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v)
  if (typeof v === 'string') return Buffer.concat([head(3, Buffer.byteLength(v)), Buffer.from(v)])
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v])
  const parts: Buffer[] = [head(5, v.size)]
  for (const [k, x] of v) parts.push(cbor(k), cbor(x))
  return Buffer.concat(parts)
}

export class SoftAuthenticator {
  private priv: KeyObject
  private pubJwk: { x: string; y: string }
  readonly credId = randomBytes(16)
  private counter = 0
  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    this.priv = privateKey
    this.pubJwk = publicKey.export({ format: 'jwk' }) as any
  }

  /** navigator.credentials.create() given Zitadel's publicKeyCredentialCreationOptions. */
  create(opts: any, origin: string): any {
    const pk = opts.publicKey ?? opts
    const rpId: string = pk.rp?.id
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: b64u(fromB64u(pk.challenge)), origin, crossOrigin: false }))
    const cose = cbor(
      new Map<C, C>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, fromB64u(this.pubJwk.x)],
        [-3, fromB64u(this.pubJwk.y)],
      ]),
    )
    const len = Buffer.alloc(2)
    len.writeUInt16BE(this.credId.length)
    const authData = Buffer.concat([sha256(rpId), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), len, this.credId, cose])
    const att = cbor(new Map<C, C>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]))
    return {
      id: b64u(this.credId),
      rawId: b64u(this.credId),
      type: 'public-key',
      response: { attestationObject: b64u(att), clientDataJSON: b64u(clientData) },
    }
  }

  /** navigator.credentials.get() given publicKeyCredentialRequestOptions. */
  get(opts: any, origin: string, userHandle?: string): any {
    const pk = opts.publicKey ?? opts
    const rpId: string = pk.rpId
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: b64u(fromB64u(pk.challenge)), origin, crossOrigin: false }))
    const cnt = Buffer.alloc(4)
    cnt.writeUInt32BE(++this.counter)
    const authData = Buffer.concat([sha256(rpId), Buffer.from([0x05]), cnt])
    const sig = createSign('SHA256').update(Buffer.concat([authData, sha256(clientData)])).sign(this.priv)
    return {
      id: b64u(this.credId),
      rawId: b64u(this.credId),
      type: 'public-key',
      response: {
        authenticatorData: b64u(authData),
        clientDataJSON: b64u(clientData),
        signature: b64u(sig),
        ...(userHandle ? { userHandle } : {}),
      },
    }
  }
}
