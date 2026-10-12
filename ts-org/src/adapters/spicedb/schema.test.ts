// The TS schema generator against Go's: same catalog → same schema (stack e vs a on one engine).
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { GRANTABLE, MERCHANT_ACTIONS, PLATFORM_ACTIONS, STORE_ACTIONS } from '../../kernel/catalog.js'
import { perm, schema } from './schema.js'

const goDir = fileURLToPath(new URL('../../../../go/internal/adapters/spicedb/', import.meta.url))
const here = fileURLToPath(new URL('.', import.meta.url))
const dropHeader = (s: string) => s.slice(s.indexOf('\n') + 1)

/** Body of `definition <name> { … }`. */
function definition(s: string, name: string) {
  const start = s.indexOf(`definition ${name} {`)
  return s.slice(start, s.indexOf('\n}', start))
}

const zedAvailable = spawnSync('zed', ['version'], { stdio: 'ignore' }).status === 0

describe('SpiceDB schema', () => {
  it("equals Go's schema.zed without the membership addition (header comment aside)", () => {
    const goSchema = readFileSync(join(goDir, 'schema.zed'), 'utf8')
    expect(dropHeader(schema({ membership: false }))).toBe(dropHeader(goSchema))
  })

  it('the membership addition is exactly two lines on merchant', () => {
    const base = schema({ membership: false }).split('\n')
    const withM = schema({ membership: true }).split('\n')
    expect(withM.filter((l) => !base.includes(l))).toEqual(['\trelation member: user', '\tpermission agent_register = member - suspended'])
  })

  it('every action the app checks maps to a permission on its resource type', () => {
    const s = schema({ membership: true })
    const at: Record<string, readonly string[]> = {
      platform: PLATFORM_ACTIONS.filter((a) => a !== 'platform.break_glass').concat('platform.app.register'),
      merchant: [...MERCHANT_ACTIONS, ...GRANTABLE.filter((a) => a.endsWith('.view')), 'platform.break_glass', 'role.manage_owner', 'agent.register'],
      store: STORE_ACTIONS,
    }
    for (const [type, actions] of Object.entries(at)) {
      const def = definition(s, type)
      for (const a of actions) expect(def, `${a} on ${type}`).toContain(`permission ${perm(a)} =`)
    }
  })

  it.skipIf(!zedAvailable)("zed validate: Go's validation.yaml and e's membership assertions pass on e's schema", () => {
    const dir = mkdtempSync(join(tmpdir(), 'e-schema-'))
    writeFileSync(join(dir, 'schema.zed'), schema({ membership: true }))
    writeFileSync(join(dir, 'a.yaml'), readFileSync(join(goDir, 'validation.yaml'), 'utf8'))
    writeFileSync(join(dir, 'e.yaml'), readFileSync(join(here, 'validation-e.yaml'), 'utf8'))
    for (const f of ['a.yaml', 'e.yaml']) execFileSync('zed', ['validate', join(dir, f)], { cwd: dir, stdio: 'pipe' })
  })
})
