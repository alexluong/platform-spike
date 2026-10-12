// The Cerbos policy names every permission twice per resource (CEL can't see the action, so each
// permission is its own rule) and repeats the catalog in constants. Nothing else ties the YAML to
// kernel/catalog.ts, so check it here: a permission added to the catalog without a rule would be
// silently denied everywhere; a rule whose condition names a different action grants the wrong thing.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { GRANTABLE, NEVER_FOR_APPS } from './catalog.js'

const dir = fileURLToPath(new URL('../../../stacks/d/cerbos/policies/', import.meta.url))
const policy = (f: string) => readFileSync(dir + f, 'utf8')
const sorted = (xs: Iterable<string>) => [...new Set(xs)].sort()

/** One-line rules: `actions: ["a"] ... expr: '"b" in V.granted'` → [a, b]. */
function oneLiners(yaml: string): [string, string][] {
  return [...yaml.matchAll(/actions: \["([\w.]+)"\][^\n]*expr: '"([\w.]+)" in V\.granted/g)].map((m) => [m[1]!, m[2]!])
}
const constant = (yaml: string, name: string) => JSON.parse(new RegExp(`${name}: (\\[[^\\]]*\\])`).exec(yaml)![1]!) as string[]

describe('Cerbos policy ↔ catalog', () => {
  for (const f of ['merchant.yaml', 'store.yaml']) {
    it(`${f}: every rule's condition names its own action`, () => {
      for (const [action, inCondition] of oneLiners(policy(f))) expect(inCondition, f).toBe(action)
    })
  }

  it('merchant.yaml: one rule per grantable permission', () => {
    expect(sorted(oneLiners(policy('merchant.yaml')).map(([a]) => a))).toEqual(sorted(GRANTABLE))
  })

  it('store.yaml: one rule per grantable permission (store.view has its planner-friendly user rule too)', () => {
    const y = policy('store.yaml')
    expect(sorted(oneLiners(y).map(([a]) => a))).toEqual(sorted(GRANTABLE))
    expect(y).toMatch(/name: store_view_user\n\s+actions: \["store.view"\]/)
  })

  it('store.yaml constants match the catalog', () => {
    const y = policy('store.yaml')
    expect(sorted(constant(y, 'storeActions'))).toEqual(sorted(GRANTABLE))
    expect(sorted(constant(y, 'neverForApps'))).toEqual(sorted(NEVER_FOR_APPS))
  })

  it('break-glass reads are view actions only', () => {
    for (const f of ['merchant.yaml', 'store.yaml']) {
      const m = /name: break_glass_read[^\n]*\n\s+actions: (\[[^\]]*\])/.exec(policy(f))
      const actions = JSON.parse(m![1]!) as string[]
      expect(actions.length).toBeGreaterThan(0)
      for (const a of actions) expect(a, f).toMatch(/\.view$/)
    }
  })
})
