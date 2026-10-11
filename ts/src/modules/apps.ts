// Apps (SPEC §5): registered by the platform, installed per store with scopes ⊆ requested.
import { and, asc, eq } from 'drizzle-orm'
import { z } from 'zod'
import { newId } from '../db/ids.js'
import { appInstalls, apps } from '../db/schema.js'
import { defineAction } from '../kernel/action.js'
import { NEVER_FOR_APPS, isGrantable } from '../kernel/catalog.js'
import { invalid, notFound } from '../kernel/errors.js'
import { assertHoldsAll } from './guardrails.js'
import { findStore, platformResource, storeResource } from './lookup.js'

/** Narrow port onto the identity provider: mint client credentials. */
export interface ClientRegistry {
  createClient(name: string, actorCredential: string): Promise<{ clientId: string; clientSecret: string }>
}

const installOut = (x: typeof appInstalls.$inferSelect) => ({ id: x.id, appId: x.appId, storeId: x.storeId, scopes: x.scopes })

export function appActions(deps: { clients: ClientRegistry }) {
  const register = defineAction({
    id: 'platform.app.register',
    mutating: true,
    kinds: ['platform'],
    input: z.object({ name: z.string().min(1), scopes: z.array(z.string()) }),
    authorize: async () => ({ action: 'platform.app.register', resource: platformResource }),
    async run({ tx, principal, emit }, i) {
      const bad = i.scopes.filter((s) => !isGrantable(s))
      if (bad.length) throw invalid('not_grantable', `not grantable: ${bad.join(', ')}`)
      const never = i.scopes.filter((s) => (NEVER_FOR_APPS as readonly string[]).includes(s))
      if (never.length) throw invalid('not_grantable_to_apps', `apps never get: ${never.join(', ')}`)
      const c = await deps.clients.createClient(i.name, principal.credential)
      const id = newId('app')
      await tx.insert(apps).values({ id, name: i.name, requestedScopes: [...new Set(i.scopes)], clientId: c.clientId })
      emit({ type: 'app.registered', appId: id })
      return { id, clientId: c.clientId, clientSecret: c.clientSecret }
    },
  })

  const install = defineAction({
    id: 'app.install',
    mutating: true,
    input: z.object({ storeId: z.string(), appId: z.string().min(1), scopes: z.array(z.string()) }),
    authorize: async ({ db, principal }, i) => ({ action: 'app.install', resource: storeResource((await findStore(db, principal, i.storeId)).id) }),
    async run({ tx, principal, can, emit }, i) {
      const s = await findStore(tx, principal, i.storeId)
      const [a] = await tx.select().from(apps).where(eq(apps.id, i.appId))
      if (!a) throw notFound('app')
      const scopes = [...new Set(i.scopes)]
      const extra = scopes.filter((x) => !a.requestedScopes.includes(x))
      if (extra.length) throw invalid('invalid_input', `not requested by the app: ${extra.join(', ')}`)
      await assertHoldsAll(can, scopes, storeResource(s.id))
      const [x] = await tx
        .insert(appInstalls)
        .values({ id: newId('inst'), merchantId: s.merchantId, storeId: s.id, appId: a.id, scopes, installedBy: principal.id })
        .returning()
      emit({ type: 'app.installed', installId: x!.id })
      return installOut(x!)
    },
  })

  const uninstall = defineAction({
    id: 'app.uninstall',
    mutating: true,
    input: z.object({ storeId: z.string(), installId: z.string() }),
    authorize: async ({ db, principal }, i) => ({ action: 'app.uninstall', resource: storeResource((await findStore(db, principal, i.storeId)).id) }),
    async run({ tx, emit }, i) {
      const del = await tx
        .delete(appInstalls)
        .where(and(eq(appInstalls.id, i.installId), eq(appInstalls.storeId, i.storeId)))
        .returning()
      if (!del.length) throw notFound('install')
      emit({ type: 'app.uninstalled', installId: i.installId })
      return null
    },
  })

  const list = defineAction({
    id: 'app.view',
    mutating: false,
    input: z.object({ storeId: z.string() }),
    authorize: async ({ db, principal }, i) => ({ action: 'app.view', resource: storeResource((await findStore(db, principal, i.storeId)).id) }),
    async run({ tx }, i) {
      const rows = await tx.select().from(appInstalls).where(eq(appInstalls.storeId, i.storeId)).orderBy(asc(appInstalls.createdAt))
      return { items: rows.map(installOut) }
    },
  })

  return [register, install, uninstall, list]
}
