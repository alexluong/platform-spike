import type { StackDriver } from './driver'
import { env, type StackName } from './env'
import a from '../stacks/a'
import b from '../stacks/b'
import c from '../stacks/c'
import d from '../stacks/d'
import e from '../stacks/e'
import a2 from '../stacks/a2'
import f from '../stacks/f'

const drivers: Record<StackName, StackDriver> = { a, b, c, d, e, a2, f }

export function getDriver(): StackDriver {
  return drivers[env.stack]
}
