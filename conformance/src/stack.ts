import type { StackDriver } from './driver'
import { env } from './env'
import a from '../stacks/a'
import b from '../stacks/b'
import c from '../stacks/c'

const drivers: Record<string, StackDriver> = { a, b, c }

export function getDriver(): StackDriver {
  return drivers[env.stack]
}
