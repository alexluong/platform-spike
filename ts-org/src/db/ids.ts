import { randomBytes } from 'node:crypto'
export const newId = (prefix: string) => `${prefix}_${randomBytes(10).toString('base64url')}`
