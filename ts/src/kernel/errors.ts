export class AppError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message?: string,
  ) {
    super(message ?? code)
  }
}

export const unauthenticated = () => new AppError(401, 'unauthenticated')
export const forbidden = (code = 'forbidden', message?: string) => new AppError(403, code, message)
export const notFound = (what = 'resource') => new AppError(404, 'not_found', `${what} not found`)
export const invalid = (code = 'invalid_input', message?: string) => new AppError(400, code, message)
export const conflict = (code: string, message?: string) => new AppError(409, code, message)
