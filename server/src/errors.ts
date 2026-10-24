/**
 * The closed error set from spec section 6.3.
 *
 * Clients switch on `code`; `message` is for humans and may be reworded
 * without breaking anyone. Every error carries a requestId that also appears
 * in the audit log.
 */

export const ERROR_STATUS = {
  MALFORMED_REQUEST: 400,
  UNAUTHENTICATED: 401,
  INSUFFICIENT_SCOPE: 403,
  NOT_FOUND: 404,
  DEVICE_NOT_FOUND: 404,
  DEVICE_NAME_CONFLICT: 409,
  DEVICE_VERSION_CONFLICT: 409,
  DEVICE_LIMIT_REACHED: 409,
  // Not in the spec's section 6.3 table, which covers only the device API.
  // Sign-up needs a distinct code so the client can highlight the username
  // field rather than showing a generic validation message.
  USERNAME_TAKEN: 409,
  VALIDATION_FAILED: 422,
  INVALID_STATE: 422,
  RATE_LIMITED: 429,
  INTERNAL_ERROR: 500,
  SERVICE_UNAVAILABLE: 503
} as const;

export type ErrorCode = keyof typeof ERROR_STATUS;

const DEFAULT_MESSAGE: Record<ErrorCode, string> = {
  MALFORMED_REQUEST: 'The request body could not be read.',
  // Deliberately identical for a bad username and a bad password: never reveal
  // which half was wrong, or the endpoint becomes an account enumerator.
  UNAUTHENTICATED: 'Invalid username or password.',
  INSUFFICIENT_SCOPE: 'This credential is not permitted to perform that action.',
  NOT_FOUND: 'No such endpoint.',
  DEVICE_NOT_FOUND: 'That device does not exist.',
  DEVICE_NAME_CONFLICT: 'A device with this name already exists.',
  DEVICE_VERSION_CONFLICT: 'This device changed. Refresh it and try again.',
  DEVICE_LIMIT_REACHED: 'You have reached the maximum number of devices.',
  USERNAME_TAKEN: 'That username is already taken.',
  VALIDATION_FAILED: 'One or more fields are invalid.',
  INVALID_STATE: 'State must be exactly "on" or "off".',
  RATE_LIMITED: 'Too many requests. Try again shortly.',
  INTERNAL_ERROR: 'Unexpected error.',
  SERVICE_UNAVAILABLE: 'Temporarily unavailable. Try again shortly.'
};

export class AppError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly field: string | undefined;

  constructor(code: ErrorCode, message?: string, field?: string) {
    super(message ?? DEFAULT_MESSAGE[code]);
    this.name = 'AppError';
    this.code = code;
    this.status = ERROR_STATUS[code];
    this.field = field;
  }

  toBody(requestId: string) {
    return {
      error: {
        code: this.code,
        message: this.message,
        ...(this.field ? { field: this.field } : {}),
        requestId
      }
    };
  }
}

export function isAppError(value: unknown): value is AppError {
  return value instanceof AppError;
}

/** Postgres unique_violation. PGlite reports the same SQLSTATE. */
export const UNIQUE_VIOLATION = '23505';

export function isUniqueViolation(error: unknown, constraint?: string): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const candidate = error as { code?: string; constraint_name?: string; constraint?: string };
  if (candidate.code !== UNIQUE_VIOLATION) return false;
  if (!constraint) return true;
  return (candidate.constraint_name ?? candidate.constraint) === constraint;
}
