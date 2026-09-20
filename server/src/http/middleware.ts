import { randomBytes } from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { Db } from '../db/index.ts';
import { AppError, isAppError } from '../errors.ts';
import { verifyAccessToken } from '../domain/sessions.ts';
import type { Identity } from '../domain/types.ts';

export interface RequestContext {
  requestId: string;
  identity?: Identity;
  sessionId?: string;
}

/** Typed accessor for the per-request context stashed on res.locals. */
export function context(res: Response): RequestContext {
  return res.locals.ctx as RequestContext;
}

/** The verified caller, or a 401. Route handlers use this, never res.locals. */
export function identityOf(res: Response): Identity {
  const identity = context(res).identity;
  if (!identity) throw new AppError('UNAUTHENTICATED', 'Sign in to continue.');
  return identity;
}

export function withRequestId(): RequestHandler {
  return (req, res, next) => {
    const requestId = `req_${randomBytes(6).toString('hex')}`;
    res.locals.ctx = { requestId } satisfies RequestContext;
    res.setHeader('x-request-id', requestId);
    next();
  };
}

function bearer(req: Request): string | null {
  const header = req.get('authorization');
  if (!header?.toLowerCase().startsWith('bearer ')) return null;
  return header.slice(7).trim() || null;
}

/**
 * Resolves a bearer token on every request that carries one.
 *
 * `required: false` is used on endpoints that behave differently when signed
 * in but do not demand it. It never *rejects* — the route decides, via
 * identityOf, so that an optional-auth route cannot accidentally become a
 * protected one by forgetting a guard.
 */
export function authenticate(db: Db, options: { required: boolean }): RequestHandler {
  return async (req, res, next) => {
    try {
      const verified = await verifyAccessToken(db, bearer(req));
      if (verified) {
        const ctx = context(res);
        ctx.identity = {
          accountId: verified.accountId,
          channel: 'native',
          requestId: ctx.requestId
        };
        ctx.sessionId = verified.sessionId;
      } else if (options.required) {
        throw new AppError('UNAUTHENTICATED', 'Sign in to continue.');
      }
      next();
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Requests per window. Spec section 7.2.
 *
 * The bucket key is a parameter because the right one differs by route:
 * credential-guessing surfaces are limited by address, but an authenticated
 * routine operation must not be, or everyone behind one NAT shares a quota.
 */
export function rateLimit(
  limit: number,
  windowMs: number,
  keyOf: (req: Request) => string = (req) => `${req.ip ?? 'unknown'}:${req.path}`
): RequestHandler {
  const hits = new Map<string, { count: number; resetAt: number }>();

  return (req, res, next) => {
    const now = Date.now();
    const key = keyOf(req);
    const entry = hits.get(key);

    if (!entry || entry.resetAt <= now) {
      hits.set(key, { count: 1, resetAt: now + windowMs });
      // Opportunistic sweep; this map is per-process and must not grow forever.
      if (hits.size > 10_000) {
        for (const [k, v] of hits) if (v.resetAt <= now) hits.delete(k);
      }
      next();
      return;
    }

    if (++entry.count > limit) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      res.setHeader('retry-after', String(retryAfter));
      next(new AppError('RATE_LIMITED'));
      return;
    }
    next();
  };
}

export function notFound(): RequestHandler {
  return (_req, _res, next) => next(new AppError('NOT_FOUND'));
}

/**
 * The single place an error becomes a response body. Spec section 6.3: a
 * closed set of codes, a correlation id, and never an internal stack trace.
 */
export function errorHandler() {
  return (error: unknown, _req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) return next(error);

    const requestId = context(res)?.requestId ?? 'req_unknown';

    if (isAppError(error)) {
      res.status(error.status).json(error.toBody(requestId));
      return;
    }

    // body-parser rejections are the client's mistake, not ours. Key on its
    // `type`, not on the error class: only a parse failure is a SyntaxError,
    // so matching on the class alone sends an oversized body to the 500 branch
    // and tells the caller the server broke.
    const parserType = (error as { type?: string })?.type;
    if (parserType === 'entity.too.large') {
      const tooLarge = new AppError('VALIDATION_FAILED', 'Request body is too large.');
      res.status(413).json(tooLarge.toBody(requestId));
      return;
    }
    if (parserType === 'entity.parse.failed' || parserType === 'encoding.unsupported') {
      const malformed = new AppError('MALFORMED_REQUEST');
      res.status(malformed.status).json(malformed.toBody(requestId));
      return;
    }

    process.stderr.write(`[error] ${requestId} ${String((error as Error)?.stack ?? error)}\n`);
    const internal = new AppError('INTERNAL_ERROR');
    res.status(internal.status).json(internal.toBody(requestId));
  };
}
