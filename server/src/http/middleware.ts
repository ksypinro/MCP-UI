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

/** Requests per window, keyed by address and route. Spec section 7.2. */
export function rateLimit(limit: number, windowMs: number): RequestHandler {
  const hits = new Map<string, { count: number; resetAt: number }>();

  return (req, res, next) => {
    const now = Date.now();
    const key = `${req.ip ?? 'unknown'}:${req.path}`;
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

    // express.json() rejects a malformed body with a SyntaxError carrying a
    // status. That is the client's mistake, not ours.
    if (error instanceof SyntaxError && 'status' in error && (error as { status?: number }).status === 400) {
      const malformed = new AppError('MALFORMED_REQUEST');
      res.status(malformed.status).json(malformed.toBody(requestId));
      return;
    }

    process.stderr.write(`[error] ${requestId} ${String((error as Error)?.stack ?? error)}\n`);
    const internal = new AppError('INTERNAL_ERROR');
    res.status(internal.status).json(internal.toBody(requestId));
  };
}
