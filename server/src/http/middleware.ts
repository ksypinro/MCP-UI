import { randomBytes } from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { AppError, isAppError } from '../errors.ts';
import type { VerifiedCaller } from '../domain/types.ts';
import { API_RESOURCE, DPOP_ALGORITHMS } from '../oauth/config.ts';
import { DpopError, currentDpopNonce, verifyDpopProof } from '../oauth/dpop.ts';
import { credentialFrom, requestHtu } from '../security/credentials.ts';
import { API_BASE_URL } from '../config.ts';
import type { ReplayStore } from '../security/replay.ts';
import type { TokenVerifier } from '../security/verifier.ts';
import { log } from '../observability/log.ts';

export interface RequestContext {
  requestId: string;
  caller?: VerifiedCaller;
}

/** Typed accessor for the per-request context stashed on res.locals. */
export function context(res: Response): RequestContext {
  return res.locals.ctx as RequestContext;
}

/** The verified caller, or a 401. Route handlers use this, never res.locals. */
export function callerOf(res: Response): VerifiedCaller {
  const caller = context(res).caller;
  if (!caller) throw new AppError('UNAUTHENTICATED', 'Sign in to continue.');
  return caller;
}

export function withRequestId(): RequestHandler {
  return (req, res, next) => {
    const requestId = `req_${randomBytes(6).toString('hex')}`;
    res.locals.ctx = { requestId } satisfies RequestContext;
    res.setHeader('x-request-id', requestId);
    next();
  };
}

/**
 * Resolves the access token on every request that carries one. The API
 * accepts only the app's OAuth tokens: audience the REST API, bound to its
 * Secure Enclave key (RFC 9449), each request carrying a proof from that key.
 * A bearer token, or one minted for another resource, is refused.
 *
 * `required: false` is for endpoints that behave differently when signed in
 * but do not demand it. It never rejects a request for carrying no token —
 * the route decides, via callerOf — but a token that is presented must be
 * valid and bound, whatever the route.
 */
export function authenticate(verifier: TokenVerifier, options: { required: boolean; replay: ReplayStore }): RequestHandler {
  return async (req, res, next) => {
    try {
      const credential = credentialFrom(req);
      const token = credential?.token ?? null;
      // A fresh nonce on every response to a DPoP client, so it rarely needs
      // a round trip to learn one.
      if (credential?.scheme === 'DPoP') res.set('DPoP-Nonce', currentDpopNonce());

      const oauth = token ? await verifier.oauth(token, [], { audience: API_RESOURCE }) : null;
      if (oauth?.ok && token) {
        if (!oauth.cnfJkt) throw new AppError('UNAUTHENTICATED', 'This API requires DPoP-bound tokens.');
        try {
          if (credential?.scheme !== 'DPoP') {
            throw new DpopError('invalid_dpop_proof', 'This token must be presented with the DPoP scheme.', 'scheme');
          }
          await verifyDpopProof(req.get('dpop'), {
            htm: req.method, htu: requestHtu(API_BASE_URL, req), accessToken: token, expectedJkt: oauth.cnfJkt, replay: options.replay
          });
        } catch (error) {
          if (!(error instanceof DpopError)) throw error;
          res.set('WWW-Authenticate',
            `DPoP error="${error.code}", error_description="${error.message}", algs="${DPOP_ALGORITHMS.join(' ')}"`);
          res.set('DPoP-Nonce', currentDpopNonce());
          throw new AppError('UNAUTHENTICATED', error.message);
        }
        const ctx = context(res);
        ctx.caller = {
          kind: 'verified',
          accountId: oauth.accountId,
          clientId: oauth.clientId,
          grantId: oauth.grantId,
          channel: 'native',
          scopes: oauth.scopes,
          requestId: ctx.requestId,
          credential: token
        };
        next();
        return;
      }

      if (options.required) throw new AppError('UNAUTHENTICATED', 'Sign in to continue.');
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function notFound(): RequestHandler {
  return (_req, _res, next) => next(new AppError('NOT_FOUND'));
}

/**
 * The single place an error becomes a response body. Spec section 6.3: a
 * closed set of codes, a correlation id, and never an internal stack trace.
 */
export function errorHandler(options: { jsonRpcPaths?: string[] } = {}) {
  const jsonRpcPaths = new Set(options.jsonRpcPaths ?? []);

  return (error: unknown, req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) return next(error);

    const requestId = context(res)?.requestId ?? 'req_unknown';

    // The MCP endpoint speaks JSON-RPC. Answering it with the REST envelope
    // hands an MCP client a shape it has no reason to understand, and one
    // that differs from what the transport itself returns on the same path.
    const wantsJsonRpc = jsonRpcPaths.has(req.path);

    const send = (status: number, rpcCode: number, message: string, appCode?: string) => {
      if (wantsJsonRpc) {
        res.status(status).json({
          jsonrpc: '2.0',
          error: { code: rpcCode, message, ...(appCode ? { data: { code: appCode, requestId } } : { data: { requestId } }) },
          id: null
        });
      } else {
        const appError = new AppError((appCode as never) ?? 'INTERNAL_ERROR', message);
        res.status(status).json(appError.toBody(requestId));
      }
    };

    // Application errors keep their status and code in both dialects. Folding
    // them into the generic branch turned a rate limit into a 500.
    if (isAppError(error)) {
      if (wantsJsonRpc) {
        res.status(error.status).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: error.message, data: { code: error.code, requestId } },
          id: null
        });
      } else {
        res.status(error.status).json(error.toBody(requestId));
      }
      return;
    }

    // body-parser rejections are the client's mistake, not ours. Key on its
    // `type`, not on the error class: only a parse failure is a SyntaxError,
    // so matching on the class alone sends an oversized body to the 500
    // branch and tells the caller the server broke.
    const parserType = (error as { type?: string })?.type;
    if (parserType === 'entity.too.large') {
      send(413, -32600, 'Request body is too large.', 'VALIDATION_FAILED');
      return;
    }
    if (parserType === 'entity.parse.failed' || parserType === 'encoding.unsupported') {
      send(400, -32700, wantsJsonRpc ? 'Parse error' : 'The request body could not be read.', 'MALFORMED_REQUEST');
      return;
    }

    log('error', 'unhandled_error', { requestId, method: req.method, path: req.path, error: error instanceof Error ? error : String(error) });
    send(500, -32603, wantsJsonRpc ? 'Internal error' : 'Unexpected error.', 'INTERNAL_ERROR');
  };
}
