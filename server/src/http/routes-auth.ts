/**
 * The legacy first-party authentication endpoints from spec section 7.1.
 *
 * Superseded by OAuth: the app now signs in through the system browser, with
 * PAR, PKCE and a DPoP key in the Secure Enclave, and refreshes and revokes
 * at the authorization server. LEGACY_FIRST_PARTY_AUTH retires these in
 * steps:
 *
 *   on          as before
 *   deprecated  as before, plus Deprecation and Sunset headers (the default)
 *   off         sign-up, log-in and refresh answer 410; /me and /logout keep
 *               working one release longer, so existing installs can still
 *               read their account and sign out
 */

import { Router, type RequestHandler } from 'express';
import type { Db } from '../db/index.ts';
import type { Infrastructure } from '../stores/index.ts';
import type { TokenVerifier } from '../security/verifier.ts';
import { AppError } from '../errors.ts';
import { createAccount, getAccount, verifyCredentials } from '../domain/accounts.ts';
import { refreshSession, revokeSession, startSession } from '../domain/sessions.ts';
import { createHash } from 'node:crypto';
import { authenticate, callerOf, context, rateLimit } from './middleware.ts';

/** When the legacy endpoints stop working. Advisory until LEGACY_FIRST_PARTY_AUTH=off. */
const SUNSET = 'Mon, 01 Feb 2027 00:00:00 GMT';
const DEPRECATED_SINCE = '@1792281600'; // 18 Oct 2026, RFC 9745 structured date

function legacyMode(): 'on' | 'deprecated' | 'off' {
  const mode = process.env.LEGACY_FIRST_PARTY_AUTH;
  return mode === 'on' || mode === 'off' ? mode : 'deprecated';
}

/** Marks every legacy response, and retires the credential-issuing ones when off. */
function legacy(retirable: boolean): RequestHandler {
  return (_req, res, next) => {
    const mode = legacyMode();
    if (mode !== 'on') {
      res.set('Deprecation', DEPRECATED_SINCE);
      res.set('Sunset', SUNSET);
    }
    if (mode === 'off' && retirable) return next(new AppError('ENDPOINT_RETIRED'));
    next();
  };
}

export function authRoutes(db: Db, infra: Infrastructure, verifier: TokenVerifier): Router {
  const router = Router();
  router.use('/v1/auth/signup', legacy(true));
  router.use('/v1/auth/login', legacy(true));
  router.use('/v1/auth/refresh', legacy(true));
  router.use('/v1/auth/me', legacy(false));
  router.use('/v1/auth/logout', legacy(false));

  // Spec section 7.2. Generous enough not to bite a real user retyping a
  // password, tight enough that the endpoint is not a credential oracle.
  const limiter = rateLimit(10, 60_000, (req) => `${req.ip ?? 'unknown'}:${req.path}`, infra.buckets);

  // Refresh is an authenticated routine operation performed by every client,
  // not a credential-guessing surface, so it is bucketed by the token
  // presented rather than by address. Limiting it per address logs out the
  // eleventh person behind an office NAT.
  const refreshLimiter = rateLimit(
    30,
    60_000,
    (req) => {
      const token = (req.body as { refreshToken?: unknown } | undefined)?.refreshToken;
      return typeof token === 'string'
        ? `refresh:${createHash('sha256').update(token).digest('hex')}`
        : `refresh-anon:${req.ip ?? 'unknown'}`;
    },
    infra.buckets
  );

  router.post('/v1/auth/signup', limiter, async (req, res) => {
    const body = req.body as { username?: unknown; password?: unknown } | undefined;
    const account = await createAccount(db, body?.username, body?.password);
    const tokens = await startSession(db, account.id);
    res.status(201).json({ account, ...tokens });
  });

  router.post('/v1/auth/login', limiter, async (req, res) => {
    const body = req.body as { username?: unknown; password?: unknown } | undefined;
    const account = await verifyCredentials(db, body?.username, body?.password);
    // One generic failure for both an unknown username and a wrong password.
    if (!account) throw new AppError('UNAUTHENTICATED');
    const tokens = await startSession(db, account.id);
    res.json({ account, ...tokens });
  });

  router.get('/v1/auth/me', authenticate(verifier, { required: true, replay: infra.replay }), async (_req, res) => {
    const account = await getAccount(db, callerOf(res).accountId);
    if (!account) throw new AppError('UNAUTHENTICATED');
    res.json({ account });
  });

  router.post('/v1/auth/refresh', refreshLimiter, async (req, res) => {
    const body = req.body as { refreshToken?: unknown } | undefined;
    res.json(await refreshSession(db, body?.refreshToken));
  });

  router.post('/v1/auth/logout', authenticate(verifier, { required: true, replay: infra.replay }), async (_req, res) => {
    const sessionId = context(res).sessionId;
    if (sessionId) await revokeSession(db, sessionId);
    res.status(204).end();
  });

  return router;
}

/**
 * The API gateway's share of /v1/auth when split into processes (plan 4.7).
 * The gateway holds no database credentials, so the password endpoints are
 * retired outright there, which is why profile M comes after the browser
 * sign-in build has shipped. `me` answers from the verified caller.
 */
export function gatewayAuthRoutes(infra: Infrastructure, verifier: TokenVerifier): Router {
  const router = Router();
  for (const path of ['/v1/auth/signup', '/v1/auth/login', '/v1/auth/refresh', '/v1/auth/logout']) {
    router.post(path, (_req, res, next) => {
      res.set('Deprecation', DEPRECATED_SINCE);
      res.set('Sunset', SUNSET);
      next(new AppError('ENDPOINT_RETIRED'));
    });
  }
  router.get('/v1/auth/me', authenticate(verifier, { required: true, replay: infra.replay }), async (_req, res) => {
    const account = await verifier.account(callerOf(res).accountId);
    if (!account) throw new AppError('UNAUTHENTICATED');
    res.json({ account });
  });
  return router;
}
