/**
 * The token endpoint. Two grants: authorization_code and refresh_token.
 *
 * Clients here are public — `token_endpoint_auth_methods_supported` is
 * `["none"]`, which Claude requires before it will use CIMD — so there is no
 * client secret to check. PKCE and the client_id binding on the code are what
 * stand in for one.
 */

import { Router, type Request, type Response } from 'express';
import type { Db } from '../db/index.ts';
import { RESOURCE_URI } from './config.ts';
import { verifyPkce } from './crypto.ts';
import {
  consumeAuthorizationCode, establishGrant, readRefreshToken, revokeGrant, rotateRefreshToken
} from './store.ts';

function fail(res: Response, status: number, error: string, description: string): void {
  // RFC 6749 section 5.2: token errors are JSON, and must not be cached.
  res.status(status)
    .set('Cache-Control', 'no-store')
    .set('Pragma', 'no-cache')
    .json({ error, error_description: description });
}

export function tokenRoutes(db: Db): Router {
  const router = Router();

  router.post('/token', async (req: Request, res: Response) => {
    const grantType = req.body?.grant_type;
    if (grantType === 'authorization_code') return exchangeCode(db, req, res);
    if (grantType === 'refresh_token') return exchangeRefreshToken(db, req, res);
    return fail(res, 400, 'unsupported_grant_type',
      'Supported grant types are authorization_code and refresh_token.');
  });

  return router;
}

async function exchangeCode(db: Db, req: Request, res: Response): Promise<void> {
  const { code, code_verifier, redirect_uri, client_id, resource } = req.body ?? {};

  // OAuth 2.1 section 3.2.2: a client that does not authenticate MUST send
  // client_id. Treating it as optional would leave the code bound to nothing
  // an attacker does not already have.
  if (typeof client_id !== 'string' || client_id.length === 0) {
    return fail(res, 400, 'invalid_request', 'client_id is required.');
  }

  const record = await consumeAuthorizationCode(db, code);
  if (!record) return fail(res, 400, 'invalid_grant', 'Unknown authorization code.');

  if (record.alreadyConsumed) {
    // OAuth 2.1: a replayed code means the code leaked, and whatever it
    // produced is suspect, so the grant goes with it.
    //
    // Exactly the grant this code produced, and nothing if it produced none.
    // A code burned by a failed exchange never became a grant, and guessing
    // from account and client would revoke an unrelated, newer one.
    if (record.grantId) await revokeGrant(db, record.grantId);
    return fail(res, 400, 'invalid_grant', 'This authorization code has already been used.');
  }

  if (record.expired) return fail(res, 400, 'invalid_grant', 'This authorization code has expired.');

  // The code is bound to the client it was issued to. With public clients
  // there is no secret to check, but the identity must still match.
  if (client_id !== record.clientId) {
    return fail(res, 400, 'invalid_grant', 'This code was issued to a different client.');
  }
  if (typeof redirect_uri === 'string' && redirect_uri !== record.redirectUri) {
    return fail(res, 400, 'invalid_grant', 'redirect_uri does not match the authorization request.');
  }
  if (!verifyPkce(code_verifier, record.codeChallenge)) {
    return fail(res, 400, 'invalid_grant', 'PKCE verification failed.');
  }
  if (resource !== undefined && resource !== record.resource) {
    return fail(res, 400, 'invalid_target', 'resource does not match the authorization request.');
  }

  const tokens = await establishGrant(db, {
    code: code as string,
    accountId: record.accountId,
    clientId: record.clientId,
    resource: record.resource,
    scope: record.scope
  });
  respond(res, tokens);
}

async function exchangeRefreshToken(db: Db, req: Request, res: Response): Promise<void> {
  const { refresh_token, client_id, resource, scope } = req.body ?? {};

  if (typeof client_id !== 'string' || client_id.length === 0) {
    return fail(res, 400, 'invalid_request', 'client_id is required.');
  }

  const record = await readRefreshToken(db, refresh_token);
  if (!record) return fail(res, 400, 'invalid_grant', 'Unknown refresh token.');

  if (record.alreadyReplaced) {
    // A legitimate client never replays a rotated refresh token, so treat this
    // as theft and take down the whole grant — including the token the thief
    // did not steal. Done before the refusal is sent, and outside any
    // transaction that the refusal would roll back.
    await revokeGrant(db, record.grantId);
    return fail(res, 400, 'invalid_grant', 'This refresh token was already used. The grant has been revoked.');
  }
  if (record.revoked || record.grantRevoked || record.expired) {
    return fail(res, 400, 'invalid_grant', 'This refresh token is no longer valid.');
  }
  if (client_id !== record.clientId) {
    return fail(res, 400, 'invalid_grant', 'This refresh token was issued to a different client.');
  }
  if (resource !== undefined && resource !== record.audience) {
    return fail(res, 400, 'invalid_target', 'resource does not match this grant.');
  }

  // A refresh may narrow scope but never widen it (RFC 6749 section 6).
  let scopeToIssue = record.scope;
  if (typeof scope === 'string' && scope.trim().length > 0) {
    const granted = record.scope.split(' ').filter(Boolean);
    const requested = scope.split(/\s+/).filter(Boolean);
    if (requested.some((entry) => !granted.includes(entry))) {
      return fail(res, 400, 'invalid_scope', 'A refresh cannot request scopes beyond the original grant.');
    }
    scopeToIssue = requested.join(' ');
  }

  const tokens = await rotateRefreshToken(
    db, record.tokenHash, record.grantId, record.audience, scopeToIssue
  );
  respond(res, tokens);
}

function respond(res: Response, tokens: { accessToken: string; refreshToken: string; expiresIn: number; scope: string }): void {
  res.status(200)
    .set('Cache-Control', 'no-store')
    .set('Pragma', 'no-cache')
    .json({
      access_token: tokens.accessToken,
      token_type: 'Bearer',
      expires_in: tokens.expiresIn,
      refresh_token: tokens.refreshToken,
      scope: tokens.scope
    });
}

export const TOKEN_RESOURCE = RESOURCE_URI;
