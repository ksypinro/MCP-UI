/**
 * The token endpoint. Two grants: authorization_code and refresh_token.
 *
 * Clients here are public — `token_endpoint_auth_methods_supported` is
 * `["none"]`, which Claude requires before it will use CIMD — so there is no
 * client secret to check. PKCE and the client_id binding on the code are what
 * stand in for one.
 *
 * DPoP (RFC 9449): a request carrying a proof gets tokens bound to the
 * proof's key, `token_type: DPoP`. A code whose authorization named a key
 * (dpop_jkt) can only be redeemed with that key, the first-party app must
 * always bind, and a bound grant's refresh token needs a proof from the same
 * key. Proofs are checked before the code or refresh token is touched, so a
 * client told to retry with a fresh nonce has lost nothing.
 */

import { Router, type Request, type Response } from 'express';
import type { Db } from '../db/index.ts';
import {
  FIRST_PARTY_CLIENT_ID, ISSUER, REFRESH_GRACE_SECONDS, RESOURCE_URI, refreshRequiresOfflineAccess
} from './config.ts';
import { DpopError, currentDpopNonce, verifyDpopProof } from './dpop.ts';
import { verifyPkce } from './crypto.ts';
import { tokenDigest } from '../tokens/hash.ts';
import { MemorySealedResponses, type SealedResponses } from './sealed.ts';
import {
  consumeAuthorizationCode, establishGrant, revokeGrantNow, rotateRefresh, type IssuedTokens
} from './store.ts';

function fail(res: Response, status: number, error: string, description: string): void {
  // RFC 6749 section 5.2: token errors are JSON, and must not be cached.
  res.status(status)
    .set('Cache-Control', 'no-store')
    .set('Pragma', 'no-cache')
    .json({ error, error_description: description });
}

/**
 * Verifies this request's DPoP proof, if it carries one. Returns the key's
 * thumbprint, null when there is no proof, or sends the error and returns
 * false.
 */
async function proofOf(req: Request, res: Response): Promise<string | null | false> {
  const proof = req.get('dpop');
  if (proof === undefined) return null;
  try {
    return (await verifyDpopProof(proof, { htm: 'POST', htu: `${ISSUER}/token` })).jkt;
  } catch (error) {
    if (!(error instanceof DpopError)) throw error;
    fail(res, 400, error.code, error.message);
    return false;
  }
}

export function tokenRoutes(db: Db): Router {
  const router = Router();
  // Per app, so that two servers in one process never share sealed responses.
  const sealed = new MemorySealedResponses();

  router.post('/token', async (req: Request, res: Response) => {
    // Every answer carries a fresh nonce, so a DPoP client never needs a
    // round trip just to learn one.
    res.set('DPoP-Nonce', currentDpopNonce());
    const grantType = req.body?.grant_type;
    if (grantType === 'authorization_code') return exchangeCode(db, req, res);
    if (grantType === 'refresh_token') return exchangeRefreshToken(db, sealed, req, res);
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

  const presentedJkt = await proofOf(req, res);
  if (presentedJkt === false) return;
  // Our own app always binds its tokens to its Secure Enclave key.
  if (client_id === FIRST_PARTY_CLIENT_ID && !presentedJkt) {
    return fail(res, 400, 'invalid_dpop_proof', 'This client must present a DPoP proof.');
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
    if (record.grantId) await revokeGrantNow(db, record.grantId);
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
  // RFC 9449 section 10: a code issued for a key is redeemable only with it.
  if (record.dpopJkt && presentedJkt !== record.dpopJkt) {
    return fail(res, 400, 'invalid_dpop_proof', 'This code is bound to a different DPoP key.');
  }

  const tokens = await establishGrant(db, {
    code: code as string,
    accountId: record.accountId,
    clientId: record.clientId,
    resource: record.resource,
    scope: record.scope,
    withRefresh: !refreshRequiresOfflineAccess() || record.offlineAccess,
    dpopJkt: presentedJkt
  });
  respond(res, tokens);
}

async function exchangeRefreshToken(
  db: Db, sealed: SealedResponses, req: Request, res: Response
): Promise<void> {
  const { refresh_token, client_id, resource, scope } = req.body ?? {};

  if (typeof client_id !== 'string' || client_id.length === 0) {
    return fail(res, 400, 'invalid_request', 'client_id is required.');
  }

  const presentedJkt = await proofOf(req, res);
  if (presentedJkt === false) return;

  // Keyed by the presented token, and bound to the client, so only the same
  // client presenting the same token inside the window gets the copy.
  const sealKey = typeof refresh_token === 'string' ? `${client_id}:${tokenDigest(refresh_token)}` : '';

  const outcome = await rotateRefresh(db, refresh_token, {
    clientId: client_id,
    resource,
    scope,
    graceSeconds: REFRESH_GRACE_SECONDS,
    presentedJkt,
    seal: (issued) => sealed.seal(sealKey, tokenBody(issued), REFRESH_GRACE_SECONDS)
  });

  switch (outcome.kind) {
    case 'rotated':
      return respond(res, outcome.issued);
    case 'replay': {
      // The same request again, inside the window: give back exactly what the
      // first one received. If that copy is gone (a restart), refuse without
      // revoking — the caller already holds the tokens, or will sign in again.
      const body = sealed.unseal(sealKey);
      if (!body) return fail(res, 400, 'invalid_grant', 'This refresh token was already used.');
      return sendTokens(res, body);
    }
    case 'theft':
      return fail(res, 400, 'invalid_grant', 'This refresh token was already used. The grant has been revoked.');
    case 'invalid_target':
      return fail(res, 400, 'invalid_target', 'resource does not match this grant.');
    case 'invalid_scope':
      return fail(res, 400, 'invalid_scope', 'A refresh cannot request scopes beyond the original grant.');
    case 'invalid_dpop':
      return fail(res, 400, 'invalid_dpop_proof', 'This refresh token is bound to a DPoP key; prove possession of it.');
    case 'invalid':
      return fail(res, 400, 'invalid_grant', {
        unknown: 'Unknown refresh token.',
        dead: 'This refresh token is no longer valid.',
        wrong_client: 'This refresh token was issued to a different client.'
      }[outcome.reason]);
  }
}

function tokenBody(tokens: IssuedTokens) {
  return {
    access_token: tokens.accessToken,
    token_type: tokens.tokenType,
    expires_in: tokens.expiresIn,
    ...(tokens.refreshToken ? { refresh_token: tokens.refreshToken } : {}),
    scope: tokens.scope
  };
}

function respond(res: Response, tokens: IssuedTokens): void {
  sendTokens(res, tokenBody(tokens));
}

function sendTokens(res: Response, body: unknown): void {
  res.status(200)
    .set('Cache-Control', 'no-store')
    .set('Pragma', 'no-cache')
    .json(body);
}

export const TOKEN_RESOURCE = RESOURCE_URI;
