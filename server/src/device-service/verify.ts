/**
 * What the Device Service checks before it does anything. Plan 2.4,
 * architecture section 8.7.
 *
 * It trusts no caller and no request field. It accepts an internal token
 * only if all of this holds:
 *
 * - signed ES256 by a key the authorization server publishes, with
 *   `typ: at+jwt` — so an ID token or a token of another kind is refused,
 *   and `alg: none` or an HMAC key-confusion attempt never verifies;
 * - issued by this authorization server, for the Device Service audience,
 *   unexpired (30 s of clock tolerance);
 * - acting through the workload presenting it (`act.sub`) and bound to it
 *   (`cnf.jkt`), so a token taken from one adapter is useless to another;
 * - carrying exactly the scope the operation needs.
 *
 * The account comes from `sub` and nowhere else.
 */

import { createLocalJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { ISSUER } from '../oauth/config.ts';
import { INTERNAL_AUDIENCE } from '../oauth/exchange.ts';
import { publicJwks } from '../oauth/jwks.ts';
import { workloadUri, type Workload } from '../security/workload.ts';
import type { Identity } from '../domain/types.ts';

/**
 * An internal token the Device Service will not accept. Never shown to a
 * person: the adapter re-exchanges once and, if it happens again, reports an
 * internal error, because it means the adapter or the keys are wrong.
 */
export class InternalTokenRefused extends Error {
  constructor(reason: string) {
    super(`internal token refused: ${reason}`);
    this.name = 'InternalTokenRefused';
  }
}

interface InternalClaims extends JWTPayload {
  scope?: unknown;
  client_id?: unknown;
  grant_id?: unknown;
  channel?: unknown;
  auth_method?: unknown;
  act?: { sub?: unknown };
  cnf?: { jkt?: unknown };
}

export async function verifyInternalToken(
  token: string, peer: Workload, requiredScope: string, requestId: string
): Promise<Identity> {
  let payload: InternalClaims;
  try {
    ({ payload } = await jwtVerify<InternalClaims>(token, createLocalJWKSet(publicJwks() as never), {
      issuer: ISSUER,
      audience: INTERNAL_AUDIENCE,
      typ: 'at+jwt',
      algorithms: ['ES256'],
      clockTolerance: 30,
      requiredClaims: ['sub', 'exp', 'iat', 'jti']
    }));
  } catch (error) {
    throw new InternalTokenRefused((error as Error).message);
  }

  if (payload.act?.sub !== workloadUri(peer)) throw new InternalTokenRefused('act does not name the caller');
  if (payload.cnf?.jkt !== peer.jkt) throw new InternalTokenRefused('not bound to the caller');
  if (payload.scope !== requiredScope) throw new InternalTokenRefused(`scope ${requiredScope} required`);
  if (typeof payload.sub !== 'string' || typeof payload.client_id !== 'string'
      || typeof payload.grant_id !== 'string') {
    throw new InternalTokenRefused('missing subject claims');
  }
  const channel = payload.channel === 'native' ? 'native' : payload.channel === 'mcp' ? 'mcp' : null;
  if (!channel) throw new InternalTokenRefused('unknown channel');

  return {
    accountId: payload.sub,
    channel,
    requestId,
    clientId: payload.client_id,
    grantId: payload.grant_id,
    via: payload.act.sub as string,
    authMethod: typeof payload.auth_method === 'string' ? payload.auth_method : 'unknown'
  };
}
