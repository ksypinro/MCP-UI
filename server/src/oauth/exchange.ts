/**
 * RFC 8693 token exchange: an edge credential in, a one-minute internal token
 * out. Architecture section 7.6.
 *
 * Neither adapter ever forwards the credential it received. Before calling
 * the Device Service it exchanges it for a token whose audience is the Device
 * Service alone, narrowed to the single scope the operation needs, naming the
 * workload acting for the person (`act`) and bound to that workload (`cnf`).
 * A stolen internal token is therefore good for one minute, one scope, and
 * one caller.
 *
 * In one process this is a function call. Split into processes, the
 * authorization server serves the same check, claims and signature on its
 * internal mTLS listener (split/servers.ts).
 */

import { randomBytes } from 'node:crypto';
import type { Queryable } from '../db/index.ts';
import { AppError } from '../errors.ts';
import { keys } from '../security/keys.ts';
import { workloadUri, type Workload } from '../security/workload.ts';
import { API_RESOURCE, ISSUER, type Scope } from './config.ts';
import { verifyOAuthAccessToken } from './verify.ts';

export const INTERNAL_AUDIENCE = 'https://device.internal';
export const INTERNAL_TOKEN_TTL_SECONDS = 60;

export interface ExchangeRequest {
  workload: Workload;
  /** The credential the edge adapter received and has already verified. */
  subjectToken: string;
  /** Exactly one scope: what this operation needs, and nothing else. */
  scope: Scope;
}

export interface ExchangedToken {
  token: string;
  expiresIn: number;
  grantId: string;
}

interface Subject {
  accountId: string;
  clientId: string;
  grantId: string;
  channel: 'mcp' | 'native';
  authMethod: string;
  expiresIn: number;
}

/**
 * Which subject a workload may present, and what it may become.
 *
 * The MCP adapter exchanges only OAuth access tokens issued for the MCP
 * resource, and only for a scope the token already holds. The REST gateway
 * exchanges only the app's credentials: OAuth tokens issued for the REST API.
 * Neither may present the other's.
 */
async function resolveSubject(db: Queryable, request: ExchangeRequest): Promise<Subject> {
  if (request.workload.name === 'mcp-rs') {
    const verified = await verifyOAuthAccessToken(db, request.subjectToken, [request.scope]);
    if (!verified.ok) {
      throw verified.reason === 'insufficient_scope'
        ? new AppError('INSUFFICIENT_SCOPE')
        : new AppError('UNAUTHENTICATED', 'Sign in to continue.');
    }
    return {
      accountId: verified.accountId, clientId: verified.clientId, grantId: verified.grantId,
      channel: 'mcp', authMethod: 'oauth', expiresIn: verified.expiresIn
    };
  }

  // The app's OAuth token, audience the REST API.
  const oauth = await verifyOAuthAccessToken(db, request.subjectToken, [request.scope], { audience: API_RESOURCE });
  if (oauth.ok) {
    return {
      accountId: oauth.accountId, clientId: oauth.clientId, grantId: oauth.grantId,
      channel: 'native', authMethod: oauth.cnfJkt ? 'oauth-dpop' : 'oauth', expiresIn: oauth.expiresIn
    };
  }
  throw oauth.reason === 'insufficient_scope'
    ? new AppError('INSUFFICIENT_SCOPE')
    : new AppError('UNAUTHENTICATED', 'Sign in to continue.');
}

const b64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

export async function exchangeToken(db: Queryable, request: ExchangeRequest): Promise<ExchangedToken> {
  const subject = await resolveSubject(db, request);
  // Never outlive the credential it was exchanged from.
  const expiresIn = Math.min(INTERNAL_TOKEN_TTL_SECONDS, subject.expiresIn);
  if (expiresIn <= 0) throw new AppError('UNAUTHENTICATED', 'Sign in to continue.');

  const [signing] = keys().signingKeys;
  if (!signing) throw new Error('No signing key configured');
  const now = Math.floor(Date.now() / 1000);

  // Assembled by hand rather than with jose's SignJWT, because the private key
  // may live in a KMS: all this process can do is ask for a signature.
  const header = { alg: 'ES256', typ: 'at+jwt', kid: signing.kid };
  const claims = {
    iss: ISSUER,
    aud: INTERNAL_AUDIENCE,
    sub: subject.accountId,
    iat: now,
    exp: now + expiresIn,
    jti: `tb_${randomBytes(12).toString('base64url')}`,
    client_id: subject.clientId,
    grant_id: subject.grantId,
    scope: request.scope,
    channel: subject.channel,
    auth_method: subject.authMethod,
    act: { sub: workloadUri(request.workload) },
    cnf: request.workload.cnf
  };
  const signingInput = `${b64url(header)}.${b64url(claims)}`;
  const signature = await signing.sign(Buffer.from(signingInput));
  const token = `${signingInput}.${signature.toString('base64url')}`;

  return { token, expiresIn, grantId: subject.grantId };
}
