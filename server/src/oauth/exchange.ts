/**
 * RFC 8693 token exchange: an edge credential in, a one-minute internal token
 * out. Plan 2.3, architecture section 7.6.
 *
 * Neither adapter ever forwards the credential it received. Before calling
 * the Device Service it exchanges it for a token whose audience is the Device
 * Service alone, narrowed to the single scope the operation needs, naming the
 * workload acting for the person (`act`) and bound to that workload (`cnf`).
 * A stolen internal token is therefore good for one minute, one scope, and
 * one caller.
 *
 * In one process this is a function call. It is the same check, the same
 * claims and the same signature that an internal HTTP endpoint will serve
 * when the components are split.
 */

import { randomBytes } from 'node:crypto';
import { SignJWT, importJWK } from 'jose';
import type { Queryable } from '../db/index.ts';
import { AppError } from '../errors.ts';
import { keys } from '../security/keys.ts';
import { workloadUri, type Workload } from '../security/workload.ts';
import { verifyAccessToken } from '../domain/sessions.ts';
import { ISSUER, type Scope } from './config.ts';
import { verifyOAuthAccessToken } from './verify.ts';

export const INTERNAL_AUDIENCE = 'https://device.internal';
export const INTERNAL_TOKEN_TTL_SECONDS = 60;
/** The client the first-party app is recorded as. */
export const FIRST_PARTY_CLIENT_ID = 'iot-switch-ios';

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
 * exchanges only first-party session tokens. Neither may present the other's.
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

  const session = await verifyAccessToken(db, request.subjectToken);
  if (!session) throw new AppError('UNAUTHENTICATED', 'Sign in to continue.');
  // A first-party session holds every device scope.
  return {
    accountId: session.accountId, clientId: FIRST_PARTY_CLIENT_ID, grantId: session.familyId,
    channel: 'native', authMethod: 'first-party-session', expiresIn: session.expiresIn
  };
}

export async function exchangeToken(db: Queryable, request: ExchangeRequest): Promise<ExchangedToken> {
  const subject = await resolveSubject(db, request);
  // Never outlive the credential it was exchanged from.
  const expiresIn = Math.min(INTERNAL_TOKEN_TTL_SECONDS, subject.expiresIn);
  if (expiresIn <= 0) throw new AppError('UNAUTHENTICATED', 'Sign in to continue.');

  const [signing] = keys().signingKeys;
  if (!signing) throw new Error('No signing key configured');
  const key = await importJWK(signing.privateJwk as Parameters<typeof importJWK>[0], 'ES256');
  const now = Math.floor(Date.now() / 1000);

  const token = await new SignJWT({
    client_id: subject.clientId,
    grant_id: subject.grantId,
    scope: request.scope,
    channel: subject.channel,
    auth_method: subject.authMethod,
    act: { sub: workloadUri(request.workload) },
    cnf: { jkt: request.workload.jkt }
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid: signing.kid })
    .setIssuer(ISSUER)
    .setAudience(INTERNAL_AUDIENCE)
    .setSubject(subject.accountId)
    .setIssuedAt(now)
    .setExpirationTime(now + expiresIn)
    .setJti(`tb_${randomBytes(12).toString('base64url')}`)
    .sign(key);

  return { token, expiresIn, grantId: subject.grantId };
}
