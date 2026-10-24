/**
 * The edge processes' view of the authorization server and the Device
 * Service in profile M: the same interfaces as in one process, over mTLS.
 * Plan 4.7.
 *
 * Introspection answers are cached briefly (at most 30 seconds, never past
 * the token's own expiry), keyed by a hash of the token, and dropped the
 * moment a revocation event names their grant, account or client. Without
 * the revocation bus (REDIS_URL) a revoked token could therefore keep working
 * at an edge for up to the cache lifetime; profile M requires Redis for that
 * reason.
 */

import { createHash } from 'node:crypto';
import type { Agent } from 'node:https';
import { AppError, ERROR_STATUS, type ErrorCode } from '../errors.ts';
import type { Account, Device } from '../domain/types.ts';
import type { VerifiedSession } from '../domain/sessions.ts';
import type { DeviceService } from '../device-service/service.ts';
import { InternalTokenRefused } from '../device-service/verify.ts';
import type { Exchanger } from '../exchange-client.ts';
import type { Scope } from '../oauth/config.ts';
import type { VerifiedToken } from '../oauth/verify.ts';
import type { RevocationEvent, RevocationHub } from '../revocation.ts';
import type { TokenVerifier } from '../security/verifier.ts';
import { metrics } from '../observability/metrics.ts';
import { postJson, type JsonResponse } from './tls.ts';

const CACHE_SECONDS = 30;

/** Any failure to reach a peer is a 503: nothing is allowed through on a guess. */
async function call(agent: Agent, url: string, body: unknown, headers?: Record<string, string>): Promise<JsonResponse> {
  try {
    return await postJson(agent, url, body, headers);
  } catch {
    throw new AppError('SERVICE_UNAVAILABLE');
  }
}

interface Introspected {
  accountId: string; clientId: string; grantId: string; scopes: Scope[]; cnfJkt: string | null; expiresAt: number;
}

export function remoteVerifier(authUrl: string, agent: Agent, revocations: RevocationHub): TokenVerifier {
  const cache = new Map<string, Introspected & { cachedUntil: number }>();
  const accounts = new Map<string, Account>();

  revocations.subscribe((event: RevocationEvent) => {
    for (const [key, entry] of cache) {
      if ((event.type === 'grant.revoked' && entry.grantId === event.grantId)
        || (event.type === 'account.revoked' && entry.accountId === event.accountId)
        || (event.type === 'client.blocked' && entry.clientId === event.clientId)) cache.delete(key);
    }
  });

  async function introspect(token: string): Promise<Introspected | null> {
    const key = createHash('sha256').update(token).digest('base64url');
    const now = Date.now();
    const cached = cache.get(key);
    if (cached && cached.cachedUntil > now && cached.expiresAt > now) {
      metrics.inc('introspection_cache', { result: 'hit' });
      return cached;
    }
    metrics.inc('introspection_cache', { result: 'miss' });
    const { status, body } = await call(agent, `${authUrl}/introspect`, { token });
    if (status !== 200) throw new AppError('SERVICE_UNAVAILABLE');
    if (!body?.active) {
      cache.delete(key);
      return null;
    }
    const entry: Introspected = {
      accountId: body.accountId, clientId: body.clientId, grantId: body.grantId, scopes: body.scopes,
      cnfJkt: body.cnfJkt ?? null, expiresAt: now + body.expiresIn * 1000
    };
    cache.set(key, { ...entry, cachedUntil: now + Math.min(CACHE_SECONDS, body.expiresIn) * 1000 });
    if (cache.size > 50_000) for (const [k, v] of cache) if (v.cachedUntil <= now) cache.delete(k);
    return entry;
  }

  return {
    async oauth(token, scopes): Promise<VerifiedToken> {
      // The audience is the authorization server's to decide: it answers each
      // edge only about tokens for that edge's own resource.
      if (typeof token !== 'string' || token.length === 0 || token.length > 512) return { ok: false, reason: 'invalid_token' };
      const found = await introspect(token);
      if (!found) return { ok: false, reason: 'invalid_token' };
      const missing = scopes.filter((scope) => !found.scopes.includes(scope));
      if (missing.length > 0) {
        return { ok: false, reason: 'insufficient_scope', grantId: found.grantId, granted: found.scopes, required: scopes };
      }
      return {
        ok: true, accountId: found.accountId, clientId: found.clientId, grantId: found.grantId, scopes: found.scopes,
        expiresIn: Math.max(0, Math.floor((found.expiresAt - Date.now()) / 1000)), cnfJkt: found.cnfJkt
      };
    },

    async session(token): Promise<VerifiedSession | null> {
      if (!token) return null;
      const { status, body } = await call(agent, `${authUrl}/introspect`, { token, kind: 'session' });
      if (status !== 200) throw new AppError('SERVICE_UNAVAILABLE');
      return body?.active
        ? { accountId: body.accountId, sessionId: body.sessionId, familyId: body.familyId, expiresIn: body.expiresIn }
        : null;
    },

    async account(accountId): Promise<Account | null> {
      const known = accounts.get(accountId);
      if (known) return known;
      const { status, body } = await call(agent, `${authUrl}/account`, { accountId });
      if (status !== 200) throw new AppError('SERVICE_UNAVAILABLE');
      if (body?.account) {
        accounts.set(accountId, body.account);
        if (accounts.size > 10_000) accounts.clear();
      }
      return body?.account ?? null;
    }
  };
}

export function remoteExchanger(authUrl: string, agent: Agent): Exchanger {
  return async (subjectToken, scope) => {
    const { status, body } = await call(agent, `${authUrl}/token-exchange`, { subject_token: subjectToken, scope });
    if (status === 200 && typeof body?.access_token === 'string') {
      return { token: body.access_token, expiresIn: body.expires_in };
    }
    throw remoteError(status, body);
  };
}

function remoteError(status: number, body: any): Error {
  if (status === 401 && body?.error === 'internal_token_refused') return new InternalTokenRefused('refused by the Device Service');
  const code = body?.error?.code as ErrorCode | undefined;
  if (code && code in ERROR_STATUS) return new AppError(code, body.error.message, body.error.field);
  return new AppError('SERVICE_UNAVAILABLE');
}

export function remoteDeviceService(deviceUrl: string, agent: Agent): DeviceService {
  const invoke = async <T>(operation: string, token: string, requestId: string, extra: Record<string, unknown>): Promise<T> => {
    const { status, body } = await call(agent, `${deviceUrl}/devices/${operation}`, { requestId, ...extra }, {
      authorization: `Bearer ${token}`
    });
    if (status === 200) return body as T;
    throw remoteError(status, body);
  };
  // The peer workload is not sent: the Device Service learns it from the
  // certificate on the connection, which is the point.
  return {
    list: async (token, _peer, requestId) => (await invoke<{ devices: Device[] }>('list', token, requestId, {})).devices,
    get: async (token, _peer, requestId, deviceId) => (await invoke<{ device: Device }>('get', token, requestId, { deviceId })).device,
    add: async (token, _peer, requestId, input) => (await invoke<{ device: Device }>('add', token, requestId, { input })).device,
    control: async (token, _peer, requestId, input) => (await invoke<{ device: Device }>('control', token, requestId, { input })).device
  };
}
