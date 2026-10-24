/**
 * The iOS app as a test client of the REST API: a grant for the first-party
 * client, tokens bound to a DPoP key, and every request carrying a fresh
 * proof from that key, as the app's Secure Enclave key does.
 */

import { randomBytes } from 'node:crypto';
import type { Db } from '../src/db/index.ts';
import { API_BASE_URL } from '../src/config.ts';
import { API_RESOURCE, FIRST_PARTY_CLIENT_ID } from '../src/oauth/config.ts';
import { establishGrant } from '../src/oauth/store.ts';
import { DpopKey } from './dpop-helpers.ts';

export const APP_SCOPE = 'devices:read devices:control devices:create offline_access';

export interface AppResponse<T = Record<string, any>> {
  status: number;
  body: T & { error?: { code: string; message: string; requestId: string; field?: string } };
  requestId: string | null;
  headers: Headers;
}

export class AppClient {
  readonly base: string;
  readonly key: DpopKey;
  readonly accessToken: string;
  readonly refreshToken: string | null;

  constructor(base: string, key: DpopKey, accessToken: string, refreshToken: string | null) {
    this.base = base;
    this.key = key;
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
  }

  /** One API request, signed with a fresh proof for exactly this method and path. */
  async call<T = Record<string, any>>(
    method: string,
    path: string,
    options: { body?: unknown; raw?: string; headers?: Record<string, string> } = {}
  ): Promise<AppResponse<T>> {
    const proof = await this.key.proof({ htm: method, htu: `${API_BASE_URL}${path}`, accessToken: this.accessToken });
    const response = await fetch(this.base + path, {
      method,
      headers: {
        'content-type': 'application/json',
        authorization: `DPoP ${this.accessToken}`,
        dpop: proof,
        ...options.headers
      },
      body: options.raw ?? (options.body === undefined ? undefined : JSON.stringify(options.body))
    });
    const text = await response.text();
    return {
      status: response.status,
      body: text ? JSON.parse(text) : {},
      requestId: response.headers.get('x-request-id'),
      headers: response.headers
    };
  }
}

/**
 * The app, signed in as `accountId`: the grant the authorization server
 * creates at the end of the app's sign-in, without walking the browser pages.
 * The sign-in itself is covered end to end in first-party.test.ts.
 */
export async function appClientFor(db: Db, base: string, accountId: string, scope = APP_SCOPE): Promise<AppClient> {
  const key = await DpopKey.create();
  const tokens = await establishGrant(db, {
    code: `unused-${randomBytes(6).toString('hex')}`, accountId, clientId: FIRST_PARTY_CLIENT_ID,
    resource: API_RESOURCE, scope, withRefresh: true, dpopJkt: key.jkt
  });
  return new AppClient(base, key, tokens.accessToken, tokens.refreshToken);
}

/** An unauthenticated request to the API, or one with an arbitrary Authorization header. */
export async function anonymous(
  base: string, method: string, path: string, options: { authorization?: string; body?: unknown } = {}
): Promise<AppResponse> {
  const response = await fetch(base + path, {
    method,
    headers: {
      'content-type': 'application/json',
      ...(options.authorization ? { authorization: options.authorization } : {})
    },
    body: options.body === undefined ? undefined : JSON.stringify(options.body)
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : {}, requestId: response.headers.get('x-request-id'), headers: response.headers };
}
