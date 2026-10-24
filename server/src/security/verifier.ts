/**
 * How an edge adapter learns who a caller is. Plan 4.7.
 *
 * In one process that is a database lookup. Split into processes (profile M),
 * the MCP resource server and the API gateway hold no database credentials at
 * all: they ask the authorization server, over mTLS, by token introspection
 * (split/remote.ts). Both implement this interface, so the gate and the
 * middleware are the same code either way.
 */

import type { Db } from '../db/index.ts';
import type { Account } from '../domain/types.ts';
import { getAccount } from '../domain/accounts.ts';
import { verifyAccessToken, type VerifiedSession } from '../domain/sessions.ts';
import type { Scope } from '../oauth/config.ts';
import { verifyOAuthAccessToken, type VerifiedToken } from '../oauth/verify.ts';

export interface TokenVerifier {
  /** An OAuth access token, for `audience` (the MCP resource unless given). */
  oauth(token: string | null | undefined, scopes: Scope[], options?: { audience?: string }): Promise<VerifiedToken>;
  /** A legacy first-party session token. */
  session(token: string | null): Promise<VerifiedSession | null>;
  /** The account behind a caller that was just verified. */
  account(accountId: string): Promise<Account | null>;
}

export function localVerifier(db: Db): TokenVerifier {
  return {
    oauth: (token, scopes, options) => verifyOAuthAccessToken(db, token, scopes, options),
    session: (token) => verifyAccessToken(db, token),
    account: (accountId) => getAccount(db, accountId)
  };
}
