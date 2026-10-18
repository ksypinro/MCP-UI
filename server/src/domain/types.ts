export type DeviceState = 'on' | 'off';

/**
 * A verified caller. The device service takes this rather than an HTTP
 * request, so the MCP adapter in phase 4 can call the same functions directly
 * and still carry the identity the transport verified — spec section 3.
 *
 * accountId is never accepted from a client payload. It comes from a
 * validated credential, or the call does not happen.
 */
export interface Identity {
  accountId: string;
  /** Recorded on every mutation so isolation can be evidenced later. */
  channel: 'native' | 'mcp' | 'internal';
  requestId?: string;
  /** The OAuth client, or the first-party app, the person acted through. */
  clientId?: string;
  /** The grant (OAuth) or session family (first-party) behind the request. */
  grantId?: string;
  /** The workload that called the Device Service on the person's behalf. */
  via?: string;
  /** How the person proved who they are, for audit. */
  authMethod?: string;
}

/**
 * Who is calling an edge adapter (the MCP endpoint or the REST API).
 *
 * A discriminated type rather than `Identity | null`, so a handler for a
 * protected operation cannot be written against an anonymous caller without
 * the compiler noticing — and there is no fallback identity to fail open to.
 */
export type Caller = AnonymousCaller | VerifiedCaller;

export interface AnonymousCaller {
  kind: 'anonymous';
  requestId: string;
}

export interface VerifiedCaller {
  kind: 'verified';
  accountId: string;
  clientId: string;
  grantId: string;
  channel: 'native' | 'mcp';
  scopes: readonly string[];
  requestId: string;
  /**
   * The credential the caller presented, kept only for this request so the
   * adapter can exchange it for an internal token. Never logged, never
   * returned, never forwarded.
   */
  credential: string;
}

/** The client-visible device shape from spec section 4.2. */
export interface Device {
  id: string;
  name: string;
  state: DeviceState;
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface Account {
  id: string;
  username: string;
  createdAt: string;
}
