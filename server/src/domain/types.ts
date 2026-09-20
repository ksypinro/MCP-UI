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
