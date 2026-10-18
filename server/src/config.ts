export const PORT = Number(process.env.PORT ?? 4000);

/**
 * Public origin, no trailing slash.
 *
 * Everything in OAuth depends on this being stable and identical to the URL a
 * host was given: it becomes the issuer, the RFC 8707 resource indicator and
 * the token audience. Hosts cache discovery documents globally by URL for
 * minutes, so changing it mid-session produces stale-cache behaviour that
 * reads like a code bug and is not one.
 */
export const BASE_URL = (process.env.BASE_URL ?? `http://localhost:${PORT}`).replace(/\/$/, '');

/**
 * The three public origins: the authorization server, the MCP endpoint and
 * the REST API. Each defaults to BASE_URL, which keeps local development on
 * one origin.
 *
 * In production they are separate hostnames. The authorization server's
 * cookies are then never sent to, or readable by, the other two, and its
 * pages can carry a strict CSP and framing policy without affecting anything
 * else. All three must be final before launch: the issuer is what hosts key
 * their stored client registration by, so changing it later disconnects
 * every one of them.
 */
const origin = (value: string | undefined) => (value ?? BASE_URL).replace(/\/$/, '');
export const AUTH_BASE_URL = origin(process.env.AUTH_BASE_URL);
export const MCP_BASE_URL = origin(process.env.MCP_BASE_URL);
export const API_BASE_URL = origin(process.env.API_BASE_URL);

/** True when the three surfaces share one origin, as in local development. */
export const SINGLE_ORIGIN = AUTH_BASE_URL === MCP_BASE_URL && MCP_BASE_URL === API_BASE_URL;

/** PGlite persists here. See README for why this is not a real server yet. */
export const DATABASE_PATH = process.env.DATABASE_PATH ?? './.data';

export const ACCESS_TOKEN_TTL_SECONDS = Number(process.env.ACCESS_TOKEN_TTL_SECONDS ?? 900);
export const REFRESH_TOKEN_TTL_SECONDS = Number(process.env.REFRESH_TOKEN_TTL_SECONDS ?? 2_592_000);

/** Spec section 4.3. Creation beyond this fails with DEVICE_LIMIT_REACHED. */
export const MAX_DEVICES_PER_ACCOUNT = 100;

export const USERNAME_MIN = 3;
export const USERNAME_MAX = 32;
export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 128;
export const DEVICE_NAME_MAX = 64;
