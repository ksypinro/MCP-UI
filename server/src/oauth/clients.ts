/**
 * Resolving a `client_id` to the redirect URIs it is allowed to use.
 *
 * Two mechanisms, in the priority the 2026-07-28 authorization specification
 * sets: Client ID Metadata Documents first, Dynamic Client Registration as a
 * fallback for hosts that do not support CIMD. DCR is deprecated in that
 * revision but retained, and ChatGPT still uses it.
 */

import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { randomBytes } from 'node:crypto';
import type { Db, Queryable } from '../db/index.ts';
import { MAX_REGISTERED_CLIENTS } from './config.ts';

export interface ResolvedClient {
  clientId: string;
  redirectUris: string[];
  /**
   * What the consent screen shows.
   *
   * For CIMD this is the host of the client_id URL, never the document's
   * `client_name`: the document is self-asserted, so its name is whatever the
   * client felt like claiming, while the host is what the client had to
   * control in order to serve it.
   */
  displayHost: string;
}

const CIMD_TIMEOUT_MS = 5_000;
const CIMD_MAX_BYTES = 64 * 1024;

/* ------------------------------------------------------------------ SSRF */

/**
 * A client_id is a URL supplied by whoever is starting an authorization, and
 * we fetch it. Without this check that is a request forgery primitive pointed
 * at whatever the server can reach — cloud metadata endpoints being the
 * classic target.
 */
function isPrivateAddress(address: string): boolean {
  if (isIP(address) === 6) {
    const normalized = address.toLowerCase();
    if (normalized === '::1' || normalized === '::') return true;
    if (normalized.startsWith('fe80') || normalized.startsWith('fc') || normalized.startsWith('fd')) {
      return true;
    }
    // IPv4-mapped, e.g. ::ffff:169.254.169.254
    const mapped = normalized.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return mapped?.[1] ? isPrivateAddress(mapped[1]) : false;
  }

  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) return true;
  const [a = 0, b = 0] = parts;

  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;       // link-local, incl. 169.254.169.254
  if (a === 100 && b >= 64 && b <= 127) return true; // carrier-grade NAT
  if (a >= 224) return true;                      // multicast and reserved
  return false;
}

async function resolvesToPublicAddress(hostname: string): Promise<boolean> {
  if (isIP(hostname)) return !isPrivateAddress(hostname);
  try {
    const addresses = await lookup(hostname, { all: true });
    // Every address must be public: a name that resolves to both is still a
    // way to reach the private one.
    return addresses.length > 0 && addresses.every((entry) => !isPrivateAddress(entry.address));
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------ CIMD */

interface ClientIdMetadataDocument {
  client_id?: unknown;
  client_name?: unknown;
  redirect_uris?: unknown;
}

async function resolveMetadataDocument(clientId: string): Promise<ResolvedClient | null> {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:') return null;
  if (!(await resolvesToPublicAddress(url.hostname))) return null;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CIMD_TIMEOUT_MS);
  try {
    const response = await fetch(clientId, {
      headers: { accept: 'application/json' },
      signal: controller.signal,
      // A redirect could land on a host we never checked. Refuse rather than
      // re-run the whole validation on a moving target.
      redirect: 'error'
    });
    if (!response.ok) return null;

    const body = await response.text();
    if (body.length > CIMD_MAX_BYTES) return null;

    const document = JSON.parse(body) as ClientIdMetadataDocument;

    // The document must be self-referential, or anyone could host a document
    // claiming to be someone else's client_id.
    if (document.client_id !== clientId) return null;

    const redirectUris = Array.isArray(document.redirect_uris)
      ? document.redirect_uris.filter((entry): entry is string => typeof entry === 'string')
      : [];
    if (redirectUris.length === 0) return null;

    return { clientId, redirectUris, displayHost: url.host };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/* ------------------------------------------------------------------- DCR */

export async function registerClient(
  db: Db,
  redirectUris: string[],
  clientName: string | undefined
): Promise<{ clientId: string } | { error: string }> {
  const valid = redirectUris.filter(isRegisterableRedirectUri);
  if (valid.length === 0) return { error: 'invalid_redirect_uri' };

  const { rows } = await db.query<{ n: number }>('SELECT count(*)::int AS n FROM oauth_clients');
  if ((rows[0]?.n ?? 0) >= MAX_REGISTERED_CLIENTS) return { error: 'registration_closed' };

  const clientId = `client_${randomBytes(16).toString('base64url')}`;
  await db.query(
    `INSERT INTO oauth_clients (client_id, client_name, redirect_uris, source)
     VALUES ($1, $2, $3, 'dcr')`,
    [clientId, clientName ?? null, JSON.stringify(valid)]
  );
  return { clientId };
}

/**
 * https, loopback http, or a private-use scheme in the reverse-DNS form native
 * apps use (`com.example.app:/callback`).
 *
 * The previous form of this check ended in `protocol !== 'http:'`, which
 * accepted anything that was not plain HTTP — `javascript:` and `data:`
 * included. A registered `javascript:` redirect is a stored cross-site
 * scripting payload that this server would then send a live authorization
 * code to.
 */
const FORBIDDEN_SCHEMES = new Set([
  'javascript:', 'data:', 'vbscript:', 'file:', 'blob:', 'about:', 'filesystem:'
]);

export function isRegisterableRedirectUri(uri: string): boolean {
  if (typeof uri !== 'string' || uri.length === 0 || uri.length > 2048) return false;
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }
  if (parsed.hash) return false;
  if (FORBIDDEN_SCHEMES.has(parsed.protocol.toLowerCase())) return false;
  if (parsed.protocol === 'https:') return true;
  if (parsed.protocol === 'http:') return isLoopback(parsed);
  // A private-use scheme must be reverse-DNS, per RFC 8252 section 7.1.
  return /^[a-z][a-z0-9+.-]*\.[a-z0-9+.-]+:$/i.test(parsed.protocol);
}

async function resolveRegisteredClient(db: Queryable, clientId: string): Promise<ResolvedClient | null> {
  const { rows } = await db.query<{ client_id: string; redirect_uris: string }>(
    'SELECT client_id, redirect_uris FROM oauth_clients WHERE client_id = $1',
    [clientId]
  );
  const row = rows[0];
  if (!row) return null;

  const redirectUris = JSON.parse(row.redirect_uris) as string[];
  // A registered client's identity is the opaque id it was issued. There is no
  // verified name to show, so the consent screen shows the redirect host.
  let displayHost = clientId;
  try {
    displayHost = new URL(redirectUris[0] ?? '').host || clientId;
  } catch { /* keep the id */ }

  return { clientId, redirectUris, displayHost };
}

/** CIMD when the id is an HTTPS URL, otherwise a registered client. */
export async function resolveClient(db: Queryable, clientId: unknown): Promise<ResolvedClient | null> {
  if (typeof clientId !== 'string' || clientId.length === 0 || clientId.length > 2048) return null;
  if (clientId.startsWith('https://')) return resolveMetadataDocument(clientId);
  return resolveRegisteredClient(db, clientId);
}

/* -------------------------------------------------------- redirect_uri */

function isLoopback(url: URL): boolean {
  const host = url.hostname.toLowerCase();
  return host === '127.0.0.1' || host === '[::1]' || host === '::1' || host === 'localhost';
}

/**
 * Exact match, except for loopback, where the port is ignored.
 *
 * RFC 8252 section 7.3: a native app binds an ephemeral port at runtime and
 * cannot know it in advance, so it registers one loopback URI and listens
 * wherever it can.
 */
export function redirectUriAllowed(requested: string, allowed: string[]): boolean {
  let candidate: URL;
  try {
    candidate = new URL(requested);
  } catch {
    return false;
  }
  if (candidate.hash) return false; // RFC 6749: no fragment in a redirect URI

  return allowed.some((entry) => {
    if (entry === requested) return true;
    try {
      const known = new URL(entry);
      if (!isLoopback(candidate) || !isLoopback(known)) return false;
      return candidate.protocol === known.protocol && candidate.pathname === known.pathname;
    } catch {
      return false;
    }
  });
}
