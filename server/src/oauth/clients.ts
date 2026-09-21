/**
 * Resolving a `client_id` to the redirect URIs it is allowed to use.
 *
 * Two mechanisms, in the priority the 2026-07-28 authorization specification
 * sets: Client ID Metadata Documents first, Dynamic Client Registration as a
 * fallback for hosts that do not support CIMD. DCR is deprecated in that
 * revision but retained, and ChatGPT still uses it.
 */

import { lookup } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
import { randomBytes } from 'node:crypto';
import type { Db, Queryable } from '../db/index.ts';
import { MAX_REGISTERED_CLIENTS, UNUSED_CLIENT_TTL_SECONDS } from './config.ts';

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

/**
 * Resolves a hostname and returns the address to connect to, or null if any of
 * them is private.
 *
 * The address is returned rather than a boolean because the caller pins the
 * connection to it. Checking a hostname and then letting the HTTP client
 * resolve it again is open to DNS rebinding: an attacker serving a short TTL
 * answers the check with a public address and the connection with an internal
 * one.
 */
async function resolvePinnedAddress(
  hostname: string
): Promise<{ address: string; family: number } | null> {
  if (isIP(hostname)) {
    return isPrivateAddress(hostname)
      ? null
      : { address: hostname, family: isIP(hostname) };
  }
  try {
    const addresses = await lookup(hostname, { all: true });
    if (addresses.length === 0) return null;
    // Every address must be public: a name resolving to both is still a way
    // to reach the private one.
    if (addresses.some((entry) => isPrivateAddress(entry.address))) return null;
    const chosen = addresses[0];
    return chosen ? { address: chosen.address, family: chosen.family } : null;
  } catch {
    return null;
  }
}

/**
 * GET over HTTPS with the connection pinned to `pinned`, while TLS still
 * validates against the real hostname via SNI.
 */
function fetchPinned(
  url: URL, pinned: { address: string; family: number }
): Promise<{ status: number; body: string } | null> {
  return new Promise((resolve) => {
    const req = httpsRequest(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || 443,
        path: `${url.pathname}${url.search}`,
        method: 'GET',
        headers: { accept: 'application/json', host: url.host },
        servername: url.hostname,
        timeout: CIMD_TIMEOUT_MS,
        // The whole point: connect to the address that was checked, not to
        // whatever DNS says a second time.
        lookup: (_hostname, _options, callback) => {
          (callback as (err: Error | null, address: string, family: number) => void)(
            null, pinned.address, pinned.family
          );
        }
      },
      (response) => {
        // A redirect could land on a host we never checked. Refuse rather
        // than re-run the whole validation on a moving target.
        const status = response.statusCode ?? 0;
        if (status >= 300 && status < 400) {
          response.destroy();
          resolve(null);
          return;
        }
        let body = '';
        let size = 0;
        response.setEncoding('utf8');
        response.on('data', (chunk: string) => {
          size += chunk.length;
          if (size > CIMD_MAX_BYTES) {
            response.destroy();
            resolve(null);
            return;
          }
          body += chunk;
        });
        response.on('end', () => resolve({ status, body }));
        response.on('error', () => resolve(null));
      }
    );
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
    req.end();
  });
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

  const pinned = await resolvePinnedAddress(url.hostname);
  if (!pinned) return null;

  try {
    const response = await fetchPinned(url, pinned);
    if (!response || response.status < 200 || response.status >= 300) return null;

    const document = JSON.parse(response.body) as ClientIdMetadataDocument;

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

  // Evict before counting. A client that registered and never authorized is
  // either an abandoned experiment or noise; a real one has a grant within
  // minutes. Without this the cap below can only ever be reached once.
  await evictUnusedClients(db);

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

export async function evictUnusedClients(db: Queryable): Promise<number> {
  const { affectedRows } = await db.query(
    `DELETE FROM oauth_clients
      WHERE source = 'dcr'
        AND created_at < now() - make_interval(secs => $1)
        AND NOT EXISTS (SELECT 1 FROM oauth_grants g WHERE g.client_id = oauth_clients.client_id)`,
    [UNUSED_CLIENT_TTL_SECONDS]
  );
  return affectedRows;
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
