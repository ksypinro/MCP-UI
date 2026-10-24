/**
 * Resolving a `client_id` to the redirect URIs it is allowed to use.
 *
 * Two mechanisms, in the priority the 2026-07-28 authorization specification
 * sets: Client ID Metadata Documents first, Dynamic Client Registration as a
 * fallback for hosts that do not support CIMD. DCR is deprecated in that
 * revision and can be removed no earlier than the first revision on or after
 * 28 July 2027; until then it is kept, hardened, and never trusted.
 */

import { lookup } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import { isIP, type LookupFunction } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import ipaddr from 'ipaddr.js';
import type { Db, Queryable } from '../db/index.ts';
import {
  FIRST_PARTY_CLIENT_ID, MAX_REGISTERED_CLIENTS, UNUSED_CLIENT_TTL_SECONDS, firstPartyRedirectUris
} from './config.ts';
import { MemoryBucketStore, bucket, type BucketStore } from '../security/rate-limit.ts';
import { metrics } from '../observability/metrics.ts';
import { log } from '../observability/log.ts';

export interface ResolvedClient {
  clientId: string;
  redirectUris: string[];
  /**
   * What the consent screen shows.
   *
   * For CIMD this is the host of the client_id URL, never the document's
   * `client_name`: the document is self-asserted, so its name is whatever the
   * client felt like claiming, while the host is what the client had to
   * control in order to serve it. Null for DCR: consent must instead name
   * the validated callback selected by this authorization request.
   */
  displayHost: string | null;
  /** How the client is known. Drives what the consent screen claims about it. */
  kind: 'cimd' | 'dcr' | 'preregistered';
  /**
   * `verified` only for a CIMD URL on our allowlist of known hosts, or a
   * client we registered ourselves. Everything else is `unverified`.
   */
  trust: 'verified' | 'unverified';
  /**
   * SHA-256 of the metadata document, for CIMD clients. A remembered consent
   * is tied to it, so a changed document asks the person again.
   */
  documentDigest: string | null;
  /** Our own app: consent implied, PAR and DPoP required, API resource only. */
  firstParty: boolean;
}

const CIMD_TIMEOUT_MS = 5_000;
/** CIMD draft -02 recommends about 5 KB; a real document is a few hundred bytes. */
const CIMD_MAX_BYTES = 5 * 1024;

/**
 * CIMD client_ids we recognise by URL, shown as verified on the consent
 * screen. Comma-separated KNOWN_CLIENTS overrides the default. Claude's CIMD
 * URL is added once host-check has confirmed it.
 */
export function knownClients(): Set<string> {
  const configured = process.env.KNOWN_CLIENTS ?? 'https://chatgpt.com/oauth/client.json';
  return new Set(configured.split(',').map((entry) => entry.trim()).filter(Boolean));
}

/* ------------------------------------------------------------------ SSRF */

/**
 * A client_id is a URL supplied by whoever is starting an authorization, and
 * we fetch it. Without this check that is a request forgery primitive pointed
 * at whatever the server can reach — cloud metadata endpoints being the
 * classic target.
 *
 * Only ordinary public unicast is allowed. ipaddr.js classifies everything
 * else — private, loopback, link-local, carrier-grade NAT, benchmarking and
 * documentation ranges, multicast, unique-local IPv6, and the IPv6 forms that
 * embed an IPv4 address (mapped, NAT64, 6to4, Teredo) — so there is no
 * hand-written parsing left to get wrong. An earlier version checked only the
 * fe80 prefix of link-local and missed NAT64 entirely.
 */
export function isForbiddenAddress(address: string): boolean {
  if (!ipaddr.isValid(address)) return true;
  let parsed = ipaddr.parse(address);
  if (parsed.kind() === 'ipv6' && (parsed as ipaddr.IPv6).isIPv4MappedAddress()) {
    parsed = (parsed as ipaddr.IPv6).toIPv4Address();
  }
  return parsed.range() !== 'unicast';
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
function deniedRange(host: string): void {
  metrics.inc('cimd_fetch', { result: 'denied_range' });
  log('warn', 'cimd_fetch_denied_range', { host });
}

async function resolvePinnedAddress(
  hostname: string
): Promise<{ address: string; family: number } | null> {
  if (isIP(hostname)) {
    if (!isForbiddenAddress(hostname)) return { address: hostname, family: isIP(hostname) };
    deniedRange(hostname);
    return null;
  }
  try {
    const addresses = await lookup(hostname, { all: true });
    if (addresses.length === 0) return null;
    // Every address must be public: a name resolving to both is still a way
    // to reach the private one.
    if (addresses.some((entry) => isForbiddenAddress(entry.address))) {
      deniedRange(hostname);
      return null;
    }
    const chosen = addresses[0];
    return chosen ? { address: chosen.address, family: chosen.family } : null;
  } catch {
    return null;
  }
}

/** A pinned DNS answer in either callback shape requested by Node. */
export function pinnedLookup(pinned: { address: string; family: number }): LookupFunction {
  return (_hostname, options, callback) => {
    if (options.all) callback(null, [pinned]);
    else callback(null, pinned.address, pinned.family);
  };
}

/**
 * GET over HTTPS with the connection pinned to `pinned`, while TLS still
 * validates against the real hostname via SNI.
 */
function fetchPinned(
  url: URL, pinned: { address: string; family: number }
): Promise<FetchedDocument | null> {
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
        lookup: pinnedLookup(pinned)
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
        // Counted in bytes, not decoded characters, so multi-byte text cannot
        // stretch the cap.
        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > CIMD_MAX_BYTES) {
            response.destroy();
            resolve(null);
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => resolve({
          status,
          cacheControl: typeof response.headers['cache-control'] === 'string' ? response.headers['cache-control'] : null,
          body: Buffer.concat(chunks).toString('utf8')
        }));
        response.on('error', () => resolve(null));
      }
    );
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
    req.end();
  });
}

/* ------------------------------------------------------------------ CIMD */

/**
 * Outbound fetches per client_id host per minute.
 *
 * `GET /authorize` is reachable without an account, and each call with an
 * unseen https client_id makes this server resolve and fetch a URL of the
 * caller's choosing. Without a ceiling that is a free request amplifier aimed
 * at any host the caller names. Successful documents are cached (below), so
 * legitimate clients fetch once per cache period, not once per sign-in.
 */
const CIMD_FETCHES_PER_HOST_PER_MINUTE = 20;
let takeCimdFetch = bucket(new MemoryBucketStore(), CIMD_FETCHES_PER_HOST_PER_MINUTE, 60_000);

/** Counts metadata fetches in a store every process shares. Called once at start-up. */
export function useCimdFetchStore(store: BucketStore): void {
  takeCimdFetch = bucket(store, CIMD_FETCHES_PER_HOST_PER_MINUTE, 60_000);
}

export async function cimdFetchAllowed(host: string): Promise<boolean> {
  return (await takeCimdFetch(`cimd-host:${host.toLowerCase()}`)).ok;
}

interface ClientIdMetadataDocument {
  client_id?: unknown;
  client_name?: unknown;
  redirect_uris?: unknown;
}

export interface FetchedDocument {
  status: number;
  cacheControl: string | null;
  body: string;
}

/** How a metadata document is fetched. Replaced in tests; see resolveClient. */
export type CimdFetcher = (url: URL) => Promise<FetchedDocument | null>;

/** The real fetcher: resolve, refuse forbidden addresses, connect to the checked one. */
const pinnedFetcher: CimdFetcher = async (url) => {
  const pinned = await resolvePinnedAddress(url.hostname);
  return pinned ? fetchPinned(url, pinned) : null;
};

/**
 * How long a fetched document may be reused: the document's own max-age,
 * clamped to between one minute and a day, or five minutes when it says
 * nothing. `no-store` and `no-cache` are honoured by not caching.
 */
export function cimdCacheSeconds(cacheControl: string | null): number {
  if (!cacheControl) return 300;
  if (/\bno-(store|cache)\b/i.test(cacheControl)) return 0;
  const maxAge = /\bmax-age=(\d+)/i.exec(cacheControl)?.[1];
  if (maxAge === undefined) return 300;
  return Math.min(Math.max(Number(maxAge), 60), 86_400);
}

async function cachedDocument(db: Queryable, clientId: string): Promise<ResolvedClient | null> {
  const { rows } = await db.query<{ redirect_uris: string; display_host: string; digest: string }>(
    'SELECT redirect_uris, display_host, digest FROM cimd_cache WHERE client_id = $1 AND expires_at > now()',
    [clientId]
  );
  const row = rows[0];
  if (!row) return null;
  return {
    clientId,
    redirectUris: JSON.parse(row.redirect_uris) as string[],
    displayHost: row.display_host,
    kind: 'cimd',
    trust: knownClients().has(clientId) ? 'verified' : 'unverified',
    documentDigest: row.digest,
    firstParty: false
  };
}

async function resolveMetadataDocument(
  db: Queryable, clientId: string, fetcher: CimdFetcher
): Promise<ResolvedClient | null> {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' || url.hash) return null;

  // Successful documents are reused across sign-ins and restarts, so the
  // per-host budget below never bites a popular host's legitimate users.
  const cached = await cachedDocument(db, clientId);
  if (cached) return cached;
  if (!(await cimdFetchAllowed(url.host))) {
    metrics.inc('cimd_fetch', { result: 'budget' });
    return null;
  }

  try {
    const response = await fetcher(url);
    const invalid = () => { metrics.inc('cimd_fetch', { result: 'invalid' }); return null; };
    if (!response) return null; // refused before any connection: counted where it was refused
    if (response.status < 200 || response.status >= 300) return invalid();
    if (Buffer.byteLength(response.body, 'utf8') > CIMD_MAX_BYTES) return invalid();

    const document = JSON.parse(response.body) as ClientIdMetadataDocument;

    // The document must be self-referential, or anyone could host a document
    // claiming to be someone else's client_id.
    if (document.client_id !== clientId) return invalid();

    const redirectUris = Array.isArray(document.redirect_uris)
      ? document.redirect_uris.filter((entry): entry is string => typeof entry === 'string')
      : [];
    if (redirectUris.length === 0) return invalid();

    const digest = createHash('sha256').update(response.body).digest('hex');
    const ttl = cimdCacheSeconds(response.cacheControl);
    if (ttl > 0) {
      await db.query(
        `INSERT INTO cimd_cache (client_id, redirect_uris, display_host, digest, fetched_at, expires_at)
         VALUES ($1, $2, $3, $4, now(), now() + make_interval(secs => $5))
         ON CONFLICT (client_id) DO UPDATE
           SET redirect_uris = EXCLUDED.redirect_uris, display_host = EXCLUDED.display_host,
               digest = EXCLUDED.digest, fetched_at = EXCLUDED.fetched_at, expires_at = EXCLUDED.expires_at`,
        [clientId, JSON.stringify(redirectUris), url.host, digest, ttl]
      );
    }

    metrics.inc('cimd_fetch', { result: 'ok' });
    return {
      clientId,
      redirectUris,
      displayHost: url.host,
      kind: 'cimd',
      trust: knownClients().has(clientId) ? 'verified' : 'unverified',
      documentDigest: digest,
      firstParty: false
    };
  } catch {
    metrics.inc('cimd_fetch', { result: 'error' });
    return null;
  }
}

/* ------------------------------------------------------------------- DCR */

export interface ClientRegistration {
  redirectUris: unknown;
  clientName: unknown;
  applicationType: unknown;
}

export type RegistrationOutcome =
  | { clientId: string; redirectUris: string[]; clientName: string | null; applicationType: 'web' | 'native' }
  | { error: 'invalid_redirect_uri' | 'invalid_client_metadata' | 'registration_closed' };

/**
 * Dynamic Client Registration (RFC 7591), deprecated by MCP 2026-07-28 and
 * kept, hardened, until it can be removed.
 *
 * - `application_type` is required, as 2026-07-28 requires clients to send
 *   it, and constrains redirects the way OpenID Connect does: `web` clients
 *   use https on a non-loopback host; `native` clients use loopback http, a
 *   reverse-DNS private-use scheme, or https.
 * - One unacceptable redirect URI refuses the whole registration. Silently
 *   dropping it would register something other than what was asked for.
 * - The name is length-limited and stripped of control characters, and
 *   nothing the client sent is echoed back unvalidated.
 * - Every DCR client is unverified, and consent is never remembered for it.
 */
export async function registerClient(db: Db, registration: ClientRegistration): Promise<RegistrationOutcome> {
  const applicationType = registration.applicationType;
  if (applicationType !== 'web' && applicationType !== 'native') return { error: 'invalid_client_metadata' };

  const redirectUris = Array.isArray(registration.redirectUris) ? registration.redirectUris : [];
  if (redirectUris.length === 0 || redirectUris.length > 10) return { error: 'invalid_redirect_uri' };
  for (const uri of redirectUris) {
    if (typeof uri !== 'string' || !isRegisterableRedirectUri(uri)) return { error: 'invalid_redirect_uri' };
    if (!suitsApplicationType(uri, applicationType)) return { error: 'invalid_redirect_uri' };
  }
  const uris = redirectUris as string[];

  const clientName = typeof registration.clientName === 'string'
    ? registration.clientName.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 100) || null
    : null;

  // Evict before counting. A client that registered and never authorized is
  // either an abandoned experiment or noise; a real one has a grant within
  // minutes. Without this the cap below can only ever be reached once.
  await evictUnusedClients(db);

  const { rows } = await db.query<{ n: number }>('SELECT count(*)::int AS n FROM oauth_clients');
  if ((rows[0]?.n ?? 0) >= MAX_REGISTERED_CLIENTS) return { error: 'registration_closed' };

  const clientId = `client_${randomBytes(16).toString('base64url')}`;
  await db.query(
    `INSERT INTO oauth_clients (client_id, client_name, redirect_uris, source, application_type)
     VALUES ($1, $2, $3, 'dcr', $4)`,
    [clientId, clientName, JSON.stringify(uris), applicationType]
  );
  return { clientId, redirectUris: uris, clientName, applicationType };
}

function suitsApplicationType(uri: string, applicationType: 'web' | 'native'): boolean {
  const url = new URL(uri);
  if (applicationType === 'web') return url.protocol === 'https:' && !isLoopback(url);
  return true; // native: loopback http, private-use scheme or https, all already checked
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
  const { rows } = await db.query<{ client_id: string; redirect_uris: string; source: string }>(
    'SELECT client_id, redirect_uris, source FROM oauth_clients WHERE client_id = $1',
    [clientId]
  );
  const row = rows[0];
  if (!row) return null;

  const redirectUris = JSON.parse(row.redirect_uris) as string[];
  // DCR does not establish ownership of a name or of the first registered
  // URI. The authorization endpoint must display the validated destination
  // actually selected for this request.
  const preregistered = row.source === 'preregistered';
  return {
    clientId,
    redirectUris,
    displayHost: null,
    kind: preregistered ? 'preregistered' : 'dcr',
    trust: preregistered ? 'verified' : 'unverified',
    documentDigest: null,
    firstParty: false
  };
}

/**
 * CIMD when the id is an HTTPS URL, otherwise a registered client.
 *
 * `fetcher` exists for tests, which cannot serve a document from a public
 * address; production always uses the pinned fetcher.
 */
export async function resolveClient(
  db: Queryable, clientId: unknown, options: { fetcher?: CimdFetcher } = {}
): Promise<ResolvedClient | null> {
  if (typeof clientId !== 'string' || clientId.length === 0 || clientId.length > 2048) return null;
  if (clientId === FIRST_PARTY_CLIENT_ID) {
    return {
      clientId, redirectUris: firstPartyRedirectUris(), displayHost: 'the IoT Switch app',
      kind: 'preregistered', trust: 'verified', documentDigest: null, firstParty: true
    };
  }
  if (clientId.startsWith('https://')) return resolveMetadataDocument(db, clientId, options.fetcher ?? pinnedFetcher);
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
