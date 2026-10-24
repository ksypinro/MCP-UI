/**
 * The server's only logger. Plan 4.8.
 *
 * Structured, one JSON object per line, and allowlisted: a field is written
 * only if its name is on the list below, so a request object, a header map or
 * a token passed by mistake is dropped rather than printed. Every string that
 * is written is scanned too: anything shaped like one of this server's tokens
 * (`iotsw_xx_…`), a JWT, or an Authorization value is replaced, and counted,
 * so a leak that does get as far as a log line is visible in the metrics
 * rather than in the log.
 */

import { metrics } from './metrics.ts';

export type Level = 'info' | 'warn' | 'error' | 'alert';

/** Field names that may appear in a log line. Anything else is dropped. */
const ALLOWED = new Set([
  'requestId', 'grantId', 'clientId', 'accountId', 'passkeyId', 'component', 'kind', 'tool', 'reason', 'status',
  'count', 'limit', 'windowSeconds', 'host', 'scope', 'method', 'path', 'error', 'detail', 'alert'
]);

const PATTERNS: Array<[RegExp, string]> = [
  // This server's typed tokens: access, refresh, codes, sessions, bindings.
  [/iotsw_[a-z]{2}_[A-Za-z0-9_-]+/g, 'iotsw_[redacted]'],
  // Compact JWS/JWT: internal tokens, DPoP proofs, anyone else's tokens.
  [/eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g, '[redacted-jwt]'],
  // An Authorization or DPoP header value, however it got into a string.
  [/\b(Bearer|DPoP|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, '$1 [redacted]']
];

/** Replaces anything token-shaped in `value`, counting each replacement. */
export function scrub(value: string): string {
  let out = value;
  for (const [pattern, replacement] of PATTERNS) {
    out = out.replace(pattern, (...match) => {
      metrics.inc('log_secrets_redacted');
      return replacement.replace('$1', String(match[1] ?? ''));
    });
  }
  return out;
}

function clean(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (typeof value === 'string') return scrub(value);
  if (value instanceof Error) return scrub(value.stack ?? value.message);
  // Any other object is not written: it is where headers and bodies hide.
  return '[object omitted]';
}

let sink: (line: string) => void = (line) => { process.stderr.write(`${line}\n`); };

/** Redirects log output. For tests. */
export function useLogSink(write: (line: string) => void): void {
  sink = write;
}

export function log(level: Level, event: string, fields: Record<string, unknown> = {}): void {
  const entry: Record<string, unknown> = { t: new Date().toISOString(), level, event: scrub(event) };
  for (const [key, value] of Object.entries(fields)) {
    if (ALLOWED.has(key)) entry[key] = clean(value);
    else metrics.inc('log_fields_dropped');
  }
  sink(JSON.stringify(entry));
}
