/**
 * Response headers for the hosted authorization pages.
 *
 * These pages are the one place a credential is typed, so they must not be
 * framed: RFC 9700 section 4.16 makes clickjacking prevention a MUST for an
 * authorization server, and a framed login page is also an embedded user agent
 * that RFC 8252 forbids for credential entry.
 */

import { randomBytes } from 'node:crypto';
import type { Response } from 'express';

/** A fresh nonce per response, for the page's one inline stylesheet. */
export function newNonce(): string {
  return randomBytes(16).toString('base64');
}

/**
 * The CSP source that lets a form's submission redirect to `redirectUri`.
 *
 * Browsers apply `form-action` to the redirect that follows a form POST, so
 * `'self'` alone would block the 302 back to the host's callback. A
 * private-use scheme has an opaque origin and is matched by scheme instead.
 */
export function formActionSource(redirectUri: string): string {
  const url = new URL(redirectUri);
  return url.origin === 'null' ? url.protocol : url.origin;
}

export function authPageHeaders(
  res: Response, options: { nonce: string; formTargets?: string[] }
): void {
  const formAction = ["'self'", ...(options.formTargets ?? [])].join(' ');
  res.set({
    'Content-Security-Policy': [
      "default-src 'none'",
      `style-src 'nonce-${options.nonce}'`,
      "img-src 'self'",
      `form-action ${formAction}`,
      "frame-ancestors 'none'",
      "base-uri 'none'"
    ].join('; '),
    'X-Frame-Options': 'DENY',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
}
