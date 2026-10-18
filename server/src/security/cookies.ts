/**
 * Cookies for the authorization server's own pages.
 *
 * Over HTTPS every cookie uses the `__Host-` prefix, which the browser
 * enforces: Secure, Path=/, and no Domain, so no sibling host can set or
 * overwrite it. Plain-HTTP localhost (development and tests) cannot use the
 * prefix, because it requires Secure, so the bare name is used there.
 */

import type { Request, Response } from 'express';
import { ISSUER } from '../oauth/config.ts';

const SECURE = ISSUER.startsWith('https://');

export function cookieName(base: 'as_session' | 'pa'): string {
  return SECURE ? `__Host-${base}` : base;
}

export function readCookie(req: Request, name: string): string | null {
  const header = req.get('cookie');
  if (!header) return null;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    if (part.slice(0, index).trim() === name) {
      try {
        return decodeURIComponent(part.slice(index + 1).trim());
      } catch {
        return null;
      }
    }
  }
  return null;
}

export function setCookie(res: Response, name: string, value: string, maxAgeSeconds: number): void {
  res.cookie(name, value, {
    httpOnly: true,
    secure: SECURE,
    // Lax, not Strict: the authorization request arrives as a top-level
    // navigation from the client's site, and must still see the session.
    sameSite: 'lax',
    path: '/',
    maxAge: maxAgeSeconds * 1000
  });
}

export function clearCookie(res: Response, name: string): void {
  res.clearCookie(name, { httpOnly: true, secure: SECURE, sameSite: 'lax', path: '/' });
}
