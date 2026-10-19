/**
 * The credential a request presents, in either scheme.
 *
 * Only the Authorization header is read: a token in a query string or body
 * ends up in logs, browser history and Referer headers, so it is never
 * accepted there.
 */

import type { Request } from 'express';

export interface PresentedCredential {
  scheme: 'Bearer' | 'DPoP';
  token: string;
}

export function credentialFrom(req: Request): PresentedCredential | null {
  const header = req.get('authorization');
  if (!header) return null;
  const match = /^(bearer|dpop) +(.+)$/i.exec(header.trim());
  if (!match?.[2]) return null;
  return { scheme: match[1]!.toLowerCase() === 'dpop' ? 'DPoP' : 'Bearer', token: match[2].trim() };
}

/** The request URL without query or fragment, as a DPoP proof's htu names it. */
export function requestHtu(baseUrl: string, req: Request): string {
  const path = (req.originalUrl ?? req.url).split('?')[0] ?? '/';
  return `${baseUrl}${path}`;
}
