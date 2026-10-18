/**
 * The shape of every token this server issues.
 *
 *   iotsw_<kind>_<43 base64url characters: 256 random bits><6 base62 characters: CRC-32>
 *
 * The prefix lets secret scanners, the log scrubber and the WAF recognise a
 * leaked token with no false positives, and says which kind it is so one kind
 * cannot be presented where another is expected. The checksum lets the server
 * reject garbage without a database round trip. Beyond that a token means
 * nothing: it is a reference, so decoding it reveals nothing.
 */

import { randomBytes } from 'node:crypto';
import { crc32 } from 'node:zlib';

const PREFIX = {
  access: 'iotsw_at_',
  refresh: 'iotsw_rt_',
  code: 'iotsw_ac_',
  session: 'iotsw_ss_',
  binding: 'iotsw_pb_'
} as const;

export type TokenKind = keyof typeof PREFIX;

const BODY_LENGTH = 43;
const CHECK_LENGTH = 6;
const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const BODY_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function base62(value: number, width: number): string {
  let out = '';
  let rest = value;
  for (let index = 0; index < width; index++) {
    out = BASE62[rest % 62] + out;
    rest = Math.floor(rest / 62);
  }
  return out;
}

function checksum(prefixAndBody: string): string {
  return base62(crc32(prefixAndBody), CHECK_LENGTH);
}

export function mint(kind: TokenKind): string {
  const prefixAndBody = PREFIX[kind] + randomBytes(32).toString('base64url');
  return prefixAndBody + checksum(prefixAndBody);
}

/** Right kind, right length, valid checksum. Says nothing about whether it is live. */
export function wellFormed(kind: TokenKind, token: unknown): token is string {
  const prefix = PREFIX[kind];
  if (typeof token !== 'string' || token.length !== prefix.length + BODY_LENGTH + CHECK_LENGTH) return false;
  if (!token.startsWith(prefix)) return false;
  const body = token.slice(prefix.length, prefix.length + BODY_LENGTH);
  if (!BODY_PATTERN.test(body)) return false;
  return token.slice(-CHECK_LENGTH) === checksum(prefix + body);
}

/** Matches any token of ours anywhere in a string. For log scrubbing and leak scanning. */
export const TOKEN_PATTERN = /iotsw_(?:at|rt|ac|ss|pb)_[A-Za-z0-9_-]{43}[0-9A-Za-z]{6}/g;
