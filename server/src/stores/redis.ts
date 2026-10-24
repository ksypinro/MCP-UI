/**
 * Redis-backed stores, for when more than one process serves traffic.
 *
 * Each implements the same interface as its in-memory counterpart, and the
 * contract tests (test/stores.test.ts) run one set of assertions against
 * both. What changes is only that every process sees the same counts, the
 * same used proof ids, the same sealed responses and the same revocations.
 *
 * Failure is closed. The client neither queues commands while disconnected
 * nor waits long for an answer: any error, timeout or lost connection becomes
 * a 503 SERVICE_UNAVAILABLE. A rate limit, replay check or refresh seal that
 * cannot be consulted refuses the request rather than letting it through.
 */

import { createHash, hkdfSync, randomBytes } from 'node:crypto';
import { createClient } from 'redis';
import { AppError } from '../errors.ts';
import type { BucketStore } from '../security/rate-limit.ts';
import type { ReplayStore } from '../security/replay.ts';
import { Sealer, type SealedResponses } from '../oauth/sealed.ts';
import type { ReceivedEvent, RevocationHub } from '../revocation.ts';
import { keys } from '../security/keys.ts';
import { log } from '../observability/log.ts';

/** How long any one command may take before the request is refused. */
const COMMAND_TIMEOUT_MS = Number(process.env.REDIS_COMMAND_TIMEOUT_MS ?? 500);

function newClient(url: string) {
  return createClient({
    url,
    disableOfflineQueue: true,
    commandOptions: { timeout: COMMAND_TIMEOUT_MS },
    socket: {
      connectTimeout: 2_000,
      // Keep trying in the background, a little slower each time. Requests
      // meanwhile fail fast, because the offline queue is off.
      reconnectStrategy: (retries: number) => Math.min(100 * 2 ** retries, 5_000)
    }
  });
}

export type Redis = ReturnType<typeof newClient>;

export async function connectRedis(url: string): Promise<Redis> {
  const client = newClient(url);
  // Without a listener an error event would crash the process. A dropped
  // connection is reported here and surfaces to requests as 503s.
  client.on('error', (error: Error) => log('error', 'redis_connection', { detail: error.message }));
  await client.connect();
  return client;
}

/** Runs a Redis call, turning any failure into a 503. */
async function guarded<T>(what: string, call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (error) {
    log('error', 'redis_unavailable', { component: what, detail: (error as Error).message });
    throw new AppError('SERVICE_UNAVAILABLE');
  }
}

/**
 * INCR and the expiry in one script, so a window can never be left without
 * one: two separate commands would leave a counter that never resets if the
 * process died between them.
 */
const HIT = `
local count = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {count, ttl}`;

export class RedisBucketStore implements BucketStore {
  private readonly redis: Redis;
  private readonly prefix: string;

  constructor(redis: Redis, prefix: string) {
    this.redis = redis;
    this.prefix = prefix;
  }

  async hit(key: string, windowMs: number): Promise<{ count: number; resetAt: number }> {
    const reply = await guarded('bucket', () => this.redis.eval(HIT, {
      keys: [`${this.prefix}bucket:${key}`], arguments: [String(windowMs)]
    })) as [number, number];
    return { count: Number(reply[0]), resetAt: Date.now() + Number(reply[1]) };
  }
}

export class RedisReplayStore implements ReplayStore {
  private readonly redis: Redis;
  private readonly prefix: string;

  constructor(redis: Redis, prefix: string) {
    this.redis = redis;
    this.prefix = prefix;
  }

  async claim(key: string, ttlSeconds: number): Promise<boolean> {
    const reply = await guarded('replay', () => this.redis.set(`${this.prefix}replay:${key}`, '1', {
      condition: 'NX', expiration: { type: 'EX', value: ttlSeconds }
    }));
    return reply === 'OK';
  }
}

/**
 * The sealing key is derived from the internal MAC key, so every process
 * holding the same key material can open what another sealed, and nothing
 * else can. Redis sees only ciphertext.
 */
export function sharedSealingKey(): Buffer {
  return Buffer.from(hkdfSync('sha256', keys().internalMacKey, Buffer.alloc(0), 'iot-switch sealed refresh responses', 32));
}

export class RedisSealedResponses implements SealedResponses {
  private readonly redis: Redis;
  private readonly prefix: string;
  private readonly sealer: Sealer;

  constructor(redis: Redis, prefix: string, secret: Buffer = sharedSealingKey()) {
    this.redis = redis;
    this.prefix = prefix;
    this.sealer = new Sealer(secret);
  }

  /** Store keys are hashed again, so Redis never holds a token digest either. */
  private storeKey(key: string): string {
    return `${this.prefix}sealed:${createHash('sha256').update(key).digest('base64url')}`;
  }

  async seal(key: string, body: unknown, ttlSeconds: number): Promise<void> {
    const sealed = this.sealer.seal(key, body).toString('base64');
    await guarded('seal', () => this.redis.set(this.storeKey(key), sealed, {
      expiration: { type: 'EX', value: ttlSeconds }
    }));
  }

  async unseal(key: string): Promise<unknown | null> {
    const sealed = await guarded('unseal', () => this.redis.get(this.storeKey(key)));
    if (typeof sealed !== 'string') return null;
    return this.sealer.open(key, Buffer.from(sealed, 'base64'));
  }
}

/**
 * Joins this process's revocation hub to every other process's, over a
 * Redis channel. Local events are published; events from other processes are
 * delivered locally, marked remote so they are not sent back.
 *
 * Losing an event here costs at most an internal token's remaining minute in
 * another process's cache: every request still verifies the caller's own
 * token live, so a revoked grant is refused at the edge regardless.
 */
export async function bridgeRevocations(redis: Redis, hub: RevocationHub, prefix: string): Promise<() => Promise<void>> {
  const channel = `${prefix}revocations`;
  const origin = randomBytes(8).toString('hex');
  const subscriber = redis.duplicate();
  subscriber.on('error', (error: Error) => log('error', 'redis_subscriber', { detail: error.message }));
  await subscriber.connect();

  await subscriber.subscribe(channel, (message) => {
    let parsed: { origin?: string; event?: ReceivedEvent };
    try {
      parsed = JSON.parse(message);
    } catch {
      return;
    }
    if (!parsed.event || parsed.origin === origin) return;
    hub.publish({ ...parsed.event, remote: true });
  });

  const unsubscribe = hub.subscribe((event) => {
    if (event.remote) return;
    const { remote: _ignored, ...plain } = event;
    redis.publish(channel, JSON.stringify({ origin, event: plain })).catch((error: Error) => {
      log('error', 'revocation_not_broadcast', { detail: error.message });
    });
  });

  return async () => {
    unsubscribe();
    await subscriber.unsubscribe(channel).catch(() => {});
    subscriber.destroy();
  };
}
