/**
 * The shared state a server needs beyond its database: rate-limit and budget
 * counters, used DPoP proof ids, sealed refresh responses, and revocation
 * events.
 *
 * In memory (the default) each process keeps its own, which is right for one
 * process and for tests. With REDIS_URL every process shares them, which is
 * what lets more than one process serve traffic without each allowing the
 * full rate limit, accepting a proof another already accepted, or keeping
 * internal tokens for a grant another revoked.
 */

import { randomBytes } from 'node:crypto';
import { MemoryBucketStore, type BucketStore } from '../security/rate-limit.ts';
import { MemoryReplayStore, type ReplayStore } from '../security/replay.ts';
import { MemorySealedResponses, type SealedResponses } from '../oauth/sealed.ts';
import { processRevocations, type RevocationHub } from '../revocation.ts';
import {
  RedisBucketStore, RedisReplayStore, RedisSealedResponses, bridgeRevocations, connectRedis
} from './redis.ts';

export interface Infrastructure {
  kind: 'memory' | 'redis';
  buckets: BucketStore;
  replay: ReplayStore;
  sealed: SealedResponses;
  revocations: RevocationHub;
  close(): Promise<void>;
}

/** Fresh per-process stores. Each call gets its own, so two apps in one test never share counts. */
export function memoryInfrastructure(revocations: RevocationHub = processRevocations): Infrastructure {
  return {
    kind: 'memory',
    buckets: new MemoryBucketStore(),
    replay: new MemoryReplayStore(),
    sealed: new MemorySealedResponses(),
    revocations,
    close: async () => {}
  };
}

export interface RedisOptions {
  url: string;
  /** Namespaces every key and the revocation channel. Tests use one per run. */
  prefix?: string;
  revocations?: RevocationHub;
}

export async function redisInfrastructure(options: RedisOptions): Promise<Infrastructure> {
  const prefix = options.prefix ?? process.env.REDIS_PREFIX ?? 'iotsw:';
  const revocations = options.revocations ?? processRevocations;
  const redis = await connectRedis(options.url);
  const unbridge = await bridgeRevocations(redis, revocations, prefix);
  return {
    kind: 'redis',
    buckets: new RedisBucketStore(redis, prefix),
    replay: new RedisReplayStore(redis, prefix),
    sealed: new RedisSealedResponses(redis, prefix),
    revocations,
    close: async () => {
      await unbridge();
      redis.destroy();
    }
  };
}

/** REDIS_URL selects Redis; otherwise memory. A Redis that cannot be reached at start-up stops the server. */
export async function infrastructureFromEnvironment(): Promise<Infrastructure> {
  const url = process.env.REDIS_URL;
  return url ? redisInfrastructure({ url }) : memoryInfrastructure();
}

/** A prefix no other test run shares. */
export function isolatedPrefix(): string {
  return `iotsw-test:${randomBytes(6).toString('hex')}:`;
}
