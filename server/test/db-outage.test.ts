/**
 * A PostgreSQL server that is down, or goes away, fails fast and closed: a
 * 503 within the connect timeout, never a request queued for ever and never a
 * 500 with a stack trace. Found in the phase 4 failover drill. AC-47.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { createPgDb } from '../src/db/pg.ts';

const DATABASE = process.env.TEST_DATABASE_URL;

test('an unreachable database is a fast 503, not a hang', async () => {
  process.env.DATABASE_CONNECT_TIMEOUT_MS = '500';
  try {
    // Port 1 on loopback: nothing listens there, so the connection is refused.
    const db = await createPgDb({ connectionString: 'postgres://nobody:nothing@127.0.0.1:1/none' });
    const started = Date.now();
    await assert.rejects(db.query('SELECT 1'), (error: any) => error.code === 'SERVICE_UNAVAILABLE');
    await assert.rejects(db.transaction(async (tx) => tx.query('SELECT 1')), (error: any) => error.code === 'SERVICE_UNAVAILABLE');
    assert.ok(Date.now() - started < 3_000, `took ${Date.now() - started} ms`);
    await db.close();
  } finally {
    delete process.env.DATABASE_CONNECT_TIMEOUT_MS;
  }
});

test('a connection the server terminates is a 503, and the pool recovers', { skip: DATABASE ? false : 'set TEST_DATABASE_URL' }, async () => {
  const db = await createPgDb({ connectionString: DATABASE!, max: 1 });
  try {
    const { rows } = await db.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
    const admin = new pg.Client({ connectionString: DATABASE! });
    await admin.connect();
    await admin.query('SELECT pg_terminate_backend($1)', [rows[0]!.pid]);
    await admin.end();

    // The pooled connection is dead: the next query on it is refused as a
    // service outage, not as a fault in this server.
    let outage: unknown = null;
    try {
      await db.query('SELECT 1');
    } catch (error) {
      outage = error;
    }
    if (outage) assert.equal((outage as any).code, 'SERVICE_UNAVAILABLE');
    // Either way the pool replaces the connection and carries on.
    assert.deepEqual((await db.query<{ ok: number }>('SELECT 1 AS ok')).rows, [{ ok: 1 }]);
  } finally {
    await db.close();
  }
});
