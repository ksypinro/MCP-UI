/**
 * The PostgreSQL server driver. Plan 4.1.
 *
 * Same interface as the PGlite driver, so nothing above `src/db` knows which
 * one it is talking to. Two differences are smoothed over here rather than
 * leaked upwards:
 *
 * - `int8` arrives as a string from `pg` and as a number from PGlite. Every
 *   bigint in this schema is an identity or a count well inside 2^53, so it is
 *   parsed as a number. `date` is parsed as UTC midnight, as PGlite does.
 *   Both parsers are per pool, never global.
 * - A transaction needs one connection for its whole life. `transaction()`
 *   checks one out, runs BEGIN … COMMIT on it, and gives `fn` only that
 *   connection. Anything `fn` runs through the pool instead runs outside the
 *   transaction, exactly as it would on a real server.
 *
 * Unlike PGlite, statements here really do run at the same time. That is the
 * point: the concurrency tests prove row-lock behaviour under contention only
 * when they run against this driver.
 */

import pg from 'pg';
import type { Db, QueryResult, Tx } from './index.ts';
import { log } from '../observability/log.ts';

const INT8 = 20;
const DATE = 1082;

const types = {
  getTypeParser(oid: number, format?: 'text' | 'binary') {
    if (oid === INT8) return (value: string) => Number(value);
    if (oid === DATE) return (value: string) => new Date(`${value}T00:00:00Z`);
    return pg.types.getTypeParser(oid, format as 'text');
  }
};

export interface PgOptions {
  connectionString: string;
  /**
   * A schema to create if missing and put first on the search path. Tests use
   * one per database so that suites sharing a server never see each other's
   * rows.
   */
  schema?: string;
  /** Drop `schema` on close. For tests only. */
  dropSchemaOnClose?: boolean;
  /** Connections in the pool. */
  max?: number;
}

function quoteIdent(name: string): string {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(name)) throw new Error(`Unsafe schema name: ${name}`);
  return `"${name}"`;
}

export async function createPgDb(options: PgOptions): Promise<Db> {
  const { connectionString, schema, dropSchemaOnClose, max = Number(process.env.DATABASE_POOL_SIZE ?? 10) } = options;

  if (schema) {
    // Created over a separate connection, before the pool's connections start
    // naming it in their search path.
    const admin = new pg.Client({ connectionString });
    await admin.connect();
    try {
      await admin.query(`CREATE SCHEMA IF NOT EXISTS ${quoteIdent(schema)}`);
    } finally {
      await admin.end();
    }
  }

  const pool = new pg.Pool({
    connectionString,
    max,
    types,
    ...(schema ? { options: `-c search_path=${schema}` } : {})
  });
  // An idle connection dropped by the server must not crash the process; the
  // pool replaces it on the next checkout.
  pool.on('error', (error) => log('error', 'db_idle_connection', { detail: error.message }));

  const run = async <T>(target: pg.Pool | pg.PoolClient, sql: string, params?: unknown[]): Promise<QueryResult<T>> => {
    const result = await target.query(sql, params as unknown[] | undefined);
    return { rows: result.rows as T[], affectedRows: result.rowCount ?? 0 };
  };

  const db: Db = {
    query: <T>(sql: string, params?: unknown[]) => run<T>(pool, sql, params),

    async exec(sql: string) {
      // No parameters, so pg uses the simple query protocol, which accepts
      // several statements at once.
      await pool.query(sql);
    },

    async transaction<T>(fn: (tx: Tx) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      let broken = false;
      try {
        await client.query('BEGIN');
        const tx: Tx = {
          query: <U>(sql: string, params?: unknown[]) => run<U>(client, sql, params),
          async exec(sql: string) { await client.query(sql); }
        };
        const outcome = await fn(tx);
        await client.query('COMMIT');
        return outcome;
      } catch (error) {
        try {
          await client.query('ROLLBACK');
        } catch {
          // The connection itself failed. Destroy it rather than return a
          // client in an unknown transaction state to the pool.
          broken = true;
        }
        throw error;
      } finally {
        client.release(broken);
      }
    },

    async close() {
      if (schema && dropSchemaOnClose) await pool.query(`DROP SCHEMA IF EXISTS ${quoteIdent(schema)} CASCADE`);
      await pool.end();
    }
  };

  return db;
}

