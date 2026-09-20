import { PGlite } from '@electric-sql/pglite';
import { MIGRATIONS } from './migrations.ts';

export interface QueryResult<T> {
  rows: T[];
  affectedRows: number;
}

/** Anything a query can run against: the pool, or a transaction within it. */
export interface Queryable {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<QueryResult<T>>;
}

export interface Db extends Queryable {
  /**
   * Runs one or more statements with no parameters, over the simple query
   * protocol. Needed because the extended protocol that `query` uses accepts
   * exactly one statement, which multi-statement DDL is not.
   */
  exec(sql: string): Promise<void>;
  transaction<T>(fn: (tx: Queryable) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

/**
 * PGlite is real PostgreSQL compiled to WebAssembly: the same SQL, the same
 * constraint enforcement, the same SQLSTATEs. What it is not is a server — it
 * runs in-process and serialises queries, so no two statements are ever truly
 * concurrent.
 *
 * Everything above this file is written against the Queryable interface and
 * plain Postgres SQL, so swapping in `pg` is a matter of adding a second
 * implementation here. See README for what that changes about the tests.
 */
export async function createDb(dataDir?: string): Promise<Db> {
  const pglite = dataDir ? await PGlite.create(dataDir) : await PGlite.create();

  const toResult = <T>(result: { rows: unknown[]; affectedRows?: number }): QueryResult<T> => ({
    rows: result.rows as T[],
    affectedRows: result.affectedRows ?? 0
  });

  const db: Db = {
    async query<T>(sql: string, params?: unknown[]) {
      return toResult<T>(await pglite.query(sql, params as never));
    },
    async exec(sql: string) {
      await pglite.exec(sql);
    },
    async transaction<T>(fn: (tx: Queryable) => Promise<T>): Promise<T> {
      const outcome = await pglite.transaction(async (tx) =>
        fn({
          async query<U>(sql: string, params?: unknown[]) {
            return toResult<U>(await tx.query(sql, params as never));
          }
        })
      );
      return outcome as T;
    },
    async close() {
      await pglite.close();
    }
  };

  await migrate(db);
  return db;
}

async function migrate(db: Db): Promise<void> {
  await db.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
    name text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
  )`);

  const { rows } = await db.query<{ name: string }>('SELECT name FROM schema_migrations');
  const applied = new Set(rows.map((row) => row.name));

  for (const migration of MIGRATIONS) {
    if (applied.has(migration.name)) continue;
    // Each migration is one transaction: a half-applied schema is worse than
    // an unapplied one. Transaction control goes through exec rather than the
    // transaction helper, because the DDL is multi-statement.
    await db.exec('BEGIN');
    try {
      await db.exec(migration.sql);
      await db.query('INSERT INTO schema_migrations (name) VALUES ($1)', [migration.name]);
      await db.exec('COMMIT');
    } catch (error) {
      await db.exec('ROLLBACK');
      throw error;
    }
  }
}
