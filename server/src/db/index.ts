import { createHash, randomBytes } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { MIGRATIONS } from './migrations.ts';
import { createPgDb } from './pg.ts';

export interface QueryResult<T> {
  rows: T[];
  affectedRows: number;
}

/** Anything a query can run against: the pool, or a transaction within it. */
export interface Queryable {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<QueryResult<T>>;
}

/** A transaction's connection. `exec` is there for multi-statement DDL. */
export interface Tx extends Queryable {
  exec(sql: string): Promise<void>;
}

export interface Db extends Queryable {
  /**
   * Runs one or more statements with no parameters, over the simple query
   * protocol. Needed because the extended protocol that `query` uses accepts
   * exactly one statement, which multi-statement DDL is not.
   */
  exec(sql: string): Promise<void>;
  transaction<T>(fn: (tx: Tx) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

/**
 * Opens the database and brings its schema up to date.
 *
 * With DATABASE_URL set, that is a PostgreSQL server (`pg.ts`). Otherwise it
 * is PGlite: real PostgreSQL compiled to WebAssembly, with the same SQL, the
 * same constraint enforcement and the same SQLSTATEs, persisted in `dataDir`
 * or held in memory. What PGlite is not is a server. It runs in-process and
 * serialises queries, so no two statements are ever truly concurrent.
 *
 * Everything above this file is written against `Queryable` and plain
 * Postgres SQL, so the two drivers are interchangeable.
 */
export async function createDb(dataDir?: string): Promise<Db> {
  const db = process.env.DATABASE_URL ? await openServer(process.env.DATABASE_URL, dataDir) : await openPglite(dataDir);
  await migrate(db);
  return db;
}

/**
 * DATABASE_ISOLATION=schema gives every database opened in this process its
 * own schema on the server, which is how the test suite runs against
 * PostgreSQL: each test's database is as empty as a fresh PGlite one. A
 * database opened with a `dataDir` gets a schema named after it, so opening
 * the same directory again finds the same data, as PGlite would.
 */
async function openServer(connectionString: string, dataDir?: string): Promise<Db> {
  if (process.env.DATABASE_ISOLATION !== 'schema') {
    return createPgDb({ connectionString, schema: process.env.DATABASE_SCHEMA });
  }
  const schema = dataDir
    ? `t_${createHash('sha256').update(dataDir).digest('hex').slice(0, 24)}`
    : `t_${randomBytes(12).toString('hex')}`;
  return createPgDb({ connectionString, schema, dropSchemaOnClose: !dataDir, max: 12 });
}

async function openPglite(dataDir?: string): Promise<Db> {
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
    async transaction<T>(fn: (tx: Tx) => Promise<T>): Promise<T> {
      const outcome = await pglite.transaction(async (tx) =>
        fn({
          async query<U>(sql: string, params?: unknown[]) {
            return toResult<U>(await tx.query(sql, params as never));
          },
          async exec(sql: string) {
            await tx.exec(sql);
          }
        })
      );
      return outcome as T;
    },
    async close() {
      await pglite.close();
    }
  };
  return db;
}

async function migrate(db: Db): Promise<void> {
  // Every step takes a transaction-scoped advisory lock first, so that several
  // processes starting at once against one server migrate one at a time
  // instead of racing to create the same tables. The lock is per schema.
  const lock = "SELECT pg_advisory_xact_lock(hashtext('iot-switch-migrate:' || current_schema()))";

  await db.transaction(async (tx) => {
    await tx.query(lock);
    await tx.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      name text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )`);
  });

  for (const migration of MIGRATIONS) {
    // Each migration is one transaction: a half-applied schema is worse than
    // an unapplied one. Whether it is already applied is decided under the
    // lock, so a migration another process just ran is not run twice.
    await db.transaction(async (tx) => {
      await tx.query(lock);
      const { rows } = await tx.query('SELECT 1 FROM schema_migrations WHERE name = $1', [migration.name]);
      if (rows.length > 0) return;
      await tx.exec(migration.sql);
      await tx.query('INSERT INTO schema_migrations (name) VALUES ($1)', [migration.name]);
    });
  }
}
