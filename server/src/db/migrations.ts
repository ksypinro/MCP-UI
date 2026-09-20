/**
 * Schema for spec sections 4.1, 4.2, 6.2, 7.1 and 11.
 *
 * Plain PostgreSQL, deliberately. The two constraints that carry the
 * acceptance criteria are the UNIQUE on (owner_id, normalized_name), which is
 * what actually prevents AC-09's duplicate device, and the version column that
 * the conditional UPDATE in the device service tests against for AC-10.
 * Neither is enforced in application code, because application code loses
 * races and the database does not.
 */

export interface Migration {
  name: string;
  sql: string;
}

export const MIGRATIONS: Migration[] = [
  {
    name: '001_init',
    sql: `
      CREATE TABLE accounts (
        id                  text PRIMARY KEY,
        username            text NOT NULL,
        normalized_username text NOT NULL UNIQUE,
        password_hash       text NOT NULL,
        created_at          timestamptz NOT NULL DEFAULT now()
      );

      CREATE TABLE devices (
        id              text PRIMARY KEY,
        owner_id        text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        name            text NOT NULL,
        normalized_name text NOT NULL,
        state           text NOT NULL CHECK (state IN ('on', 'off')),
        version         integer NOT NULL DEFAULT 1 CHECK (version >= 1),
        created_at      timestamptz NOT NULL DEFAULT now(),
        updated_at      timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT devices_owner_name_key UNIQUE (owner_id, normalized_name)
      );

      -- Matches the ordering contract in spec section 4.3 exactly, so the list
      -- read never sorts in memory.
      CREATE INDEX devices_owner_created_idx ON devices (owner_id, created_at, id);

      -- One row per refresh token. Rotation appends a row to the same family;
      -- presenting a token that was already replaced means it leaked, and the
      -- whole family is revoked.
      CREATE TABLE sessions (
        id                 text PRIMARY KEY,
        account_id         text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        family_id          text NOT NULL,
        refresh_token_hash text NOT NULL UNIQUE,
        issued_at          timestamptz NOT NULL DEFAULT now(),
        expires_at         timestamptz NOT NULL,
        revoked_at         timestamptz,
        replaced_by        text
      );

      CREATE INDEX sessions_family_idx ON sessions (family_id);
      CREATE INDEX sessions_account_idx ON sessions (account_id);

      -- Access tokens are opaque and stored hashed. Validation joins sessions
      -- so that revoking a session immediately invalidates every access token
      -- already issued under it, as spec section 7.2 requires.
      CREATE TABLE access_tokens (
        token_hash text PRIMARY KEY,
        session_id text NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        expires_at timestamptz NOT NULL
      );

      CREATE INDEX access_tokens_session_idx ON access_tokens (session_id);

      -- Spec section 6.2: a replayed create returns the original device rather
      -- than a second one.
      CREATE TABLE idempotency_keys (
        account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        endpoint   text NOT NULL,
        key        text NOT NULL,
        device_id  text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        created_at timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (account_id, endpoint, key)
      );

      -- Spec section 11. Channel is recorded because without it the isolation
      -- and external-authorization criteria are hard to evidence later.
      CREATE TABLE audit_events (
        id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        actor_account_id  text,
        device_id         text,
        action            text NOT NULL,
        old_state         text,
        new_state         text,
        outcome           text NOT NULL,
        channel           text NOT NULL,
        request_id        text,
        occurred_at       timestamptz NOT NULL DEFAULT now()
      );

      CREATE INDEX audit_events_device_idx ON audit_events (device_id, occurred_at);
    `
  },
  {
    name: '002_idempotency_fingerprint',
    sql: `
      -- Without this, a key looked up by itself makes a replay carrying
      -- different arguments return the first request's device and call it
      -- created. The fingerprint lets a mismatched replay be refused.
      ALTER TABLE idempotency_keys ADD COLUMN request_fingerprint text;
    `
  }
];
