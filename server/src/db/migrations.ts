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
  },
  {
    name: '003_oauth',
    sql: `
      -- Clients that reached us through Dynamic Client Registration, or that
      -- were pre-registered by hand. Clients identified by a Client ID
      -- Metadata Document are NOT stored: their metadata is fetched from the
      -- client_id URL at authorization time, which is the point of CIMD.
      CREATE TABLE oauth_clients (
        client_id     text PRIMARY KEY,
        client_name   text,
        redirect_uris text NOT NULL,          -- JSON array
        source        text NOT NULL CHECK (source IN ('dcr', 'preregistered')),
        created_at    timestamptz NOT NULL DEFAULT now()
      );

      -- An authorization in flight, held server-side and addressed by an
      -- opaque id. The browser never carries this record.
      --
      -- An earlier revision of the spike round-tripped it through the login
      -- form as unsigned base64, which let anyone craft a context naming their
      -- own redirect_uri and PKCE challenge, walk a victim through a genuine
      -- login page showing a spoofed client name, and collect a live
      -- authorization code. Client and redirect_uri are validated once, here,
      -- before this row exists.
      CREATE TABLE oauth_pending_authorizations (
        id             text PRIMARY KEY,
        client_id      text NOT NULL,
        client_host    text NOT NULL,         -- what the consent screen shows
        redirect_uri   text NOT NULL,
        state          text,
        code_challenge text NOT NULL,
        resource       text NOT NULL,
        scope          text NOT NULL,         -- space delimited
        created_at     timestamptz NOT NULL DEFAULT now(),
        expires_at     timestamptz NOT NULL
      );

      -- Codes are stored hashed and are single use.
      CREATE TABLE oauth_authorization_codes (
        code_hash      text PRIMARY KEY,
        account_id     text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        client_id      text NOT NULL,
        redirect_uri   text NOT NULL,
        code_challenge text NOT NULL,
        resource       text NOT NULL,
        scope          text NOT NULL,
        consumed_at    timestamptz,
        -- The grant this code produced, if it ever produced one. A replay
        -- revokes exactly this and nothing else: guessing from account and
        -- client would revoke an unrelated newer grant, and a code that was
        -- burned by a failed exchange produced no grant at all.
        grant_id       text,
        created_at     timestamptz NOT NULL DEFAULT now(),
        expires_at     timestamptz NOT NULL
      );

      -- One grant per completed authorization. Access and refresh tokens hang
      -- off it, so revoking the grant takes every token it ever issued.
      CREATE TABLE oauth_grants (
        id         text PRIMARY KEY,
        account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        client_id  text NOT NULL,
        resource   text NOT NULL,
        scope      text NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        revoked_at timestamptz
      );

      CREATE INDEX oauth_grants_account_idx ON oauth_grants (account_id);

      -- Audience is stored per token and checked on every use: a token minted
      -- for another resource must never be accepted here, however valid it is
      -- elsewhere (RFC 8707).
      CREATE TABLE oauth_access_tokens (
        token_hash text PRIMARY KEY,
        grant_id   text NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
        audience   text NOT NULL,
        scope      text NOT NULL,
        expires_at timestamptz NOT NULL
      );

      CREATE INDEX oauth_access_tokens_grant_idx ON oauth_access_tokens (grant_id);

      -- Rotated on every use. Presenting one that was already exchanged means
      -- it leaked, and the whole grant goes.
      CREATE TABLE oauth_refresh_tokens (
        token_hash  text PRIMARY KEY,
        grant_id    text NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
        audience    text NOT NULL,
        scope       text NOT NULL,
        replaced_by text,
        revoked_at  timestamptz,
        created_at  timestamptz NOT NULL DEFAULT now(),
        expires_at  timestamptz NOT NULL
      );

      CREATE INDEX oauth_refresh_tokens_grant_idx ON oauth_refresh_tokens (grant_id);
    `
  }
];
