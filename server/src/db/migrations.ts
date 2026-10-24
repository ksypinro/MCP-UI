/**
 * Schema for spec sections 4.1, 4.2, 6.2, 7 and 11.
 *
 * Plain PostgreSQL, deliberately. The two constraints that carry the
 * acceptance criteria are the UNIQUE on (owner_id, normalized_name), which is
 * what actually prevents AC-09's duplicate device, and the version column that
 * the conditional UPDATE in the device service tests against for AC-10.
 * Neither is enforced in application code, because application code loses
 * races and the database does not.
 *
 * Every *_hash column holding a token, code or session id holds HMAC-SHA256
 * under a pepper kept outside the database (security/keys.ts).
 *
 * Later schema changes are appended to MIGRATIONS as new entries; an applied
 * entry is never edited.
 */

export interface Migration {
  name: string;
  sql: string;
}

export const MIGRATIONS: Migration[] = [
  {
    name: '001_schema',
    sql: `
      -- password_hash is Argon2id over an HMAC of the password; the pepper
      -- version says which pepper that HMAC used.
      CREATE TABLE accounts (
        id                      text PRIMARY KEY,
        username                text NOT NULL,
        normalized_username     text NOT NULL UNIQUE,
        password_hash           text NOT NULL,
        password_pepper_version smallint NOT NULL,
        created_at              timestamptz NOT NULL DEFAULT now()
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

      -- Spec section 6.2: a replayed create returns the original device rather
      -- than a second one. The fingerprint of the arguments lets a replay that
      -- carries different arguments be refused instead of answered with the
      -- first request's device.
      CREATE TABLE idempotency_keys (
        account_id          text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        endpoint            text NOT NULL,
        key                 text NOT NULL,
        device_id           text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        request_fingerprint text,
        created_at          timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (account_id, endpoint, key)
      );

      -- Spec section 11. Who acted, through what, from where: the client the
      -- person used, the grant it held, the workload that called the Device
      -- Service for them, and how they signed in. Taken from the verified
      -- internal token, never from a request field.
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
        client_id         text,
        grant_id          text,
        via               text,
        auth_method       text,
        occurred_at       timestamptz NOT NULL DEFAULT now()
      );

      CREATE INDEX audit_events_device_idx ON audit_events (device_id, occurred_at);

      -- Clients that reached us through Dynamic Client Registration, or that
      -- were pre-registered by hand. Clients identified by a Client ID
      -- Metadata Document are not stored here: their metadata is fetched from
      -- the client_id URL and cached in cimd_cache.
      CREATE TABLE oauth_clients (
        client_id        text PRIMARY KEY,
        client_name      text,
        redirect_uris    text NOT NULL,          -- JSON array
        source           text NOT NULL CHECK (source IN ('dcr', 'preregistered')),
        application_type text,
        created_at       timestamptz NOT NULL DEFAULT now()
      );

      -- Client ID Metadata Documents that resolved, reused until their own
      -- Cache-Control says otherwise (clamped to a day). The digest ties a
      -- remembered consent to the exact document the person approved.
      CREATE TABLE cimd_cache (
        client_id     text PRIMARY KEY,
        redirect_uris text NOT NULL,          -- JSON array
        display_host  text NOT NULL,
        digest        text NOT NULL,
        fetched_at    timestamptz NOT NULL,
        expires_at    timestamptz NOT NULL
      );

      -- Pushed authorization requests (RFC 9126): parameters sent over the
      -- back channel and referenced by an opaque, single-use request_uri, so
      -- they never travel through the browser.
      CREATE TABLE par_requests (
        id         text PRIMARY KEY,
        client_id  text NOT NULL,
        params     text NOT NULL,          -- JSON
        expires_at timestamptz NOT NULL
      );

      -- An authorization in flight, held server-side and addressed by an
      -- opaque id, never carried by the browser. Client and redirect_uri are
      -- validated once, before this row exists, so a crafted request cannot
      -- name its own redirect_uri or PKCE challenge behind a genuine login
      -- page. binding_hash ties it to the browser that started it; dpop_jkt
      -- to the key the client named at authorization.
      CREATE TABLE oauth_pending_authorizations (
        id              text PRIMARY KEY,
        client_id       text NOT NULL,
        client_host     text NOT NULL,         -- what the consent screen shows
        client_kind     text NOT NULL,
        client_trust    text NOT NULL,
        document_digest text,
        redirect_uri    text NOT NULL,
        state           text,
        code_challenge  text NOT NULL,
        resource        text NOT NULL,
        scope           text NOT NULL,         -- space delimited
        offline_access  boolean NOT NULL DEFAULT false,
        binding_hash    text NOT NULL,
        dpop_jkt        text,
        first_party     boolean NOT NULL DEFAULT false,
        created_at      timestamptz NOT NULL DEFAULT now(),
        expires_at      timestamptz NOT NULL
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
        offline_access boolean NOT NULL DEFAULT false,
        auth_time      timestamptz,
        consent_id     text,
        dpop_jkt       text,
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
      -- off it, so revoking the grant takes every token it ever issued. A
      -- grant bound to a DPoP key (RFC 9449) carries its thumbprint, and its
      -- refresh tokens are refused without a proof from that key.
      -- last_used_at is written at most once a minute per grant.
      CREATE TABLE oauth_grants (
        id           text PRIMARY KEY,
        account_id   text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        client_id    text NOT NULL,
        resource     text NOT NULL,
        scope        text NOT NULL,
        dpop_jkt     text,
        created_at   timestamptz NOT NULL DEFAULT now(),
        last_used_at timestamptz,
        revoked_at   timestamptz
      );

      CREATE INDEX oauth_grants_account_idx ON oauth_grants (account_id);

      -- Audience is stored per token and checked on every use: a token minted
      -- for another resource must never be accepted here, however valid it is
      -- elsewhere (RFC 8707). cnf_jkt is the grant's DPoP key thumbprint.
      CREATE TABLE oauth_access_tokens (
        token_hash text PRIMARY KEY,
        grant_id   text NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
        audience   text NOT NULL,
        scope      text NOT NULL,
        cnf_jkt    text,
        expires_at timestamptz NOT NULL
      );

      CREATE INDEX oauth_access_tokens_grant_idx ON oauth_access_tokens (grant_id);

      -- Rotated on every use. Presenting one that was already exchanged means
      -- it leaked, and the whole grant goes, except for a duplicate inside a
      -- short window after replaced_at, which is answered with the identical
      -- response; see rotateRefresh in oauth/store.ts.
      CREATE TABLE oauth_refresh_tokens (
        token_hash  text PRIMARY KEY,
        grant_id    text NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
        audience    text NOT NULL,
        scope       text NOT NULL,
        replaced_by text,
        replaced_at timestamptz,
        revoked_at  timestamptz,
        created_at  timestamptz NOT NULL DEFAULT now(),
        expires_at  timestamptz NOT NULL
      );

      CREATE INDEX oauth_refresh_tokens_grant_idx ON oauth_refresh_tokens (grant_id);

      -- The authorization server's own browser session; see oauth/session.ts.
      CREATE TABLE as_sessions (
        id_hash             text PRIMARY KEY,
        account_id          text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        auth_time           timestamptz NOT NULL,
        acr                 text NOT NULL,
        idle_expires_at     timestamptz NOT NULL,
        absolute_expires_at timestamptz NOT NULL,
        revoked_at          timestamptz,
        created_at          timestamptz NOT NULL DEFAULT now()
      );

      CREATE INDEX as_sessions_account_idx ON as_sessions (account_id);

      -- What a person has approved, per client and redirect host. Remembered
      -- only for clients identified by a metadata document or registered by
      -- us, never for dynamically registered ones; see oauth/consents.ts.
      CREATE TABLE consents (
        id              text PRIMARY KEY,
        account_id      text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        client_id       text NOT NULL,
        redirect_host   text NOT NULL,
        scopes          text NOT NULL,
        document_digest text,
        granted_at      timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT consents_account_client_host_key UNIQUE (account_id, client_id, redirect_host)
      );

      -- WebAuthn credentials. The id is the credential id the authenticator
      -- chose, base64url. The public key is COSE-encoded. The signature
      -- counter is kept so a cloned authenticator that replays an old counter
      -- is refused.
      CREATE TABLE passkeys (
        id           text PRIMARY KEY,
        account_id   text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        public_key   bytea NOT NULL,
        counter      bigint NOT NULL DEFAULT 0,
        transports   text NOT NULL DEFAULT '',
        name         text NOT NULL,
        created_at   timestamptz NOT NULL DEFAULT now(),
        last_used_at timestamptz
      );

      CREATE INDEX passkeys_account_idx ON passkeys (account_id);

      -- A challenge is used once: taken with DELETE ... RETURNING. A
      -- registration challenge belongs to the signed-in account; a sign-in
      -- challenge to the browser that asked for it.
      CREATE TABLE webauthn_challenges (
        challenge  text PRIMARY KEY,
        purpose    text NOT NULL CHECK (purpose IN ('register', 'authenticate')),
        account_id text REFERENCES accounts(id) ON DELETE CASCADE,
        binding    text,
        expires_at timestamptz NOT NULL
      );
    `
  }
];
