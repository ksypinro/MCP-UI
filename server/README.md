# IoT Switch — backend (phase 1)

Persistent accounts, sessions, and the four device operations from
`../requirement.md` sections 4, 6, 7.1 and 11.

Unlike `../spike`, this is meant to survive. Phases 3–5 build on it: the MCP
adapter will call the same device service directly rather than over HTTP.

## Run

```bash
npm install
npm start          # http://localhost:4000
npm test           # 53 tests
npm run typecheck
```

No build step. Node 25 strips TypeScript types natively, which is also why
there are no enums or parameter properties anywhere in `src`.

## Layout

```
src/
  normalize.ts     the name folds, in one place on purpose
  password.ts      argon2id
  errors.ts        the closed error-code set from spec section 6.3
  db/              schema, migrations, and the Queryable seam
  domain/          accounts, sessions, devices, audit
  http/            routes, middleware, the single error-to-body mapping
```

**`domain/devices.ts` takes an `Identity`, not a request.** That is spec
section 3's requirement that the REST API and the MCP tools share one
implementation of the business rules. When phase 4 arrives, the adapter passes
`{ accountId, channel: 'mcp' }` and everything — validation, ownership,
version checks, auditing — applies unchanged.

## What the database enforces

Application code loses races; the database does not. Two constraints carry the
concurrency acceptance criteria:

- `UNIQUE (owner_id, normalized_name)` is what actually prevents AC-09's
  duplicate device. Creation uses `ON CONFLICT DO NOTHING` rather than catching
  a unique violation, because on PostgreSQL a failed statement aborts the whole
  transaction and there would be nothing usable to continue with.
- The conditional `UPDATE ... WHERE version = $expected` makes the version
  check and the write a single statement, so two writers holding the same
  version cannot both succeed. That is AC-10.

Two details that are easy to get wrong and are tested: setting a device to the
state it already has advances neither `version` nor `updatedAt`, and a replayed
control with a consumed version conflicts rather than inverting the state.

## Sessions

Access tokens are opaque, stored hashed, and resolved against the `sessions`
table on **every** protected request. That lookup is deliberate. Spec section
7.2 requires logout to invalidate access tokens already issued, and a signed
token validated only by signature and expiry cannot be withdrawn.

Refresh tokens rotate. Each refresh appends a row to the same family and marks
the old one replaced. Presenting an already-replaced token means it leaked, so
the whole family is revoked — including the session the thief did not steal.

## On PGlite

The store is [PGlite](https://pglite.dev): real PostgreSQL compiled to
WebAssembly. Same SQL, same constraint enforcement, same SQLSTATEs — the schema
and every query here run unmodified on a PostgreSQL server.

What it is not is a server. It runs in-process and serialises queries, so no
two statements are ever truly concurrent. **The tests in
`test/concurrency.test.ts` therefore prove the logic is correct when two
callers start from the same observed state — one wins, one is refused — but
not yet its behaviour under genuine row-level contention.** That gap closes by
adding a `pg`-backed implementation of the `Db` interface in `src/db/index.ts`
and pointing the same tests, unmodified, at a real server.

Everything above `src/db` is written against `Queryable` and plain Postgres
SQL specifically to keep that a one-file change.

## Known gaps for later phases

- No `pg` driver yet (above).
- The rate limiter is per-process and in-memory; several instances behind a
  load balancer would each allow the full quota. `TRUST_PROXY` is off unless
  set, because trusting `X-Forwarded-For` unconditionally lets a client forge
  `req.ip` and walk around the limit.
- `USERNAME_TAKEN` is not in the spec's section 6.3 table, which covers only
  the device API. Sign-up needs a distinct code so the client can highlight the
  username field; the spec should gain it.
