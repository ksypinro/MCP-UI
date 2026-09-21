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

Rotation marks the outgoing session replaced but does **not** revoke it. Its
refresh token is already dead, and its access token expires on its own within
minutes; revoking immediately would fail every request a client had in flight
when it refreshed proactively. Logout and detected reuse still revoke the
whole family at once.

Expired sessions and access tokens are swept hourly. Both are joined on every
protected request, so leaving them to accumulate degrades latency with uptime
rather than with load.

## The authorization server

`src/oauth/` is a complete OAuth 2.1 authorization server, built to the MCP
authorization specification revision `2026-07-28`. It is what lets an external
host — Claude, ChatGPT — connect to the MCP server that phase 4 will add,
without a credential ever passing through a tool, a model, or a conversation.

The flow is ordinary authorization-code with PKCE. What is worth knowing:

- **Discovery is a chain.** A `401` names the protected resource metadata, that
  names the authorization server, that names the endpoints. Protected resource
  metadata is served at both `/.well-known/oauth-protected-resource` and the
  `/mcp`-suffixed variant, because clients try the suffixed form first when the
  resource has a path and a server answering only one is discovered by some
  hosts and not others.
- **`client_id_metadata_document_supported` and `token_endpoint_auth_methods_supported: ["none"]`**
  are both advertised. Claude picks CIMD only when both are present.
- **Tokens are audience bound** (RFC 8707). A token minted for another resource
  is refused here however valid it is there.
- **Everything that can leak is treated as leaked.** A replayed authorization
  code revokes exactly the grant it produced; a replayed refresh token revokes
  the whole grant, including the token the thief did not steal.

### What the hosted page is for

`/authorize` renders the only place a password is ever typed. It is
server-rendered, entirely outside MCP, and returns nothing to the client but an
authorization code on a registered redirect URI. Spec section 7.4.

### Fetching a client_id is a request you did not choose to make

A Client ID Metadata Document is a URL supplied by whoever starts an
authorization, and resolving it means fetching it. `clients.ts` requires HTTPS,
resolves the hostname first and refuses any address that is loopback, private,
link-local or carrier-grade NAT — `169.254.169.254` being the usual target —
refuses redirects, caps the body, and requires the document to be
self-referential. The consent screen shows the **host of the `client_id` URL**,
never the document's `client_name`: the document is self-asserted, so the name
is whatever the client felt like claiming, while the host is what it had to
control in order to serve it.

## The MCP App views

`src/mcp/ui/` holds the four views from spec section 9. Each page is assembled
at startup from a shared stylesheet, a shared host bridge and one view script,
all inlined — which is what lets `_meta.ui.csp` stay empty. A host blocks every
external origin by default; a page that needs none cannot be broken by that
policy and cannot widen it.

**One bridge, shared.** `assets/bridge.js` is the only implementation of the
handshake, the tool-call proxy and the sizing protocol. Two copies of a
protocol do not stay identical, and the list and detail views run the same one.

**Nothing in a view ever holds a token.** Protected data arrives only as the
result of a tool call the host chose to forward. There is a test asserting the
views never mention a credential header or reach for browser storage.

**Device names are written with `textContent`, never as markup.** They are the
one user-supplied string that reaches these templates, and the templates are
otherwise entirely static.

### The inline row budget is a guess

`devices.js` renders `INLINE_ROW_BUDGET` rows inline and offers fullscreen for
the rest, because on a phone the conversation owns vertical scrolling: a pan
starting inside an inline card scrolls the chat, and the host clips whatever
overflows. A long list rendered inline is partly unreachable, not merely ugly.

The number is currently **4**, which is Claude's published guidance for an
inline card and not an observation. Question 2 in `../spike/FINDINGS.md` exists
to replace it with a measurement. When that is answered, change the constant.

### Looking at the views

```bash
npm start                       # server on :4000
node tools/mock-host/run.mjs    # harness on :8099, prints a URL
```

The harness is a mock MCP Apps host: it implements the bridge protocol, proxies
tool calls to the running server, and renders any of the four views in an
iframe with a live message log. It is not a test and is not shipped. It exists
because the views cannot otherwise be looked at, and it earned its place
immediately — it found a handler-registry collision in the bridge that every
unit test passed straight over.

## Acceptance

```bash
npm run acceptance
```

Runs the suite and reports which of the 28 criteria in section 12 of
`../requirement.md` it establishes, which are only partly established, and
which cannot be established from here at all.

It fails if a criterion's evidence goes missing, becomes ambiguous, or starts
failing, so renaming a test drops its criterion loudly rather than quietly.

It deliberately cannot print all green. Eight criteria need a host account or a
physical device — whether a host renders the views, how many rows survive an
inline card, whether every write is confirmed — and the report names each gap
rather than letting a green suite imply the product is finished.

```bash
npm run host-check
```

Opens a tunnel, starts the server told the origin it is reachable at, verifies
discovery and the `401` challenge over real HTTPS, and prints the connector URL
with the checklist. The point is that everything that can fail without a host
has already failed by the time you paste that URL anywhere.

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
  `req.ip` and walk around the limit. Sign-up and log-in are bucketed by
  address; refresh is bucketed by the token presented, so an office NAT cannot
  log its eleventh user out.
- Device names fold with NFKC plus lowercase, which is not full Unicode case
  folding — "Straße" and "STRASSE" remain distinct devices. Usernames are
  unaffected because validation restricts them to ASCII first.
- `USERNAME_TAKEN` is not in the spec's section 6.3 table, which covers only
  the device API. Sign-up needs a distinct code so the client can highlight the
  username field; the spec should gain it.
