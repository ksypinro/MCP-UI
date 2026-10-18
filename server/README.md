# IoT Switch — backend (phase 1)

Persistent accounts, sessions, and the four device operations from
`../requirement.md` sections 4, 6, 7.1 and 11.

Unlike `../spike`, this is meant to survive. Phases 3–5 build on it: the MCP
adapter will call the same device service directly rather than over HTTP.

## Run

```bash
npm install
npm start          # http://localhost:4000
npm test           # 238 tests
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
- **Redemption and rotation are atomic.** A code is consumed by one guarded
  `UPDATE`, so two concurrent redemptions cannot both succeed. A refresh locks
  its row, decides and rotates in one transaction.
- **A duplicate refresh is not theft.** Hosts refresh from several workers at
  once, and responses get lost. The same token presented again by the same
  client within `REFRESH_GRACE_SECONDS`, before its successor has been used,
  gets back the identical response, sealed in memory with AES-GCM for that
  window. Outside it, the grant is revoked.
- **The pages cannot be framed.** Every HTML response carries
  `frame-ancestors 'none'`, `X-Frame-Options: DENY` and a nonce-based CSP whose
  `form-action` names the client's redirect origin (browsers apply it to the
  redirect after the form submits). RFC 9700 §4.16.

### What the hosted pages are for

They are the only place a password is ever typed. They are server-rendered,
entirely outside MCP, and return nothing to the client but an authorization
code on a registered redirect URI. Spec section 7.4.

Signing in and approving are separate steps:

1. `GET /authorize` validates the request once and stores it under an opaque
   id, bound to this browser by a cookie. A link copied to another browser
   cannot be completed there.
2. `/login` signs in or signs up and starts the authorization server's own
   session (`__Host-as_session` over HTTPS: 30 minutes idle, 12 hours at
   most, always a fresh one on sign-in).
3. `/consent` names the client, says whether it is verified, shows where the
   person will be sent (the full address for a self-registered client), and
   lists what it asks for. Approving write access needs a sign-in from the
   last 15 minutes.

An approval is remembered per client and redirect host, for the same or
fewer scopes, while a metadata document is unchanged. It is **never**
remembered for a dynamically registered client: DCR establishes nothing about
who the client is, and remembered consent is what a confused-deputy attack
rides on. Every form carries a CSRF token derived from the browser binding.

### Tokens and keys

Every token is typed and checksummed (`iotsw_at_…`, `iotsw_rt_…`, and so on),
so a malformed one is refused without a database lookup and a leaked one is
recognisable by a scanner. Tokens are stored as HMAC-SHA256 under a pepper
held outside the database; passwords as Argon2id over an HMAC under a second
pepper. The key material comes from `TOKEN_PEPPERS`, `PASSWORD_PEPPER` and
`INTERNAL_MAC_KEY`, or else from `keys.json` beside the database, created on
first start with mode 0600. **Back that file up with the database.**

### Fetching a client_id is a request you did not choose to make

A Client ID Metadata Document is a URL supplied by whoever starts an
authorization, and resolving it means fetching it. `clients.ts` requires HTTPS,
resolves the hostname first and refuses any address that is loopback, private,
link-local or carrier-grade NAT — `169.254.169.254` being the usual target —
refuses redirects, caps the body, and requires the document to be
self-referential. Only ordinary public unicast addresses may be fetched, as
classified by `ipaddr.js`, which also refuses every IPv6 form that embeds an
IPv4 address. Documents are capped at 5 KB, fetches are budgeted per
`client_id` host (20 a minute), and successful documents are cached in the
database for as long as their own `Cache-Control` says, clamped to between a
minute and a day. So `GET /authorize`, which needs no account, cannot be used
to aim requests at a host. The consent screen shows the **host of the `client_id` URL**,
never the document's `client_name`: the document is self-asserted, so the name
is whatever the client felt like claiming, while the host is what it had to
control in order to serve it.

## The Device Service and token exchange

Neither front door touches device data itself. The MCP tools and the REST
routes are adapters: they check shape, spend the write budget, and exchange
the caller's token for an internal one before calling the Device Service
(`src/device-service/`), which wraps the unchanged rules in
`domain/devices.ts`.

- **Exchange, never forward.** `exchange-client.ts` trades the caller's token
  (RFC 8693, `oauth/exchange.ts`) for a one-minute ES256 JWT: audience
  `https://device.internal`, exactly one scope, `act` naming the adapter and
  `cnf` binding it to that adapter's workload identity. The MCP adapter may
  exchange only OAuth tokens for the MCP resource; the REST gateway only
  the app's OAuth tokens for the API, or a legacy first-party session. Tokens are cached per grant and scope, and dropped
  the moment the grant is revoked.
- **Verify everything.** The Device Service checks signature, `typ: at+jwt`,
  issuer, audience, expiry, the scope the operation needs, and that the token
  names and is bound to the workload presenting it. The account comes from
  `sub` and nowhere else.
- **One table.** `mcp/policy.ts` gives each tool its scope, annotations and
  write budget. The gate, the registrations and ChatGPT's security schemes
  all read it. A tool name that is not in it is treated as protected.
- **Budgets.** At most 6 switches a minute per device, 20 a minute and 10 new
  devices an hour per grant — a hard ceiling on what an injected prompt can
  make a host do. Report-only until `WRITE_BUDGETS=enforce`.
- **Audit.** Every change records the client, grant, adapter and sign-in
  method behind it, taken from the verified internal token.

While everything runs in one process, a workload identity is a capability
object created at start-up; when the components are split, it becomes the
adapter's mTLS certificate.

## The iOS app's sign-in: PAR and DPoP

The app is an OAuth client like the hosts, with three things the hosts are
not required to do. All three are enforced for `client_id=iot-switch-ios`,
which is resolved in code rather than registered, and ignored for everyone
else.

- **Pushed authorization requests** (RFC 9126). The app posts its whole
  request to `POST /par` and gets back a `request_uri` that works once, within
  60 seconds. The browser sheet opens `/authorize?client_id&request_uri`, so
  nothing in the URL can be altered on the way. `/authorize` refuses this
  client without one. `prompt=create` opens the sign-up form.
- **DPoP** (RFC 9449, `oauth/dpop.ts`). The request names the thumbprint of a
  key held in the Secure Enclave (`dpop_jkt`); the code is redeemable only with
  a proof from that key, and the tokens it yields carry it (`cnf_jkt`). Every
  API call then needs a fresh proof naming the method and URL, hashing the
  token (`ath`) and echoing a server nonce. A copied token, a replayed proof,
  or a proof from another key gets `401` with `WWW-Authenticate: DPoP`.
  Nonces are an HMAC of the five-minute window, so they need no storage and
  survive restarts; every token response and API answer carries the current
  one in `DPoP-Nonce`.
- **Its own audience.** The app's tokens are for the REST API
  (`API_BASE_URL`), last 10 minutes, and skip the consent screen. A refresh
  needs a proof from the same key, so a stolen refresh token is as useless as
  a stolen access token.

Hosts that send a DPoP proof get bound tokens too, at `/mcp` as well as the
API. Nothing requires them to.

The old password endpoints under `/v1/auth/*` still answer, now with
`Deprecation` and `Sunset` headers. `LEGACY_FIRST_PARTY_AUTH=off` retires
sign-up, log-in and refresh with `410`; `DPOP_REQUIRED_FOR_API=on` refuses
anything at the API that is not DPoP-bound. Both are for after the browser
sign-in build has shipped.

`/.well-known/apple-app-site-association` is served on the API host once
`APPLE_TEAM_ID` is set, for the universal-link callback that replaces the
custom scheme. `/oauth/callback` there is a page that tells a person who
lands on it in a browser to go back to the app, and never shows the code.

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

Runs the suite and reports which of the 42 criteria — the 28 in section 12 of
`../requirement.md`, plus fourteen added by the authentication redesign — it
establishes, which are only partly established, and which cannot be
established from here at all.

It fails if a criterion's evidence goes missing, becomes ambiguous, or starts
failing, so renaming a test drops its criterion loudly rather than quietly.

It deliberately cannot print all green. Eight criteria need a host account or a
physical device — whether a host renders the views, how many rows survive an
inline card, whether every write is confirmed — and the report names each gap
rather than letting a green suite imply the product is finished.

```bash
npm run client-check
```

Connects the way a specification-compliant MCP client does, using the official
SDK's own client, transport and OAuth implementation — discovery, registration,
PKCE, the token exchange and bearer attachment are all its code, not ours. It
stands in for the person only where a real client opens a browser.

Everything else in the suite drives the endpoints directly, which proves they
behave as intended but not that a real client can find its way through them.
This found a bug nothing else did: a client validates `structuredContent`
against a tool's declared `outputSchema` whenever it is present, **including on
an error result**, so every version conflict reached it as "structured content
does not match the tool's output schema" rather than as the conflict. Error
codes now travel in `_meta`, which is not schema-bound.

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
