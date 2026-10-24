# IoT Switch — backend

The OAuth 2.1 authorization server, the MCP server and its views, the REST API
and the Device Service behind both, from `../requirement.md`. The design is in
[`../docs/architecture.md`](../docs/architecture.md) and
[`../docs/authentication-architecture.md`](../docs/authentication-architecture.md).

## Run

```bash
npm install
npm start          # http://localhost:4000
npm test           # 279 tests on PGlite and in-memory stores
npm run test:pg    # the same on PostgreSQL 17 and Redis 7 (local containers, or CI)
npm run typecheck
```

No build step. Node 25 strips TypeScript types natively, which is also why
there are no enums or parameter properties anywhere in `src`.

## Layout

```
src/
  index.ts         profile S: every component in one process
  entry/           profile M: one entry point per component
  normalize.ts     the name folds, in one place on purpose
  password.ts      Argon2id over an HMAC under the password pepper
  errors.ts        the closed error-code set from spec section 6.3
  db/              PGlite and PostgreSQL drivers, the schema, the Queryable seam
  domain/          accounts, devices, audit
  device-service/  the only caller of the device rules; verifies internal tokens
  http/            the REST API: routes, middleware, the single error-to-body mapping
  oauth/           the authorization server, hosted pages and account pages
  mcp/             the MCP endpoint: gate, policy, tools, resources, views
  security/        keys, KMS, rate limits, DPoP replay, workload identities
  stores/          shared state, in memory or in Redis
  split/           profile M: mTLS listeners and remote clients
  observability/   logger, metrics, alerts
```

**`domain/devices.ts` takes an `Identity`, not a request.** That is spec
section 3's requirement that the REST API and the MCP tools share one
implementation of the business rules. The Device Service builds the identity
from a verified internal token, so validation, ownership, version checks and
auditing apply identically to both.

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

## The authorization server

`src/oauth/` is a complete OAuth 2.1 authorization server, built to the MCP
authorization specification revision `2026-07-28`. It is what lets an external
host — Claude, ChatGPT — and the iOS app connect without a credential ever
passing through a tool, a model, a conversation or app code.

The flow is ordinary authorization-code with PKCE. What is worth knowing:

- **Discovery is a chain.** A `401` names the protected resource metadata, that
  names the authorization server, that names the endpoints. Protected resource
  metadata is served at both `/.well-known/oauth-protected-resource` and the
  `/mcp`-suffixed variant, because clients try the suffixed form first when the
  resource has a path and a server answering only one is discovered by some
  hosts and not others.
- **`client_id_metadata_document_supported` and `token_endpoint_auth_methods_supported: ["none"]`**
  are both advertised. Claude picks CIMD only when both are present.
- **Tokens are opaque, audience bound** (RFC 8707) **and checked on every
  request.** A token minted for another resource is refused however valid it
  is there, and a revoked grant stops working on the next call: spec section
  7.2 requires that tokens already issued stop working, which a token validated
  only by signature and expiry cannot do.
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
  exchange only OAuth tokens for the MCP resource; the REST gateway only the
  app's OAuth tokens for the API. Internal tokens are cached per grant and
  scope, and dropped the moment the grant is revoked.
- **Verify everything.** The Device Service checks signature, `typ: at+jwt`,
  issuer, audience, expiry, the scope the operation needs, and that the token
  names and is bound to the workload presenting it. The account comes from
  `sub` and nowhere else.
- **One table.** `mcp/policy.ts` gives each tool its scope, annotations and
  write budget. The gate, the registrations and ChatGPT's security schemes
  all read it. A tool name that is not in it is treated as protected.
- **Budgets.** At most 6 switches a minute per device, 20 a minute and 10 new
  devices an hour per grant — a hard ceiling on what an injected prompt can
  make a host do. `WRITE_BUDGETS=report` logs instead of refusing, for
  measuring a changed limit.
- **Audit.** Every change records the client, grant, adapter and sign-in
  method behind it, taken from the verified internal token.

In one process, a workload identity is a capability object created at
start-up; split into processes, it is the adapter's mTLS certificate.

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

The REST API accepts nothing else: a bearer token, a bound token without its
proof, or a token for another resource gets `401`. `GET /v1/me` answers who the
caller is; signing in, refreshing and signing out all happen at the
authorization server.

Hosts that send a DPoP proof get bound tokens too, at `/mcp`. Nothing requires
them to.

`/.well-known/apple-app-site-association` is served on the API host once
`APPLE_TEAM_ID` is set, for the universal-link callback; without it the app
uses its custom scheme. `/oauth/callback` there is a page that tells a person who
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

Each view's URI carries a hash of its page (`ui://iot/devices.e824b396.html`):
hosts cache templates by URI across reconnects, so changed code must be a new
URI. `UI_DIAGNOSTICS=1` adds a panel to the device list showing the build and
every message the host sent, for host verification.

### The inline row budget

`devices.js` renders `INLINE_ROW_BUDGET` rows inline and offers fullscreen for
the rest, because on a phone the conversation owns vertical scrolling: a pan
starting inside an inline card scrolls the chat, and the host clips whatever
overflows. A long list rendered inline is partly unreachable, not merely ugly.

The number is **4**, Claude's published guidance for an inline card. A desktop
browser has room for more; a phone measurement is still to be taken
([`../docs/host-compatibility.md`](../docs/host-compatibility.md), Q2).

### Looking at the views

```bash
npm start                       # server on :4000
node tools/mock-host/run.mjs    # harness on :8099, prints a URL
```

The harness is a mock MCP Apps host: it implements the bridge protocol, proxies
tool calls to the running server, and renders any of the four views in an
iframe with a live message log. It is not a test and is not shipped; it is how
a view is looked at, and its messages watched, without a real host.

## Acceptance

```bash
npm run acceptance
```

Runs the suite and reports which of the 47 criteria in section 12 of
`../requirement.md` it establishes, which are only partly established, and which cannot be
established from here at all. A skipped test proves nothing, and criteria that
need PostgreSQL or Redis are only reported proven by a run that had them
(`DATABASE_URL=… TEST_REDIS_URL=… npm run acceptance`).

It fails if a criterion's evidence goes missing, becomes ambiguous, or starts
failing, so renaming a test drops its criterion loudly rather than quietly.

It deliberately cannot print all green. Some criteria need a host account or a
physical device — Claude on iPhone, how many rows fit in an inline card on a
phone, a platform passkey — and the report names each gap rather than letting
a green suite imply the product is finished.

```bash
npm run client-check
```

Connects the way a specification-compliant MCP client does, using the official
SDK's own client, transport and OAuth implementation — discovery, registration,
PKCE, the token exchange and bearer attachment are all its code, not ours. It
stands in for the person only where a real client opens a browser.

Everything else in the suite drives the endpoints directly, which proves they
behave as intended but not that a real client can find its way through them.
A client validates `structuredContent` against a tool's declared
`outputSchema` whenever it is present, **including on an error result**, which
is why error results carry none and their codes travel in `_meta`.

```bash
npm run host-check
```

Opens a tunnel, starts the server with the tunnel's origin as its public URL, verifies
discovery and the `401` challenge over real HTTPS, and prints the connector URL
with the checklist. The point is that everything that can fail without a host
has already failed by the time you paste that URL anywhere. Record what a host
does in [`../docs/host-compatibility.md`](../docs/host-compatibility.md).

## Databases and shared state

Without configuration the store is [PGlite](https://pglite.dev): real
PostgreSQL compiled to WebAssembly, so there is nothing to install. It runs
in-process and serialises queries, so on PGlite the concurrency tests prove the
logic, not row locks.

`DATABASE_URL` switches to a PostgreSQL server (`src/db/pg.ts`), and nothing
above `src/db` knows the difference. `npm run test:pg` runs the whole suite
there, one schema per test database, so `test/concurrency.test.ts`,
`test/oauth-refresh.test.ts` and the fifty-way `test/contention.test.ts`
contend through a real connection pool. CI runs both.

`REDIS_URL` puts the shared state in Redis instead of each process's memory: rate-limit and
write-budget counters, used DPoP proof ids, sealed refresh responses, and
revocation events. With it, several processes can serve traffic without each
allowing the full rate limit or keeping internal tokens for a grant another
revoked. It fails closed: if Redis is unreachable, requests get 503, never a
free pass.

## Keys

The peppers, the MAC key and the signing keys come from the environment, from
`keys.json` beside the database, or, with `KMS_PROVIDER`, from an envelope file
whose secrets are encrypted under a KMS key and decrypted once at start-up.
With a KMS, the signing keys never leave it. `KMS_PROVIDER=local` is a software
KMS for development; a cloud provider is an adapter implementing the `Kms`
interface in `src/security/kms.ts`. Rotate with
`npm run keys -- rotate-pepper` (every 90 days) or `rotate-signing` (every 30).

## The account pages

`/account` on the authorization server: passkeys, password, and the apps that
can reach your devices. Passkeys are WebAuthn credentials bound to this host,
so a phishing page elsewhere cannot use them; they also appear as "Sign in
with a passkey" on the authorization login page. `/account/apps` lists every
grant, and lets you disconnect one, sign out everywhere, or change the
password, which also signs out everywhere. Adding a passkey or a password needs
a sign-in in the last fifteen minutes.

## One process, or four

`npm start` runs everything in one process (profile S). `src/entry/` holds
profile M: the authorization server, the MCP resource server, the API gateway
and the Device Service as separate processes. The edges hold no database
credentials. They verify callers by introspection and get internal tokens by
exchange, both over mutual TLS, and those tokens are bound to the edge's client
certificate. `docker-compose.profile-m.yml` runs it with a local CA
(`npm run certs`).

## Logs and metrics

Every log line goes through `src/observability/log.ts`: JSON, allowlisted
fields only, and anything token-shaped replaced and counted. Security counters
(refresh rotation and theft, DPoP refusals by reason, challenges, CIMD fetches,
write budgets, cache hit ratios) are served in Prometheus format on
`METRICS_PORT`, loopback only. Alerts are raised in-process as `level: alert`
lines; `../ops/alerts.yml` has the same rules for Prometheus. `npm run load`
drives the tool-call and refresh paths against a running server.

## Known limits

- Rate limits are shared across processes only with `REDIS_URL`. `TRUST_PROXY`
  is off unless set, because trusting `X-Forwarded-For` unconditionally lets a
  client forge `req.ip` and walk around the limit. Credential submissions are
  bucketed by address; the token endpoint is not, because hosts call it from
  their own infrastructure on behalf of every one of their users.
- No cloud KMS adapter is built in; `local` is the only provider.
- Device names fold with NFKC plus lowercase, which is not full Unicode case
  folding — "Straße" and "STRASSE" remain distinct devices. Usernames are
  unaffected because validation restricts them to ASCII first.
- `USERNAME_TAKEN` is not in the spec's section 6.3 table, which covers only
  the device API. Sign-up needs a distinct code so the client can highlight the
  username field.
