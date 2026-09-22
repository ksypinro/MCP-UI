# Code flow

A walk through what actually executes, file by file, for each kind of request.
If you are trying to find where something happens, start here.

Companion documents: [Architecture](./architecture.md) ·
[Sequence diagrams](./sequence-diagrams.md)

---

## Startup

`server/src/index.ts`

```
createDb(DATABASE_PATH)        open PGlite, run migrations in order
  └── db/migrations.ts         001_init · 002_idempotency_fingerprint · 003_oauth
createApp(db)                  build the Express app
  └── http/app.ts
listen(PORT)
setInterval(prune, 1h)         expired sessions, tokens, codes, pending authorizations
```

Migrations run inside a transaction each, recorded in `schema_migrations`. A
half-applied schema is worse than an unapplied one.

The hourly sweep matters more than it looks: `access_tokens` and `sessions`
are joined on **every** protected request, so leaving them to accumulate
degrades latency with uptime rather than with load.

### Middleware order

`http/app.ts` builds the stack. Order is load-bearing.

```
withRequestId()                 correlation id on res.locals + x-request-id header
express.json({ limit })         REST bodies
express.urlencoded()            the hosted login form; OAuth is form-encoded
GET /healthz
oauthRoutes(db)                 mounted at root — .well-known paths cannot move
mcpRoutes(db)                   /mcp
authRoutes(db)                  /v1/auth/*
deviceRoutes(db)                /v1/devices*
notFound()
errorHandler({ jsonRpcPaths })  the single place an error becomes a response
```

`express.urlencoded` is not optional. Without it the hosted login form and the
token, registration and revocation endpoints — all specified as form-encoded —
receive unparsed bodies and every one of them fails.

---

## A REST device request

`GET /v1/devices` with a bearer token.

```
http/routes-devices.ts
  authenticate(db, { required: true })     http/middleware.ts
    bearerFrom(req)
    verifyAccessToken(db, token)           domain/sessions.ts
      └── SQL: access_tokens ⋈ sessions, checking expiry and revocation
    → res.locals.ctx.identity = { accountId, channel: 'native', requestId }

  identityOf(res)                          throws UNAUTHENTICATED if absent
  listDevices(db, identity)                domain/devices.ts
    └── SELECT … WHERE owner_id = $1 ORDER BY created_at, id
  res.json({ devices })
```

Ordering is a server contract (§4.3), so the read is already sorted and no
client re-sorts.

### The control path in detail

`PUT /v1/devices/:deviceId/state` → `controlDevice` in `domain/devices.ts`:

```
validate state ∈ {on, off}                 → INVALID_STATE
validate expectedVersion is a positive int → VALIDATION_FAILED

db.transaction:
  UPDATE devices
     SET state, version = version + 1, updated_at = now()
   WHERE id AND owner_id AND version = expected AND state <> desired
   RETURNING *

  if a row came back:
      audit inside the transaction   ← the record and the change land together
      return { ok: true }

  no row — one read classifies which of three cases it was:
      not ours            → DEVICE_NOT_FOUND
      version mismatch    → DEVICE_VERSION_CONFLICT
      already that state  → return unchanged, no version consumed

after the transaction:
  if it was a version conflict, audit the rejection in its own transaction
  throw AppError
```

The rejection audit is deliberately **outside**. Writing it inside meant the
rollback that carried the rejection also erased the record — and §11 asks for
the outcome of every attempt, not only the successful ones.

### Creation

```
db.transaction:
  if an idempotency key was sent, look it up
      fingerprint mismatch → VALIDATION_FAILED   ← a key is a promise that this
                                                    is the same request
  SELECT 1 FROM accounts WHERE id = $1 FOR UPDATE
      ↑ the device cap has no constraint behind it, unlike name uniqueness,
        so creates for one account serialise here
  count, compare to the cap
  INSERT … ON CONFLICT ON CONSTRAINT devices_owner_name_key DO NOTHING RETURNING *
      no row → the name is taken
  record the idempotency key
  audit
```

---

## An MCP tool call

`POST /mcp` — the gate is the whole point.

```
mcp/routes.ts
  rate limit                   by token when present, by address when anonymous
  gate(db, req, res)           mcp/gate.ts  ← before the SDK sees anything
    protectedCallsIn(req.body)     every protected call, not the first
    verifyOAuthAccessToken(db, token, union of their scopes)   oauth/verify.ts
      └── oauth_access_tokens ⋈ oauth_grants, expiry, revocation, audience
    no token   → 401 + WWW-Authenticate
    wrong scope→ 403 insufficient_scope
    otherwise  → Identity { accountId, channel: 'mcp', requestId }

  buildServer(db, identity)    a fresh McpServer per request, stateless
    registerDeviceTools()      mcp/tools.ts
    registerUi()               mcp/resources.ts
  transport.handleRequest(req, res, req.body)
```

Why the gate cannot live in a tool handler: a refusal has to be an HTTP
status. Once a handler is running, its return value is already destined for a
`200`, and a `200` carrying `isError` is an application failure — the host
hands the text to the model and moves on. No authentication prompt appears.

Why it collects *every* protected call: a JSON-RPC body may be a batch and the
SDK executes all of it. Authorizing only the first let a `devices:read` token
send `[list_devices, control_device]` and change a device.

### What a tool handler does

Very little, on purpose.

```ts
async ({ deviceId, state, expectedVersion }) => {
  if (!identity) return toolError(unauthenticated());   // defence in depth
  try {
    const device = await controlDevice(db, identity, { deviceId, state, expectedVersion });
    return { content: [{ type: 'text', text: describe(device) }],
             structuredContent: { device } };
  } catch (error) {
    return toolError(error);
  }
}
```

`toolError` returns `isError`, human text, and the code in
`_meta['iot/error']` — and **no** `structuredContent`. A client validates
structured output against the declared `outputSchema` whenever it is present,
including on an error, so an error shaped `{error:{…}}` against a schema
describing `{device}` reaches the caller as a protocol error rather than as
the conflict.

---

## The OAuth flow

### `GET /authorize`

```
oauth/authorize.ts
  resuming?  read the pending authorization by opaque id and re-render

  resolveClient(db, client_id)                oauth/clients.ts
    https:// → Client ID Metadata Document
        resolvePinnedAddress()   refuse loopback, private, link-local, CGNAT
        fetchPinned()            connect to the address that was checked;
                                 TLS still verifies the hostname via SNI
        require self-referential client_id, cap the body, refuse redirects
    otherwise → a registered client, redirect URIs from the row

  redirectUriAllowed()                        exact, except loopback ignores port

  ── until both of the above pass, errors render on our own page.
     Redirecting to an unvalidated URI would make this an open redirector. ──

  response_type = code, PKCE S256, resource matches, scope non-empty
  createPendingAuthorization()   server-side, addressed by an opaque id
  render the hosted page
```

The browser never carries the authorization context. An earlier revision
round-tripped it as unsigned base64, which let anyone craft one naming their
own `redirect_uri` and PKCE challenge, walk a victim through a genuine login
page showing a spoofed client name, and collect a live code.

The consent screen names the **host of the `client_id` URL** for CIMD clients
— the document is self-asserted, so its `client_name` is whatever the client
felt like claiming — and for dynamically registered clients it names the
redirect actually selected by this request, not the first one registered.

### `POST /authorize`

```
read the pending authorization
sign up or log in            domain/accounts.ts — one generic failure message
claimAndIssueCode()          oauth/store.ts
  └── one transaction: DELETE … RETURNING, then insert the code
      claiming and minting together, or two submissions each get a valid code
302 to redirect_uri with code, state, iss
```

### `POST /token`

```
oauth/token.ts
  client_id required                       OAuth 2.1 §3.2.2
  consumeAuthorizationCode()               marks consumed, reports replay
    already consumed → revoke exactly the grant this code produced, if any
                       (a code burned by a failed exchange produced none)
  expired? client mismatch? redirect mismatch? PKCE? resource?
  establishGrant()                         one transaction:
    insert oauth_grants
    record grant_id on the code            so a later replay revokes the right thing
    issue access + refresh tokens
```

---

## The iOS app

```
IoTSwitchApp
  └── SessionController(api, KeychainTokenStorage)   restores on launch
      └── RootView
          ├── AuthView              signed out
          └── DevicesView           signed in, keyed by account id
              ├── DevicesViewModel
              ├── DeviceDetailView → DeviceDetailViewModel
              └── AddDeviceView    → AddDeviceViewModel
```

Every authenticated call goes through one function:

```swift
session.authorized { token in
    try await api.controlDevice(id:state:expectedVersion:accessToken: token)
}
```

`authorized` runs the operation, and on `.unauthenticated` refreshes **once**
and retries. Refresh is single-flight: a caller arriving while one is running
waits for it. The backend revokes an entire token family on a replayed refresh
token, so two racing refreshes would not duplicate work — they would sign the
person out of every device.

`DeviceControlService.control` is §5.6 in one place, returning a closed set of
outcomes: `.updated`, `.conflict`, `.notFound`, `.unknown(reconciled:)`,
`.rejected`, `.signedOut`. Both screens consume the same enum.

Loads are sequence-numbered and merge rather than replace, so a refresh that
was already in flight cannot overwrite a newer one, and a read begun before a
control cannot land afterwards and undo it.

---

## The views

```
uiResources()                    server/src/mcp/ui/index.ts, built once at startup
  page(title, body, script)
    styles.css  +  bridge.js  +  <view>.js     all inlined
```

Inlining is what lets `_meta.ui.csp` stay empty. Built once and cached,
because hosts cache these globally by URL — nothing account-specific may ever
be compiled into one.

`bridge.js` exposes `window.mcpApp`:

| | |
| --- | --- |
| `start({ displayModes })` | handshake; call last, once handlers are registered |
| `callTool(name, args)` | resolves with `structuredContent`, rejects with `error.code` |
| `requestDisplayMode(mode)` | ask for fullscreen |
| `on(method, handler)` | additive — several listeners per notification |
| `reportSize()` | emits only when the value changed |

---

## Where to change things

| To change… | Go to |
| --- | --- |
| A business rule about devices | `server/src/domain/devices.ts` |
| An error code or status | `server/src/errors.ts` |
| Name matching | `server/src/normalize.ts` |
| The schema | `server/src/db/migrations.ts` — append, never edit |
| Who may call a tool | `server/src/mcp/config.ts` |
| A tool's schema or description | `server/src/mcp/tools.ts` |
| What a view looks like | `server/src/mcp/ui/assets/` |
| The OAuth consent page | `server/src/oauth/pages.ts` |
| Switch behaviour on iOS | `ios/IoTSwitch/ViewModels/DeviceControlService.swift` |
