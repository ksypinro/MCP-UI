# Code flow

A walk through what actually executes, file by file, for each kind of request.
If you are trying to find where something happens, start here.

Companion documents: [Architecture](./architecture.md) ·
[Sequence diagrams](./sequence-diagrams.md)

---

## Startup

`server/src/index.ts` (profile S; profile M starts one component per process
from `src/entry/`)

```
loadKeys()                     peppers, MAC key, signing keys: env, key file or KMS
createDb(DATABASE_PATH)        PGlite, or PostgreSQL with DATABASE_URL; apply the schema
  └── db/migrations.ts
infrastructureFromEnvironment() buckets, DPoP replay, sealed responses, revocations:
                                memory, or Redis with REDIS_URL
createApp(db, infra)           build the Express app
  └── http/app.ts
listen(PORT)
setInterval(prune, 1h)         expired tokens, codes, pending authorizations, PAR, challenges
```

Each migration runs in its own transaction under an advisory lock, recorded in
`schema_migrations`. A half-applied schema is worse than an unapplied one.

The hourly sweep matters more than it looks: `oauth_access_tokens` is read on
**every** protected request, so leaving expired rows to accumulate degrades
latency with uptime rather than with load.

### Middleware order

`http/app.ts` builds the stack. Order is load-bearing.

```
withRequestId()                 correlation id on res.locals + x-request-id header
express.json({ limit: 64kb })   REST and MCP bodies
express.urlencoded()            the hosted pages; OAuth is form-encoded
GET /healthz
onHost(AUTH)  oauthRoutes       mounted at root — .well-known paths cannot move
onHost(MCP)   mcpRoutes         /mcp
onHost(API)   appLinkRoutes     /.well-known/apple-app-site-association
              accountRoutes     /v1/me
              deviceRoutes      /v1/devices*
notFound()
errorHandler({ jsonRpcPaths })  the single place an error becomes a response
```

`onHost` mounts a router only for requests addressed to its origin, so a page
or cookie of one surface can never be reached through another. With one origin
(local development) every router is mounted everywhere.

`express.urlencoded` is not optional. Without it the hosted login form and the
token, registration and revocation endpoints — all specified as form-encoded —
receive unparsed bodies and every one of them fails.

---

## A REST device request

`GET /v1/devices` from the iOS app, with `Authorization: DPoP <token>` and a
`DPoP` proof.

```
http/routes-devices.ts
  authenticate(verifier, { required: true })      http/middleware.ts
    credentialFrom(req)                           the token and its scheme
    verifier.oauth(token, [], { audience: API })  oauth/verify.ts, or introspection in profile M
      └── oauth_access_tokens ⋈ oauth_grants: expiry, revocation, audience
    no cnf.jkt                → 401: the API takes only DPoP-bound tokens
    verifyDpopProof(...)      oauth/dpop.ts: htm, htu, ath, jti, nonce, key
    → res.locals.ctx.caller = { kind: 'verified', accountId, clientId, grantId, scopes, … }

  callerOf(res)                                   throws UNAUTHENTICATED if absent
  exchange.run(caller, 'devices:read', …)         exchange-client.ts
    └── cached internal token, or exchangeToken()  oauth/exchange.ts
  devices.list(token, peer, requestId)            device-service/service.ts
    verifyInternalToken(token, peer, scope)       device-service/verify.ts
    listDevices(db, identity)                     domain/devices.ts
      └── SELECT … WHERE owner_id = $1 ORDER BY created_at, id
  res.json({ devices })
```

Ordering is a server contract (§4.3), so the read is already sorted and no
client re-sorts.

### The control path in detail

`PUT /v1/devices/:deviceId/state` spends the write budget
(`write-budgets.ts`), exchanges for a `devices:control` internal token, and
reaches `controlDevice` in `domain/devices.ts`:

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

The rejection audit is deliberately **outside**. Written inside, the rollback
that carries the rejection would also erase the record — and §11 asks for the
outcome of every attempt, not only the successful ones.

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
  gate(verifier, req, res, requestId, limits)   mcp/gate.ts  ← before the SDK sees anything
    protectedCallsIn(req.body)     every protected call, not the first
    verifier.oauth(token, union of their scopes)   audience: the MCP resource
    bound token?  → verifyDpopProof, or 401 invalid_dpop_proof + DPoP-Nonce
    rate limit    by address until a token verifies, then by grant
    no token   → 401 + WWW-Authenticate
    wrong scope→ 403 insufficient_scope
    otherwise  → caller { kind: 'verified', accountId, clientId, grantId, scopes, … }

  buildServer(deps, caller)    a fresh McpServer per request, stateless
    registerDeviceTools()      mcp/tools.ts
    registerUi()               mcp/resources.ts
  transport.handleRequest(req, res, req.body)
```

Why the gate cannot live in a tool handler: a refusal has to be an HTTP
status. Once a handler is running, its return value is already destined for a
`200`, and a `200` carrying `isError` is an application failure — the host
hands the text to the model and moves on. No authentication prompt appears.

Why it collects *every* protected call: a JSON-RPC body may be a batch and the
SDK executes all of it. Authorizing only the first would let a `devices:read`
token send `[list_devices, control_device]` and change a device.

### What a tool handler does

Very little, on purpose.

```ts
async ({ deviceId, state, expectedVersion }) => {
  const verified = verifiedOr(caller);
  if (!verified) return toolError(unauthenticated(), challenge);   // defence in depth
  try {
    const budget = await budgets.spend('control', verified.grantId, `${verified.accountId}:${deviceId}`);
    if (!budget.ok) return toolError(overBudget(budget.retryAfter));
    const device = await exchange.run(verified, 'devices:control',
      (token, peer) => devices.control(token, peer, verified.requestId, { deviceId, state, expectedVersion }));
    return { content: [{ type: 'text', text: describe(device) }], structuredContent: { device } };
  } catch (error) {
    return toolError(error);
  }
}
```

The handler never forwards the host's token. It exchanges it for a one-minute
internal token naming this adapter and the single scope the call needs.

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
  request_uri?  take the pushed request (single use) — required for iot-switch-ios
  resuming?     read the pending authorization by opaque id and re-render

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
  createPendingAuthorization()   server-side, addressed by an opaque id,
                                 bound to this browser by the __Host-pa cookie
  303 → /login, or /consent if the AS session is already signed in
```

The browser never carries the authorization context, only an opaque id. A
context round-tripped through the page would let anyone craft one naming their
own `redirect_uri` and PKCE challenge, walk a victim through a genuine login
page showing a spoofed client name, and collect a live code.

The consent screen names the **host of the `client_id` URL** for CIMD clients
— the document is self-asserted, so its `client_name` is whatever the client
felt like claiming — and for dynamically registered clients it names the
redirect actually selected by this request, not the first one registered.

### `POST /login`, `POST /consent`

```
oauth/authorize.ts
  loadStep(pending)            the pending authorization, and the browser it is bound to
  CSRF check                   a MAC over the pending id and the browser binding
  sign up or log in            domain/accounts.ts — one generic failure message
    (or POST /passkey/login    oauth/passkeys.ts — WebAuthn assertion)
  fresh AS session             oauth/session.ts — never an upgraded old one
  303 → /consent
/consent
  remembered consent?          oauth/consents.ts — same client, redirect host, scopes, document
  write scopes on an old session? → 303 back to sign in
  approve → claimAndIssueCode()   oauth/store.ts
    └── one transaction: DELETE … RETURNING the pending row, then insert the code
        claiming and minting together, or two submissions each get a valid code
  302 to redirect_uri with code, state, iss
```

The iOS client skips consent: it is pre-registered with fixed scopes, and its
request arrived by `POST /par`, so its parameters never passed through the
browser.

### `POST /token`

```
oauth/token.ts
  client_id required                       OAuth 2.1 §3.2.2
  DPoP proof, if any, verified first        a failed proof spends nothing
  consumeAuthorizationCode()               marks consumed, reports replay
    already consumed → revoke exactly the grant this code produced, if any
                       (a code burned by a failed exchange produced none)
  expired? client mismatch? redirect mismatch? PKCE? resource? DPoP key?
  establishGrant()                         one transaction:
    insert oauth_grants
    record grant_id on the code            so a later replay revokes the right thing
    issue access + refresh tokens          bound to the DPoP key, if any
```

A refresh (`grant_type=refresh_token`) locks the presented token's row, rotates
it, and seals the response for the grace window (`oauth/sealed.ts`); a
duplicate inside it gets the identical body, any other reuse revokes the grant.

---

## The iOS app

```
IoTSwitchApp
  └── SessionController(api, KeychainTokenStorage, WebAuthenticator, DPoPKeyring)
                                                      restores on launch
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

`authorized` gets a valid access token (refreshing first if under a quarter of
its life remains), runs the operation, and on `.unauthenticated` refreshes
**once** and retries. Refresh is single-flight: a caller arriving while one is
running waits for it. Every request, refresh included, carries a DPoP proof
signed by the Secure Enclave key. Only `invalid_grant` signs the person out.

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

Inlining is what lets `_meta.ui.csp` stay empty. Built once, with a hash of
each page in its URI (`ui://iot/devices.e824b396.html`), because hosts cache
these globally by URI — nothing account-specific may ever be compiled into one,
and changed code must be a new URI.

`bridge.js` exposes `window.mcpApp`:

| | |
| --- | --- |
| `start({ displayModes })` | handshake; call last, once handlers are registered |
| `callTool(name, args)` | resolves with `structuredContent`, rejects with `error.code` |
| `requestDisplayMode(mode)` | ask for fullscreen; resolves with the mode the host granted |
| `on(method, handler)` | additive — several listeners per notification |
| `reportSize()` | emits only when the value changed |

---

## Where to change things

| To change… | Go to |
| --- | --- |
| A business rule about devices | `server/src/domain/devices.ts` |
| What the Device Service accepts | `server/src/device-service/verify.ts` |
| A write budget | `server/src/write-budgets.ts` |
| An error code or status | `server/src/errors.ts` |
| Name matching | `server/src/normalize.ts` |
| The schema | `server/src/db/migrations.ts` — append, never edit |
| Which scope a tool needs | `server/src/mcp/policy.ts` |
| A tool's schema or description | `server/src/mcp/tools.ts` |
| What a view looks like | `server/src/mcp/ui/assets/` |
| The hosted sign-in and consent pages | `server/src/oauth/pages.ts` |
| Which clients are shown as verified | `KNOWN_CLIENTS`, default in `server/src/oauth/clients.ts` |
| Switch behaviour on iOS | `ios/IoTSwitch/ViewModels/DeviceControlService.swift` |
