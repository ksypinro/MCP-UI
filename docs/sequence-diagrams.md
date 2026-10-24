# Sequence diagrams

The flows that matter, in the order you are likely to need them. Each one is
what the code actually does — where a diagram simplifies, it says so.

Companion documents: [Architecture](./architecture.md) ·
[Code flow](./code-flow.md)

---

## 1. Native app — sign up and add the first device

Implements §10.1. The app never sees the password: it is typed on the hosted
page, in the system browser sheet.

```mermaid
sequenceDiagram
    autonumber
    actor U as Person
    participant A as iOS app
    participant B as Browser sheet
    participant S as Server
    participant DB as Database

    U->>A: Sign Up
    A->>A: PKCE pair, state, Secure Enclave key thumbprint
    A->>S: POST /par (challenge, state, dpop_jkt, prompt=create)
    S-->>A: request_uri (single use, 60 s)
    A->>B: open /authorize?client_id&request_uri
    U->>B: username + password, on the hosted page
    B->>S: POST the sign-up form
    S->>DB: INSERT accounts … ON CONFLICT DO NOTHING
    Note over S,DB: the unique index decides,<br/>not application code
    S-->>B: redirect to callback (code, state, iss)
    B-->>A: callback
    A->>A: check iss, then state
    A->>S: POST /token (code, verifier) + DPoP proof
    S->>DB: grant + tokens, bound to the key (cnf_jkt)
    S-->>A: access token (10 min, memory) + refresh token (Keychain)
    A->>S: GET /v1/devices, Authorization: DPoP + proof
    S-->>A: { devices: [] }
    A-->>U: empty state, "Add a device"

    U->>A: "Bedroom Lamp"
    A->>S: POST /v1/devices (Idempotency-Key)
    S->>DB: lock owner row, count, insert
    Note over S,DB: the cap has no constraint<br/>behind it, so creates serialise
    DB-->>S: device, state off, version 1
    S-->>A: 201
    A-->>U: the device, with a switch
```

---

## 2. Controlling a switch, and losing a race

Implements §5.6 and §6.1. This is the most carefully specified flow in the
product.

```mermaid
sequenceDiagram
    autonumber
    actor U as Person
    participant V as View model
    participant S as Server
    participant DB as Database

    U->>V: flips the switch
    Note over V: capture id, desired state,<br/>and the version on screen
    V->>V: pending intent — switch inert
    V->>S: PUT /v1/devices/{id}/state<br/>{ state, expectedVersion }

    alt version matches, state differs
        S->>DB: UPDATE … WHERE version = $expected AND state <> $1
        DB-->>S: 1 row
        S-->>V: 200, the device
        V->>V: adopt the server's device
    else version matches, state already correct
        S->>DB: UPDATE matches nothing
        S->>DB: read to classify
        S-->>V: 200, unchanged
        Note over S: no version consumed,<br/>no updatedAt change
    else version is stale
        S->>DB: UPDATE matches nothing
        S->>DB: read to classify
        S-->>V: 409 DEVICE_VERSION_CONFLICT
        V->>S: GET /v1/devices/{id}
        S-->>V: the current device
        V-->>U: "changed somewhere else. It is now On."
    end
```

### The unknown outcome

The case everything else is arranged around: a write whose response was lost.

```mermaid
sequenceDiagram
    autonumber
    participant V as View model
    participant S as Server

    V->>S: PUT …/state
    S--xV: connection dropped
    Note over V: the write may or may not<br/>have been applied

    V->>V: APIError.unknownOutcome
    V->>S: GET /v1/devices/{id}
    alt the read succeeds
        S-->>V: the device
        V-->>V: adopt it and say what it is
    else the read fails too
        V-->>V: keep the confirmed state,<br/>admit we do not know
    end
```

**Never** infer success, and **never** send the inverse command. That is how a
switch ends up flipping itself back.

---

## 3. An MCP host connecting for the first time

Implements §10.3 and AC-24. The host does the work; nothing is hard-coded in
it. Claude and ChatGPT both identify themselves by a Client ID Metadata
Document; a host without one registers at `POST /register` first.

```mermaid
sequenceDiagram
    autonumber
    actor U as Person
    participant H as MCP host
    participant B as Browser
    participant S as Server

    H->>S: POST /mcp — initialize
    S-->>H: 200
    Note over H,S: anonymous discovery works:<br/>a host can look before signing in
    H->>S: tools/list
    S-->>H: 7 tools

    H->>S: tools/call list_devices
    S-->>H: 401 + WWW-Authenticate<br/>resource_metadata, scope
    Note over S: a transport status, never<br/>200 with isError

    H->>S: GET /.well-known/oauth-protected-resource/mcp
    S-->>H: resource, authorization_servers
    H->>S: GET /.well-known/oauth-authorization-server
    S-->>H: endpoints, S256, CIMD, iss

    H->>B: open /authorize<br/>client_id = its CIMD URL, PKCE S256, resource
    B->>S: GET /authorize
    S->>S: fetch and check the metadata document
    S-->>B: hosted sign-in — the only place a password is typed
    U->>B: passkey, or username + password
    B->>S: POST /login
    S-->>B: consent: client host, redirect host, scopes
    U->>B: Allow
    B->>S: POST /consent
    S->>S: claim pending + mint code, one transaction
    S-->>B: 302 with code, state, iss
    B-->>H: code
    H->>S: POST /token — code + verifier + resource
    S-->>H: access token, audience-bound

    H->>S: tools/call list_devices + bearer
    S-->>H: the devices
```

---

## 4. A view, its host, and the server

Implements §9.2. The triangle people get wrong.

```mermaid
sequenceDiagram
    autonumber
    actor U as Person
    participant V as View (WebView)
    participant H as Host
    participant S as Server

    H->>S: resources/read ui://iot/devices.<hash>.html
    S-->>H: HTML, the mcp-app content type
    H->>V: render, sandboxed

    Note over V: listeners registered<br/>*before* the handshake
    V->>H: ui/initialize
    H-->>V: hostCapabilities, hostContext
    V->>H: ui/notifications/initialized
    H--)V: ui/notifications/tool-result
    V->>V: render from what the host pushed

    U->>V: flips a switch
    V->>H: tools/call control_device
    Note over H: the host decides —<br/>it may ask the person first
    H->>S: tools/call + its token
    S-->>H: result
    H-->>V: result
    V->>V: adopt it
```

The view never reaches the server. It holds no token and has no network of its
own; the host owns the connection.

---

## 5. Refresh rotation, and a stolen token

Implements §7.1 and §7.2, for hosts and the app alike (`rotateRefresh` in
`oauth/store.ts`). A refresh token bound to a DPoP key also needs a proof from
that key.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Authorization server
    participant DB as Database

    C->>S: POST /token refresh_token=R1
    S->>DB: SELECT … FOR UPDATE
    DB-->>S: not replaced, grant live
    S->>DB: insert R2, mark R1 replaced (replaced_at), issue access token
    S->>S: seal the response for 30 s
    S-->>C: access token + R2

    alt R1 again within 30 s, R2 never used (a race or a lost response)
        C->>S: POST /token refresh_token=R1
        S-->>C: the identical sealed response
    else R1 again later, or after R2 was used
        C->>S: POST /token refresh_token=R1
        Note over S: a legitimate client never<br/>replays a rotated token
        S->>DB: revoke the whole grant
        S-->>C: 400 invalid_grant
    end
```

The outgoing access token is not revoked by rotation: it expires on its own
schedule, so requests a client had in flight when it refreshed proactively
still succeed. The revocation on reuse happens **outside** the transaction that
carries the refusal, so the rollback cannot undo it.

---

## 6. A batch that tries to smuggle a write

Why the gate authorizes every protected call in a body, not the first.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (devices:read)
    participant G as Gate
    participant SDK as MCP SDK

    C->>G: [ list_devices, control_device ]

    Note over G: every protected call,<br/>union of their scopes:<br/>devices:read + devices:control
    G-->>C: 403 insufficient_scope
    Note over G,SDK: nothing executes. Authorizing only the first<br/>call would let the SDK run both, and change the device
```

---

## 7. Two writers, one version

AC-10, and why the check lives in SQL.

```mermaid
sequenceDiagram
    autonumber
    participant A as Client A
    participant B as Client B
    participant DB as Database

    Note over A,B: both read version 1

    par
        A->>DB: UPDATE … WHERE version = 1
    and
        B->>DB: UPDATE … WHERE version = 1
    end

    DB-->>A: 1 row — now version 2
    DB-->>B: 0 rows
    Note over B: reads to classify,<br/>reports a conflict

    Note over DB: exactly one version consumed.<br/>No lost update, because the check<br/>and the write are one statement.
```
