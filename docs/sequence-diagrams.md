# Sequence diagrams

The flows that matter, in the order you are likely to need them. Each one is
what the code actually does — where a diagram simplifies, it says so.

Companion documents: [Architecture](./architecture.md) ·
[Code flow](./code-flow.md)

---

## 1. Native app — sign up and add the first device

Implements §10.1.

```mermaid
sequenceDiagram
    autonumber
    actor U as Person
    participant A as iOS app
    participant S as Server
    participant DB as Database

    U->>A: Sign Up, username + password
    A->>S: POST /v1/auth/signup
    S->>DB: INSERT accounts … ON CONFLICT DO NOTHING
    Note over S,DB: the unique index decides,<br/>not application code
    DB-->>S: account
    S->>DB: create session + access token
    S-->>A: account, accessToken, refreshToken
    A->>A: store in Keychain
    A->>S: GET /v1/devices
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
it.

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

    H->>S: POST /register
    S-->>H: client_id
    H->>B: open /authorize<br/>PKCE S256 + resource
    B->>S: GET /authorize
    S-->>B: hosted page — the only place a password is typed
    U->>B: username + password
    B->>S: POST /authorize
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

    H->>S: resources/read ui://iot/devices.html
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

Implements §7.1 and §7.2.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server
    participant DB as Database

    C->>S: POST /v1/auth/refresh (R1)
    S->>DB: SELECT … FOR UPDATE
    DB-->>S: not replaced, not revoked
    S->>DB: insert session S2, mark S1 replaced_by S2
    Note over S,DB: S1 is marked replaced but not<br/>revoked — its access token must<br/>live out its own TTL
    S-->>C: access token + R2

    rect rgba(160, 40, 40, 0.10)
    Note over C,S: later — R1 appears again
    C->>S: POST /v1/auth/refresh (R1)
    S->>DB: SELECT … FOR UPDATE
    DB-->>S: replaced_by is set
    Note over S: a legitimate client never<br/>replays a rotated token
    S->>DB: revoke the entire family
    S-->>C: 401
    end
```

The revocation happens **outside** the transaction that carries the refusal.
Performing it inside meant the rollback undid it, and a detected theft revoked
nothing.

---

## 6. A batch that tries to smuggle a write

The privilege escalation found in review, and what stops it now.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (devices:read)
    participant G as Gate
    participant SDK as MCP SDK

    C->>G: [ list_devices, control_device ]

    rect rgba(160, 40, 40, 0.10)
    Note over G: before — only the first<br/>protected call was authorized
    G->>SDK: devices:read satisfied, proceed
    SDK-->>C: both executed, and the device changed
    end

    rect rgba(40, 120, 60, 0.10)
    Note over G: now — every protected call,<br/>union of their scopes
    G-->>C: 403 insufficient_scope
    Note over G: nothing executes
    end
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
