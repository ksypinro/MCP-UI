# IoT Device Control — Application Requirements

Version: 1.1 draft  
Date: 2026-09-21  
Supersedes: 1.0 draft  
Primary platform: iOS, with responsive support for iPad  
Working product name: IoT Switch

## 0. Revision notes (1.0 → 1.1)

Version 1.0 was internally coherent but rested on host-platform facts that no longer hold, and on two specification revisions that have since been superseded. This revision changes the following. Section 15 records the sources and the date they were verified.

1. **Host reach corrected.** ChatGPT custom MCP connectors are documented as web-only. Claude is the only target host that runs this integration on an iPhone. In both hosts the connector is installed from web or desktop, never from the phone. See §2, §10.3, §12.
2. **The first-party inline-credential profile is removed.** §7.4 of version 1.0 defined a presentation profile for "a first-party host under our control," which §2.2 simultaneously placed outside version 1. Host-managed OAuth on a hosted page is now the only credential-entry path in version 1.
3. **Authorization updated from MCP `2025-11-25` to `2026-07-28`:** Client ID Metadata Documents preferred over now-deprecated Dynamic Client Registration, RFC 8707 `resource` parameter required, RFC 9207 `iss` validation added, and a `scope` parameter required in the `401` challenge.
4. **MCP Apps pinned to the released `2026-01-26` extension** rather than the pre-release overview, with real `_meta.ui` field names, the host-bridge correction, and Claude's inline-card constraints applied to §9.
5. **Domain gaps closed:** `normalizedName` added to Device, normalization folds defined, a complete error-code enum, a list ordering contract, a per-account device cap, and explicit no-op `updatedAt` behavior.
6. **Sequencing changed.** §13 gains a step 0 feasibility spike so the host-dependent unknowns are settled before the native application is built.

## 1. Product objective

Build an application that simulates controlling a user's IoT devices. Each device has exactly two persisted states: **On** and **Off**. A user can create an account, log in, add a device, view their devices, inspect one device, and change its state with a switch.

The same account and devices must be accessible through the main iOS application and through an MCP server. Compatible AI clients must be able to display an interactive MCP App with device lists, device details, switches, an add-device form, and an authentication entry screen, to the extent each host supports rendering server-supplied UI.

The main backend has exactly four device operations:

1. Fetch all devices owned by the authenticated user.
2. Fetch one device owned by the authenticated user.
3. Set a device to On or Off.
4. Add a device for the authenticated user.

Authentication is an additional logical service, with its own endpoints. It does not count toward the four device APIs.

## 2. Scope and working assumptions

The following assumptions make this draft implementable. They are proposed defaults, not additional user-confirmed requirements. Rows marked **verified** were checked against host documentation on the date in §15.

| Decision | Working assumption |
| --- | --- |
| Device behavior | Version 1 simulates devices in a database. No physical hardware connection. |
| Main application | A native iOS application provides the complete device-control experience. |
| External MCP clients | **Claude** — web, desktop, iOS, and Android — is the only target host that renders this integration on a phone. **ChatGPT** — web only; developer mode and custom MCP connectors are documented as available to Pro, Plus, Business, Enterprise, and Education accounts on the web, and connector setup cannot be completed in the ChatGPT mobile apps. *(verified)* |
| Connector installation | In Claude, a custom connector must be added on web or desktop before it appears on mobile. In ChatGPT, developer-mode setup is performed on the web. No end-to-end flow begins on the phone. *(verified)* |
| Host write approval | A host may require explicit user confirmation for every write tool call, and may re-prompt in each new conversation. ChatGPT documents this behavior for developer mode. Switch and add-device interactions must remain correct when each write is individually approved or declined. *(verified)* |
| User ownership | Each device belongs to exactly one account. No shared households or administrators. |
| New device state | Every new device starts Off. |
| Device names | Required; unique within the owner's account under the normalization fold defined in §4.2. |
| Authentication | Exactly two credential inputs: username and password. |
| Authentication presentation | Credentials are entered only on our hosted authorization page, reached through the host's OAuth flow. No credential entry occurs inside an MCP App, a tool argument, or a conversation. |
| Minimum OS version | iOS 17.0, pending confirmation against the selected Swift toolchain. Raise to 18.0 only if a required API demands it. |

### 2.1 Included in version 1

- Native iOS sign-up, login, logout, device list, device detail, add device, and state control.
- Persistent accounts and simulated device states.
- Four authenticated device APIs and an authentication service.
- An MCP server that exposes the four device operations as tools.
- MCP App resources for authentication entry, device list, device detail, and adding a device.
- Username/password authentication with account isolation across all entry points.
- Validation of the native app on iPhone and iPad.
- Validation of the MCP UI flows in Claude on iPhone and on web, and in ChatGPT on web.

### 2.2 Outside version 1

- Real device discovery, pairing, Bluetooth, Matter, HomeKit, MQTT, or vendor adapters.
- Additional device states, telemetry, schedules, rooms, scenes, or bulk control.
- Device deletion, renaming, ownership transfer, or sharing.
- Social login, email/phone sign-up, password recovery, and multi-factor authentication.
- Push notifications, background monitoring, and offline queued mutations.
- A custom AI chat client or a general-purpose MCP host inside the native iOS app. These are optional extensions, not prerequisites for controlling devices. Because no such host exists in version 1, no requirement in this document may depend on one.
- Account deletion and data export. If the service is ever exposed beyond demo use, both must be added before public sign-up is opened.

## 3. Architecture and responsibilities

```text
Native iOS application ──── authenticated device API ────┐
                                                         ├── Device service ── Database
MCP host (Claude / ChatGPT) ── authenticated MCP ── MCP server
        │                                                │
        └── Sandboxed MCP App UI ── host bridge ─────────┘
              postMessage to the HOST; the host forwards
              tools/call to the server. The UI never holds a
              token and never calls the server directly.

Native app / host authorization ──── Authentication service
                                   ├── Accounts and password verification
                                   ├── Sessions and token issuance/revocation
                                   └── OAuth 2.1 authorization server and
                                       hosted username/password page
```

| Component | Required responsibility |
| --- | --- |
| Native iOS application | Native screens, secure local session handling, device API calls, and presentation state. |
| Device service | Device validation, ownership checks, state changes, concurrency handling, and persistence. |
| Authentication service | Registration, login, session lifecycle, OAuth authorization for external MCP hosts, and account identity. |
| MCP server | Translate validated tool requests into device-service operations; expose UI resources; enforce authorization on every request. |
| MCP App | Present interactive web UI using the host bridge; render authoritative results and collect non-secret device input. |
| External MCP host | Tool execution orchestration, UI sandbox, user approvals, and host-managed OAuth. |

The device API and MCP tools must use the same business rules and database. They must not maintain separate copies of a user's devices. The MCP adapter may invoke an internal service interface or authenticated internal API; it must preserve the verified caller identity.

The MCP App's bridge terminates at the **host**, not at our server. The app issues `tools/call` over `postMessage`; the host decides whether to forward it, applies its own approval rules, and returns the result. Our server sees an ordinary authenticated tool call and cannot distinguish one originated by the app from one originated by the model, except through the tool arguments themselves.

These are logical boundaries. A modular backend deployment is sufficient for version 1; separate microservices are not required.

## 4. Domain model and rules

### 4.1 Account

| Field | Rule |
| --- | --- |
| `id` | Server-generated immutable account identifier. |
| `username` | Display value; 3–32 characters from the ASCII set `A–Z`, `a–z`, `0–9`, `.`, `_`, `-`. Must start and end with a letter or digit. Surrounding whitespace is trimmed before validation. |
| `normalizedUsername` | Unique lookup value. Derived as: trim, Unicode NFKC normalize, then Unicode case-fold. Stored in its own column with a database `UNIQUE` constraint. |
| `passwordHash` | Salted password hash; never returned to a client. |
| `createdAt` | Server-generated UTC timestamp. |

The username charset is deliberately restricted to ASCII so that the fold is deterministic and homograph collisions are impossible. Widening it later requires a confusable-detection policy, not just a charset change.

Proposed password policy: 12–128 characters, allow spaces and password-manager generated values, and do not silently trim or truncate. Sign-up and login have no email, phone, or password-confirmation field.

### 4.2 Device

| Field | Rule |
| --- | --- |
| `id` | Server-generated immutable identifier. |
| `ownerId` | Derived from authenticated identity; not accepted from a device creation request. |
| `name` | Trimmed display name, 1–64 characters after trimming, at least one non-whitespace character. |
| `normalizedName` | Uniqueness key within an owner. Derived as: trim, collapse internal whitespace runs to a single space, Unicode NFKC normalize, then Unicode case-fold. Covered by a database `UNIQUE (ownerId, normalizedName)` constraint. |
| `state` | Exactly `on` or `off`; new devices start `off`. |
| `version` | Integer starting at 1; incremented only when the persisted state actually changes. |
| `createdAt` | Server-generated UTC timestamp. |
| `updatedAt` | UTC timestamp of the most recent persisted change. A control request that does not change the state does not advance `updatedAt`. |

`normalizedName` is an internal field. It is not returned to clients and is not displayed. `name` preserves exactly what the user typed after trimming and whitespace collapse.

Client-visible device example:

```json
{
  "id": "dev_01",
  "name": "Bedroom Lamp",
  "state": "off",
  "version": 1,
  "createdAt": "2026-09-21T10:00:00Z",
  "updatedAt": "2026-09-21T10:00:00Z"
}
```

### 4.3 Business rules

- A user can access only devices they own, regardless of whether they use REST, an MCP tool, or an embedded UI.
- Device IDs are the authoritative control targets. The assistant must resolve a device name to an owned device ID before control.
- State changes express the desired state explicitly: `on` or `off`. There is no backend `toggle` operation whose outcome could reverse on retry.
- Loading, updating, unavailable network, and errors are UI states, not additional device states.
- A successful mutation means the simulated state has been persisted. The UI must not claim that physical hardware changed.
- No starter devices are created automatically for a new account. The empty state prompts the user to add one.
- Version checks and updates must be atomic. Two requests based on the same version cannot both overwrite each other silently.
- **Ordering is a server contract.** Owned devices are always returned ascending by `createdAt`, with `id` ascending as the tie-breaker. Clients render the order they receive and do not re-sort.
- **A device cap of 100 per account applies.** Creation beyond the cap fails with `DEVICE_LIMIT_REACHED` and creates nothing.

## 5. Main iOS application design

### 5.1 Navigation and appearance

- Use a native navigation stack with **Devices** as the authenticated landing screen.
- Provide **Add Device** from the Devices toolbar and an account menu containing the username and **Log Out**.
- Open device details from a device row; the switch remains an independent control.
- Use an add-device sheet on iPhone and an appropriately sized presentation on iPad.
- Support light/dark appearance, safe areas, Dynamic Type, VoiceOver, and comfortable touch targets of at least 44 × 44 points.
- Show both text and switch position for On/Off; color alone must not communicate state.
- Keep the device name and switch visible at narrow widths and large text sizes.

### 5.2 Authentication screen

- Present **Log In** and **Sign Up** modes with exactly two credential fields: **Username** and **Password**.
- Mask the password by default and provide a Show/Hide control.
- Support password autofill, paste, and the appropriate keyboard/content types.
- Show validation errors adjacent to the affected field and a readable form-level error for failed authentication.
- Disable repeat submissions while a request is in progress.
- After successful sign-up, establish a session and open the empty Devices screen.
- After login, fetch the user's devices. If a safe read-only destination was pending, restore it.
- Do not automatically execute a previously attempted add/control action merely because login succeeded; obtain a fresh user action or honor the external host's explicit approval flow.

### 5.3 Devices screen

Each row contains a generic device icon, name, explicit On/Off label, and switch. Required states:

| State | Required presentation |
| --- | --- |
| Initial loading | Progress indication without fabricated devices or states. |
| Empty | "No devices yet" and an Add Device action. |
| Loaded | All owned devices in the server-supplied order defined in §4.3. |
| Refreshing | Preserve the visible list while refreshing. |
| Updating a device | Disable that device's switch and show progress; other rows remain usable. |
| Load failure | Explain that devices could not be loaded and provide Retry. |
| Stale cached data | Identify it as previously fetched data; do not imply a fresh state. |
| Session expired | Clear protected content and show authentication. |

Pull-to-refresh and returning to the foreground must fetch fresh data. Version 1 does not promise immediate push synchronization between separate clients.

### 5.4 Device detail screen

- Display the device name, state, switch, device ID, and last-updated time.
- Fetch the latest device when the screen opens.
- Use the same control behavior as the list.
- Show a readable unavailable/not-found state when access is no longer valid.

### 5.5 Add Device screen

- Required input: **Device Name** only.
- Explain that the new device starts Off.
- Provide Add Device and Cancel actions.
- Preserve the entered name on validation/network failure.
- On success, dismiss the form, update/refetch the list, and identify the new device.
- On a name conflict (`DEVICE_NAME_CONFLICT`), show "A device with this name already exists" and retain the input.
- On reaching the cap (`DEVICE_LIMIT_REACHED`), explain the limit and retain the input.

### 5.6 Switch behavior

1. The user changes a switch.
2. Capture the device ID, desired state, and current version.
3. Display an updating state and prevent duplicate interaction with that switch.
4. Submit the control request.
5. On success, replace the displayed device with the server response.
6. On rejection, retain/restore the confirmed state and show the error.
7. On a version conflict, refetch and explain that the device changed elsewhere.
8. On a timeout with an unknown outcome, fetch the device before offering a retry. Never infer success or issue an inverse operation.

Optimistic visual motion is allowed, but the interface must distinguish pending intent from confirmed state.

## 6. Device API requirements

All endpoints are served over HTTPS and require a valid user access token. Requests and responses use JSON. No endpoint accepts an authoritative `ownerId` from the caller.

| Operation | Method and path | Input | Success response |
| --- | --- | --- | --- |
| Fetch all devices | `GET /v1/devices` | None | `200 { "devices": [Device] }` |
| Fetch particular device | `GET /v1/devices/{deviceId}` | Device ID in path | `200 { "device": Device }` |
| Control device | `PUT /v1/devices/{deviceId}/state` | `{ "state": "on" or "off", "expectedVersion": integer }` | `200 { "device": Device }` |
| Add device | `POST /v1/devices` | `{ "name": string }`, optional `Idempotency-Key` header | `201 { "device": Device }` |

The list endpoint returns the full owned list, in the order defined in §4.3. Pagination can be added in a later version without introducing another business operation.

### 6.1 Control semantics

- `expectedVersion` is required and must match the current version; otherwise return `409 DEVICE_VERSION_CONFLICT` without mutation.
- When the version matches and the requested state already matches, return the current device unchanged: no version increment, no `updatedAt` change.
- When the version matches and the state differs, persist the target state and increment the version atomically. The reference implementation is a single conditional statement whose affected-row count is checked:

  ```sql
  UPDATE devices
     SET state = :state, version = version + 1, updated_at = now()
   WHERE id = :id AND owner_id = :owner AND version = :expected_version;
  ```

  Zero affected rows means either a version conflict or a non-owned device; the two are distinguished by a follow-up ownership read, and a non-owned device yields `404` per §6.3.
- Repeated requests never invert the state. A retry carrying an old version may receive a conflict and must reconcile through a read.
- **This operation is deliberately not idempotent.** Replaying a successful request with the consumed version returns `409`. The corresponding MCP tool annotation must say so (§8.3).
- The native UI and MCP App obtain versions from their latest read; an assistant must fetch a device before controlling it when it has no current version.

### 6.2 Creation and retry semantics

- Derive the owner from the authenticated session and set the initial state to Off.
- Enforce `UNIQUE (ownerId, normalizedName)` in the database, so simultaneous identical requests cannot both succeed.
- A duplicate submission must not create another device with the same normalized name.
- Clients **should** send an `Idempotency-Key` header. The server stores the key with the created device id for at least 24 hours and replays the original `201` response for a repeat of the same key, which removes the ambiguous-timeout case entirely.
- Where no key was sent, an ambiguous create timeout is reconciled by refetching the list and matching on the requested normalized name before submitting again.

### 6.3 Errors

```json
{
  "error": {
    "code": "DEVICE_VERSION_CONFLICT",
    "message": "This device changed. Refresh it and try again.",
    "requestId": "req_01"
  }
}
```

Error codes are a closed set. Clients switch on `code`, never on `message`.

| Code | HTTP | Meaning |
| --- | --- | --- |
| `MALFORMED_REQUEST` | `400` | Body is not valid JSON, or a required field is absent. |
| `UNAUTHENTICATED` | `401` | Missing, invalid, revoked, or expired credentials. |
| `INSUFFICIENT_SCOPE` | `403` | Authenticated caller lacks the required scope. See §7.5 for the accompanying challenge. |
| `DEVICE_NOT_FOUND` | `404` | Device does not exist or is not owned by this account. The two cases are indistinguishable to the caller. |
| `DEVICE_NAME_CONFLICT` | `409` | An owned device already uses this normalized name. |
| `DEVICE_VERSION_CONFLICT` | `409` | `expectedVersion` does not match the current version. No mutation occurred. |
| `DEVICE_LIMIT_REACHED` | `409` | The account is at the device cap defined in §4.3. |
| `VALIDATION_FAILED` | `422` | Valid JSON with an out-of-range or malformed field value, such as a name of 0 or 65 characters. |
| `INVALID_STATE` | `422` | `state` is present but is not exactly `on` or `off`. |
| `RATE_LIMITED` | `429` | Rate limit exceeded. Include `Retry-After`. |
| `INTERNAL_ERROR` | `500` | Unexpected error. No stack traces or secrets in the response. |
| `SERVICE_UNAVAILABLE` | `503` | Temporary unavailability. Include `Retry-After` where known. |

Every error response carries `requestId`, which is also written to the audit log in §11.

## 7. Authentication service

### 7.1 Application authentication operations

The following are additional authentication APIs, separate from the four device APIs:

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/auth/signup` | Register using `{ "username", "password" }`; establish a first-party session on success. |
| `POST /v1/auth/login` | Verify `{ "username", "password" }`; establish a first-party session. |
| `GET /v1/auth/me` | Return authenticated account ID and username. |
| `POST /v1/auth/refresh` | Renew a valid first-party session according to the refresh policy below. |
| `POST /v1/auth/logout` | Revoke the current first-party session and its refresh credentials. |

Native login responses may contain access and refresh tokens for the first-party app. Browser login uses a secure session cookie. Neither mechanism is an OAuth password grant for third-party clients.

**Session policy.** Access tokens live 15 minutes; refresh tokens live 30 days with rotation on each use and reuse detection that revokes the whole session family. A client attempts refresh once per failed protected request, then falls back to showing authentication.

**Revocation is checked per request.** §7.2 requires that a token issued before logout stops working immediately. That rules out a bare stateless JWT validated only by signature and expiry. Implement one of:

- opaque access tokens resolved against a session store on every protected request; or
- signed access tokens carrying a session identifier and version, checked against a session store on every protected request.

The store lookup is on the hot path for every device API and MCP tool call, so it must be counted against the latency target in §11.

### 7.2 Authentication security requirements

- Store passwords with a maintained password-hashing implementation such as Argon2id, using unique salts; never store reversible passwords.
- Rate-limit registration and login; use a generic "Invalid username or password" login error.
- Keep passwords out of tool arguments/results, model context, chat messages, analytics, URLs, and logs.
- Keep tokens out of MCP UI state and model-visible results. Native credentials belong in Keychain; browser sessions use Secure, HttpOnly cookies with appropriate SameSite and CSRF protection.
- Validate token issuer, audience, expiration, revocation/session status, and required scopes on every protected request.
- Do not authorize by an MCP connection ID, a client-provided username, or a device owner parameter.
- Revoke the relevant session on logout. Subsequent protected requests using it must fail, including previously issued access tokens.
- Native logout and disconnecting an external MCP account are separate sessions. Logging out of one does not silently claim to disconnect all others.
- Users of both interfaces must authenticate against the same account directory and reach the same owned devices.

### 7.3 External MCP authorization

ChatGPT and Claude authenticate an MCP connection using a host-managed authorization flow. The server acts as an OAuth 2.1 resource server and must satisfy the MCP authorization specification, revision `2026-07-28`.

**Required of the MCP server (resource server):**

- Publish RFC 9728 Protected Resource Metadata. Serve it at **both** `/.well-known/oauth-protected-resource` and the path-suffixed `/.well-known/oauth-protected-resource/mcp`, because clients try the suffixed form first when the resource URL has a path component.
- Return `401` with a `WWW-Authenticate` challenge on unauthenticated protected calls (§7.5).
- Validate that every access token names this server in its audience, per RFC 8707. Reject tokens minted for any other resource.

**Required of the authorization server:**

- Authorization-code flow with PKCE, advertising `S256` in `code_challenge_methods_supported`. A server that omits this field or does not advertise `S256` is unsupported by ChatGPT.
- Publish RFC 8414 authorization-server metadata, OpenID Connect Discovery, or both.
- Include the RFC 9207 `iss` parameter in authorization responses and advertise `authorization_response_iss_parameter_supported: true`.
- Accept the RFC 8707 `resource` parameter on both the authorization and token requests, and copy it into the access token audience claim.
- Support token revocation.

**Client registration.** Dynamic Client Registration is deprecated in the `2026-07-28` revision and retained only for backward compatibility. Support both of the following, because host support differs:

- **Client ID Metadata Documents**, preferred. Advertise `client_id_metadata_document_supported: true` **and** `"none"` in `token_endpoint_auth_methods_supported`. Claude selects CIMD only when both are present, because its CIMD client authenticates as a public client and the token endpoint must accept PKCE-only requests with no client secret. At `/authorize`, fetch the `client_id` URL, verify the document is self-referential, and check the requested `redirect_uri` against its `redirect_uris`. Display the **host of the `client_id` URL** on the consent screen, not the self-asserted `client_name`. Compare loopback redirect URIs with the port ignored, per RFC 8252 §7.3.
- **Dynamic Client Registration** as a fallback, plus manual pre-registration for any host that requires it.

Actual redirect URIs must be registered exactly for each client.

**Device permissions:**

- `devices:read`: list and retrieve owned devices.
- `devices:control`: set the state of an owned device.
- `devices:create`: add an owned device.

**Scope strategy.** Request all three scopes at initial authorization by naming them in the `scope` parameter of the first `401` challenge, and list all three in `scopes_supported`. Minimizing the initial grant to `devices:read` would make the first switch flip or first add-device trigger a `403 insufficient_scope` and a mid-interaction re-consent prompt, which is a poor experience for a light switch and is slow to correct in practice: hosts cache discovery documents globally for minutes, and a step-up challenge is cached per user for a further period. Step-up is supported (§7.5) but must not be part of the normal path.

Tokens received for the MCP resource must not be blindly forwarded to a different backend resource. Use an internal trusted identity context or a correctly audience-bound internal credential.

### 7.4 Authentication as MCP UI

**Requested experience:** an unauthenticated user of the integration should be offered Sign Up / Log In before any device data is shown or controlled.

**How this is actually delivered.** The MCP Apps authorization guidance is explicit that an app should not present a login wall, should never collect or store credentials, and should let authorization be enforced at the HTTP boundary: when the app calls a protected tool without a token, the host intercepts the `401`, runs the OAuth flow itself, and retries the call transparently. Therefore:

- **The required path is the `401` challenge.** A correct challenge on a protected tool call is what causes a host to authenticate the user. This is the only mechanism that must work.
- **`show_auth` and `ui://iot/auth.html` are a cosmetic entry point,** not the authenticating surface. They exist so that a host which renders them shows a branded, comprehensible starting point instead of a bare Connect prompt.

Provide `ui://iot/auth.html` as a public MCP UI resource and `show_auth` as a public presentation tool. The screen must show the product name, signed-out state, Sign Up and Log In choices, loading/error states, and an explanation that authentication is needed to access devices. **It must contain no credential fields.**

Version 1.0 of this document defined a second presentation profile for "a first-party host under our control" that would render a complete username/password form inline. That profile is removed: §2.2 excludes a first-party host from version 1, so the profile described software that will not exist, and no requirement may depend on it.

Connecting to an MCP server does not, by itself, guarantee that a host will render any custom UI. A host may show its own Connect prompt or open authorization before it renders an MCP App. Therefore:

- An external host can render `show_auth` when the tool is invoked; the server must not promise unsolicited UI at connection time.
- Sign Up / Log In actions must enter the host-supported authorization flow. Where no explicit connect action is exposed to the UI, call a protected, read-only tool — `list_devices` — to obtain the host's authentication challenge. Never initiate authentication by attempting a device mutation.
- The hosted authorization page must offer both Sign Up and Log In modes, because the host may not preserve the mode selected in the MCP card.
- Do not open an unrelated login URL and assume its browser session will become the host's MCP token. A widget cannot assume that signing into a browser tab changes its host's MCP authorization.
- A form displayed inside a widget must never claim it has authenticated the MCP connection.
- The integration must remain usable through the host's own authorization flow even when the custom authentication card is never shown.

### 7.5 Public discovery and protected tools

Support anonymous initialization, tool discovery, the public authentication presentation/status tools, and static UI resource reads. These must not expose private user/device data. Every device operation remains protected.

**The refusal must be a transport-level HTTP status, not a tool result.** An unauthenticated protected call must produce `401 Unauthorized` with a `WWW-Authenticate` challenge:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token",
                  resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp",
                  scope="devices:read devices:control devices:create"
```

Returning HTTP 200 with `isError: true` is an application-level tool failure. The host passes the error text to the model and moves on; no authentication prompt appears. If users see "please sign in" as chat text instead of a Connect affordance, the server is returning the wrong thing.

**This gate must run at the HTTP layer, before the JSON-RPC message reaches the MCP SDK.** Once a tool handler is executing, its return value is already destined for a `200`. Inspect the parsed request body in the HTTP handler, short-circuit when it is a `tools/call` for a protected tool with no valid bearer, and otherwise fall through. `initialize`, `tools/list`, `resources/read` for `ui://` resources, and the public tools never reach the gate.

**Scope step-up.** When the bearer is valid but lacks a scope the tool needs, return `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"`. Include every scope required for the operation in a single challenge rather than one at a time. Under the strategy in §7.3 this should not occur in normal use.

After successful OAuth, the host owns the token and sends it with subsequent tool calls. A read can resume automatically. A write must satisfy the host's approval rules and the device-version check; the server must not silently replay rejected writes itself.

## 8. MCP server requirements

### 8.1 Connection and protocol

- Expose a remotely reachable HTTPS MCP endpoint using Streamable HTTP, suitable for mobile host connections.
- Implement initialization, tool discovery/calling, resource discovery/reading, and the MCP Apps extension, identifier `io.modelcontextprotocol/ui`, negotiated through the `extensions` capability field. Target the released `2026-01-26` extension revision.
- Advertise UI resources using the `ui://` scheme and the exact content type `text/html;profile=mcp-app`.
- Link presentation tools using `_meta.ui.resourceUri`. **Also emit `_meta["openai/outputTemplate"]` with the same value on those tools**, which ChatGPT honors as a compatibility alias.
- Declare `_meta.ui.visibility` explicitly on every tool rather than relying on the `["model", "app"]` default (§8.2).
- Retain text and structured-data results for hosts that cannot render the UI.
- Do not require the user to run a desktop subprocess or local Node/Python server on their iPhone.

### 8.2 Tool catalog

Device mutation tools are separate from presentation helpers so a switch click can update existing UI without requiring a new app view.

| Tool | Input | Authorization | Visibility | Result / UI |
| --- | --- | --- | --- | --- |
| `list_devices` | None | `devices:read` | model, app | Owned device list; links `ui://iot/devices.html`. |
| `get_device` | `deviceId` | `devices:read` | model, app | Owned device; links `ui://iot/device.html`. |
| `control_device` | `deviceId`, `state`, `expectedVersion` | `devices:control` | model, app | Updated device; data-only result. |
| `add_device` | `name` | `devices:create` | model, app | Created device; data-only result. |
| `show_add_device` | None | **Public** | model, app | Form presentation; links `ui://iot/add-device.html`. No mutation. |
| `show_auth` | Optional `mode`: `login` or `signup` | Public | model, app | Authentication entry UI; links `ui://iot/auth.html`. |
| `get_auth_status` | None | Public, with optional verified token | app | `authenticated: false`, or minimal authenticated account information. No tokens. |

`show_add_device` is **public**, changed from `devices:create` in version 1.0. Gating a form's presentation behind a write scope means that merely displaying it can trigger a `403` and a re-consent prompt before the user has typed anything. The form is inert; the `add_device` call it makes is where authorization is enforced.

The four device tools map to the four device business APIs. The remaining tools are presentation/authentication helpers, not additional device APIs. There is deliberately no model-callable password-based `login` or `signup` tool.

### 8.3 Tool contracts and results

- Declare input and output schemas with required fields, allowed enum values, and validation limits.
- Return concise human-readable `content` and consistent `structuredContent` containing the authoritative result.
- Include device IDs and versions required for subsequent actions. Because `control_device` requires `expectedVersion`, its description must state that the caller reads the device first; a model with no current version must call `get_device` or `list_devices` before controlling.
- Annotations must describe implemented behavior. Specifically, `control_device` and `add_device` are `readOnlyHint: false`, `destructiveHint: false`, and **`idempotentHint: false`** — replaying either with the same arguments fails rather than repeating (§6.1, §6.2). Annotations are hints and never substitute for permission checks.
- Treat both text and structured content as potentially model-visible; include no credentials or unnecessary personal data.
- Restrict presentation-only metadata to safe UI details. Being outside model context does not make it appropriate for passwords or access tokens.
- Map validation, ownership, conflict, and service errors to the §6.3 codes predictably. Preserve authentication challenges at the transport layer (§7.5).
- Never select another user's device or guess a device ID when a name is unknown or ambiguous.

Illustrative result from `control_device`:

```json
{
  "content": [{ "type": "text", "text": "Bedroom Lamp is now On." }],
  "structuredContent": {
    "device": {
      "id": "dev_01",
      "name": "Bedroom Lamp",
      "state": "on",
      "version": 2,
      "createdAt": "2026-09-21T10:00:00Z",
      "updatedAt": "2026-09-21T10:01:00Z"
    }
  }
}
```

## 9. MCP App requirements

### 9.1 UI resources

| Resource | Required content |
| --- | --- |
| `ui://iot/auth.html` | Authentication entry, Sign Up / Log In choices, and host handoff described in §7.4. No credential fields. |
| `ui://iot/devices.html` | Device rows with On/Off switches, refresh, empty/error states, and Add Device navigation, subject to the presentation limits in §9.3. |
| `ui://iot/device.html` | One device, its current state, switch, and last-updated information. |
| `ui://iot/add-device.html` | Device Name input, default-Off explanation, submit/cancel, and validation feedback. |

These resources may share a frontend bundle. They must use the same state labels, validation rules, ordering, and interaction behavior as the native app.

### 9.2 Bridge and lifecycle

- Use the MCP Apps initialization handshake: the view sends `ui/initialize` declaring `appCapabilities`, the host replies with `hostCapabilities` and `hostContext`, and the view then sends `ui/notifications/initialized`.
- Register event handlers **before** completing the handshake, so initial `ui/notifications/tool-input` and `ui/notifications/tool-result` messages are not lost.
- Render initial data from host-delivered tool input/result messages.
- Invoke `control_device` and `add_device` as `tools/call` through the host bridge; update the active view from the returned result. The host forwards the call and may require user approval first.
- Route requests through the originating server connection. The host may restrict which tools an app can call; treat a refusal as an expected outcome, not an error state.
- Provide an explicit device-list refresh. Refetch after creation and when a view resumes, using `ui/notifications/host-context-changed` and teardown signals where available.
- Handle `ui/resource-teardown`, `ui/notifications/tool-cancelled`, resize, theme changes, failed initialization, expired sessions, and unavailable capabilities.
- Preserve harmless presentation state when possible, but keep authoritative device/account state on the backend.
- **Never hold a bearer token in the view.** Protected data arrives only as the result of a host-forwarded tool call.
- A host-mediated tool call can return an authentication challenge before device data arrives. Keep the view in a signed-out/loading state and refetch through the host after authorization; the host, not the view, completes the OAuth flow.
- A widget cannot assume that logging into an unrelated browser tab changes its host's MCP authorization.

MCP Apps separates the server connection from the sandboxed UI-to-host bridge. Its host controls rendering and capability availability.

### 9.3 Presentation on phones and in inline cards

Host presentation limits, not our layout preferences, govern this section. The constraints below are Claude's documented guidance and are the binding target for version 1.

- Design for variable widths from **320 px** upward with no page-level horizontal scrolling, using container queries. There are no fixed breakpoints; the app always fills the container width.
- Read **`hostContext.safeAreaInsets`** — `{ top, right, bottom, left }` in pixels — and apply them as padding on the root container. CSS `env(safe-area-inset-*)` is not the mechanism here. Controls placed outside the safe area cannot be tapped.
- Use the **host's style tokens** for backgrounds, text, borders, and icons, so light and dark themes follow the host. Never hardcode colors.
- Touch targets of at least 44 × 44 pt, with spacing between adjacent controls.
- **Avoid menus, dropdowns, and popovers.** They are clipped by the container and conflict with host z-index. Use segmented buttons, toggles, and inline options.
- Set `_meta.ui.prefersBorder` deliberately. Unset, content renders borderless on web and bordered on mobile; in borderless mode the host adds no padding, so honoring `safeAreaInsets` becomes essential.

**Inline cards are tightly constrained, and this shapes `devices.html`.** An inline card is expected to auto-fit its content height, expose at most two actions, and present roughly four to five data points, with no drill-ins and no nested scrolling. On phones the conversation owns vertical scrolling: a vertical pan starting inside an inline app scrolls the conversation instead of the app, and the host caps inline height and clips the remainder. A long list of switches rendered inline is therefore partly unreachable.

Accordingly:

- `device.html` and `add-device.html` are suitable as inline cards.
- `devices.html` **must not** rely on internal vertical scrolling inline. Render a bounded summary — device count and the first few devices with their switches — and request `ui/request-display-mode: "fullscreen"` for the complete list, declaring `fullscreen` in `appCapabilities.availableDisplayModes`.
- Horizontal gestures and taps behave normally, so a horizontally scrolling presentation is an acceptable alternative for a short list.
- Do not require picture-in-picture, desktop-sized modals, or any host-specific API for the core flow. Use feature detection for optional host extensions and preserve a usable standard flow.
- Show skeleton placeholders rather than spinners while inline content loads.

### 9.4 Isolation and content policy

- Run server-supplied UI within the host's sandbox and declared content security policy. Hosts render apps in a sandboxed iframe on web and desktop, and in a native WebView on mobile; assume the stricter of the two.
- **All external origins are blocked by default.** Declare what is needed per `ui://` resource via `_meta.ui.csp`:

  ```json
  {
    "_meta": {
      "ui": {
        "csp": {
          "connectDomains": [],
          "resourceDomains": [],
          "baseUriDomains": []
        }
      }
    }
  }
  ```

  Bundle the frontend so that these lists can stay empty. `frameDomains` is currently restricted in Claude pending security review; do not depend on nested iframes.
- Request no optional `permissions`. Camera, microphone, and geolocation are unavailable on mobile in any case, and this product needs none of them.
- Device views obtain protected device data through host-mediated tools, not by storing bearer tokens in JavaScript. Iframe storage is not a credential store.
- Escape device names and all other user-supplied strings before rendering.
- Open external navigation only through supported host actions such as `ui/open-link`; do not navigate the parent application arbitrarily.
- Never place per-user data into a globally cached HTML template. Hosts cache UI resources and discovery documents globally by URL. Supply user data only through authorized tool results.

## 10. Core end-to-end flows

### 10.1 Native app: sign up and add the first device

1. User opens the app and sees Log In / Sign Up.
2. User selects Sign Up and enters username and password.
3. Authentication service creates the account and session.
4. Devices screen loads and shows its empty state.
5. User selects Add Device, enters "Bedroom Lamp," and submits.
6. Device service creates the owned device in Off state.
7. Devices screen displays the new device and switch.

### 10.2 Native app or MCP UI: control a device

1. An authenticated user views the latest device and version.
2. User sets its switch to On.
3. Native app calls the control API, or the MCP App requests `control_device` through the host.
4. The host applies its own approval rules to the write, which may include an explicit per-call confirmation.
5. Backend verifies identity, ownership, scope, and version, then persists the change.
6. The initiating view updates from the returned device.
7. Another client sees the change on its next refresh/resume; immediate cross-client push is not a version 1 requirement.

### 10.3 External MCP host: first use

1. **On web or desktop**, the user adds the connector — a custom connector in Claude, or a developer-mode MCP connector in ChatGPT. This step cannot be performed in either mobile app. In Claude the connector then becomes available on iOS and Android.
2. If the host permits anonymous discovery, public tools and static UI resources are available; no private data is returned.
3. The host may invoke `show_auth`, or the first protected operation triggers the `401` authorization challenge of §7.5.
4. The user sees the MCP authentication entry screen or the host's own Connect prompt.
5. The host opens our authorization page, where the user selects Log In / Sign Up and supplies only username and password.
6. After successful authentication and consent, the host receives its token through OAuth, bound to this resource and carrying all three device scopes.
7. The host retries the permitted read and renders the device UI. Mutations still require applicable host approval and fresh version validation.
8. Cancellation leaves the integration signed out and performs no device mutation.

### 10.4 Session expiry

1. A protected request fails because the session is expired or revoked.
2. The client may refresh a valid refresh session once under the policy in §7.1.
3. If refresh fails, clear protected presentation data and show authentication.
4. Preserve a non-secret destination where useful, but do not retain password input or queue an unapproved write.

Note that `get_auth_status` is public and returns `200` even when a token has expired, so it will report `authenticated: false` without producing a Connect affordance. A view that needs to re-authenticate must call `list_devices` to obtain the challenge.

## 11. Quality and operational requirements

- Persist accounts and devices across backend restarts; do not use an in-memory map as the only store.
- Enforce database uniqueness and atomic version updates, including concurrent API/MCP requests, using the constraint and conditional update named in §4.2 and §6.1.
- Enforce the per-account device cap and rate limits on sign-up, login, and `add_device`.
- Keep the interface responsive while waiting for requests and allow read retries without restarting the app.
- Use bounded timeouts and display uncertainty explicitly when a write response is lost.
- Retry reads with limits; reconcile writes before retrying rather than blindly resubmitting.
- Store audit events for device mutations: verified actor, device ID, old/new state, timestamp, outcome, request ID, **and the channel and host** that originated the change — native app, MCP via Claude, MCP via ChatGPT. Without the channel, the isolation and external-authorization acceptance criteria are difficult to evidence. Do not record passwords/tokens or request bodies containing them.
- Return safe diagnostics with correlation IDs, without exposing internal stack traces.
- Version API/tool contracts and UI assets so cached resources do not silently break current data shapes. Host caching of UI resources and discovery documents is global and lasts minutes, so asset URLs must be content-addressed or versioned.
- Demo acceptance targets: a visible pending indicator within **200 ms of the interaction in the initiating surface**, and device API p95 latency below **1 second** under a documented test environment. Both exclude time spent in a host's approval prompt, OAuth flow, or network; those are measured and reported separately.
- Device polling/refresh must stop when the app/view is inactive; background continuous connectivity is not required.

## 12. Acceptance criteria

| ID | Scenario | Pass condition |
| --- | --- | --- |
| AC-01 | New registration | Username/password creates one account and opens an empty owned-device list. |
| AC-02 | Invalid or duplicate registration | Clear validation; no duplicate account or leaked password data. Usernames differing only by case or NFKC form collide. |
| AC-03 | Login/logout | Correct credentials restore access; wrong credentials fail; logout invalidates that session, including access tokens already issued. |
| AC-04 | Add a device | One device is created for the current account, initially Off, and appears in both native and MCP reads. |
| AC-05 | Fetch all | Only the signed-in account's devices are returned, in `createdAt` then `id` order; zero devices produces an empty array. |
| AC-06 | Fetch particular device | Correct owned device is returned; unknown and other-user IDs are indistinguishable. |
| AC-07 | Control | Switches work in both directions, persist across reload/restart, and update from server results. |
| AC-08 | Exactly two states | Invalid states are rejected with `INVALID_STATE`; pending/error never become persisted device states. |
| AC-09 | Duplicate creation | Repeated and concurrent same-name creation cannot create duplicate owned devices; names differing only by case or internal whitespace collide. |
| AC-10 | Concurrent control | A stale version is rejected with `DEVICE_VERSION_CONFLICT` and refreshed; no silent lost update. |
| AC-11 | Ambiguous network outcome | UI reconciles through a read; no automatic inverse command or duplicate device. With `Idempotency-Key`, the replay returns the original device. |
| AC-12 | Anonymous MCP connection | `initialize`, `tools/list`, public tools, and `ui://` resource reads succeed without a token and expose no private data. |
| AC-13 | MCP authentication entry | `show_auth` renders Sign Up / Log In in Claude on web, desktop, and iOS, and selecting either reaches the host authorization flow. A host that never renders it remains fully usable through its own Connect prompt. |
| AC-14 | External authorization | **Claude (iOS and web)** and **ChatGPT (web)** each complete username/password authorization on the hosted page and send scoped, audience-bound tokens to protected tools. ChatGPT on iOS is out of scope per §2 and must be recorded as not applicable, not as a failure. |
| AC-15 | Credential isolation | Passwords/tokens are absent from tool schemas/results, model context, device HTML, analytics, and application logs. |
| AC-16 | Expired authorization | Protected calls fail appropriately; reauthentication works; canceled login causes no mutation. |
| AC-17 | MCP device UI | List, detail, add form, switches, refresh, loading, empty, and error states are functional. |
| AC-18 | Text fallback | Tool data and summaries remain usable when UI rendering is unavailable. |
| AC-19 | iOS usability | Native app core flows pass on a real iPhone, including keyboard, scrolling, light/dark appearance, and accessibility; and Claude on iPhone renders and operates all four MCP App views. |
| AC-20 | iPad and wide layout | Native screens remain usable at supported iPad sizes, and MCP App views remain usable from 320 px to fullscreen. |
| AC-21 | User isolation | Account A cannot read/control Account B's device via any API, tool, guessed ID, or stale UI. |
| AC-22 | Cross-client consistency | A mutation through one client is reflected in another client's next successful refresh. |
| AC-23 | Sandbox and CSP | The app declares empty or minimal `_meta.ui.csp`, requests no permissions, and holds no token; a `fetch` to an undeclared origin is blocked by the host. |
| AC-24 | Authentication challenge | An unauthenticated `tools/call` to `list_devices` returns HTTP `401` with `WWW-Authenticate` carrying `resource_metadata` and `scope` — never `200` with `isError`. Protected resource metadata resolves at both well-known paths, and authorization-server metadata advertises `S256` and CIMD support. |
| AC-25 | Scope sufficiency | After a single authorization, `list_devices`, `get_device`, `control_device`, and `add_device` all succeed with no step-up prompt. A deliberately under-scoped token produces `403 insufficient_scope` with a complete `scope` list and recovers on re-consent. |
| AC-26 | Device cap | Creation beyond the cap fails with `DEVICE_LIMIT_REACHED` and creates nothing. |
| AC-27 | Host write approval | Where a host confirms each write, approving applies exactly one change and declining leaves the device unchanged with the UI showing the confirmed state. |
| AC-28 | Inline presentation | With more devices than fit an inline card, the list remains fully reachable on a phone via fullscreen display mode; no content is trapped behind inline scrolling. |

External-host acceptance must record the client app/version, account plan, enabled connector capabilities, observed authentication presentation, and test date. A host capability limitation must be reported explicitly; native-app success alone does not establish ChatGPT or Claude compatibility.

## 13. Suggested implementation sequence

**0. Host feasibility spike, before anything else.** Stand up a throwaway MCP server with one public tool, one protected tool returning the §7.5 challenge, and one `ui://` resource rendering a list with switches. Add it as a custom connector in Claude on desktop, then open the same conversation on an iPhone. Attempt the same in ChatGPT developer mode on the web. Record what actually renders, whether the OAuth flow completes from each surface, how much of a list survives inline, and what approval each write requires. Every unresolved item in §14 is answerable from this spike, and its outcome may change the scope of the work below.

1. Build persistent accounts, authentication, device model, and the four API operations.
2. Build the native iOS authentication and device-control screens.
3. Expose the same operations through MCP tools and validate authorization/ownership.
4. Add device MCP UI resources and verify the UI-to-tool-to-backend round trip.
5. Add the MCP authentication entry UI and the hosted OAuth login/sign-up page, with CIMD and DCR registration paths.
6. Test the complete workflows in Claude on iOS and web and in ChatGPT on web, and document their actual capabilities.
7. Run the acceptance scenarios, especially two-account isolation, lost responses, and concurrent state changes.

## 14. Decisions awaiting clarification

1. Confirm simulated devices for version 1, or identify the real hardware protocol if required.
2. Confirm that the native iOS app and the external Claude/ChatGPT MCP UIs are all in scope.
3. **Given that ChatGPT custom connectors are web-only, confirm whether ChatGPT remains a target at all, and if so that web-only coverage is acceptable.** If phone coverage in ChatGPT is mandatory, the integration cannot be delivered as specified and the requirement must change.
4. Confirm that credential entry on our hosted authorization page, rather than inline in a host's UI, satisfies the sign-up/log-in requirement. Version 1.0 left open the possibility of a first-party host guaranteeing an inline form; §2.2 excludes building one in version 1.
5. Confirm the device cap of 100 per account and the session lifetimes proposed in §7.1.

This draft uses the defaults in §2 until these decisions are supplied. It does not claim that external apps can be forced to render an authentication form when the connection is first established.

## 15. References

Verified 2026-09-21. Host behavior changes frequently; re-verify before relying on any row.

| Topic | Source |
| --- | --- |
| MCP Apps extension, released revision | https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx |
| MCP Apps overview and security model | https://modelcontextprotocol.io/extensions/apps/overview |
| MCP Apps authorization guidance | https://apps.extensions.modelcontextprotocol.io/api/documents/authorization.html |
| MCP authorization specification | https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization |
| Extension client support matrix | https://modelcontextprotocol.io/extensions/client-matrix |
| Claude lazy authentication and CIMD | https://claude.com/docs/connectors/building/lazy-authentication |
| Claude MCP Apps design guidelines | https://claude.com/docs/connectors/building/mcp-apps/design-guidelines |
| Claude interactive connectors | https://support.claude.com/en/articles/13454812-use-interactive-connectors-in-claude |
| ChatGPT developer mode and plan availability | https://developers.openai.com/api/docs/guides/developer-mode |
| ChatGPT MCP authentication | https://developers.openai.com/plugins/build/auth |
| ChatGPT MCP server UI | https://developers.openai.com/plugins/build/chatgpt-ui |
