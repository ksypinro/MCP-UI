# IoT Device Control — Application Requirements

Version: 1.0 draft  
Date: 2026-09-21  
Primary platform: iOS, with responsive support for iPad  
Working product name: IoT Switch

## 1. Product objective

Build an application that simulates controlling a user's IoT devices. Each device has exactly two persisted states: **On** and **Off**. A user can create an account, log in, add a device, view their devices, inspect one device, and change its state with a switch.

The same account and devices must be accessible through the main iOS application and through an MCP server. Compatible AI clients must be able to display an interactive MCP App with device lists, device details, switches, an add-device form, and an authentication entry screen.

The main backend has exactly four device operations:

1. Fetch all devices owned by the authenticated user.
2. Fetch one device owned by the authenticated user.
3. Set a device to On or Off.
4. Add a device for the authenticated user.

Authentication is an additional logical service, with its own endpoints. It does not count toward the four device APIs.

## 2. Scope and working assumptions

The following assumptions make this draft implementable. They are proposed defaults, not additional user-confirmed requirements.

| Decision | Working assumption |
| --- | --- |
| Device behavior | Version 1 simulates devices in a database. No physical hardware connection. |
| Main application | A native iOS application provides the complete device-control experience. |
| External MCP clients | ChatGPT and Claude on iOS are target clients, subject to their account, connector, and UI capabilities. |
| User ownership | Each device belongs to exactly one account. No shared households or administrators. |
| New device state | Every new device starts Off. |
| Device names | Required; unique within the owner's account after trimming and case-insensitive comparison. |
| Authentication | Exactly two credential inputs: username and password. |
| Authentication presentation | Inline authentication in a first-party host where supported; a secure hosted login/sign-up page when an external host requires OAuth. |
| Minimum OS version | Select during implementation after confirming the Swift/toolchain and host-testing requirements. |

### 2.1 Included in version 1

- Native iOS sign-up, login, logout, device list, device detail, add device, and state control.
- Persistent accounts and simulated device states.
- Four authenticated device APIs and an authentication service.
- An MCP server that exposes the four device operations as tools.
- MCP App resources for authentication entry, device list, device detail, and adding a device.
- Username/password authentication with account isolation across all entry points.
- iPhone validation of the native app and the supported external MCP UI flows.

### 2.2 Outside version 1

- Real device discovery, pairing, Bluetooth, Matter, HomeKit, MQTT, or vendor adapters.
- Additional device states, telemetry, schedules, rooms, scenes, or bulk control.
- Device deletion, renaming, ownership transfer, or sharing.
- Social login, email/phone sign-up, password recovery, and multi-factor authentication.
- Push notifications, background monitoring, and offline queued mutations.
- A custom AI chat client or a general-purpose MCP host inside the native iOS app. These are optional extensions, not prerequisites for controlling devices.

## 3. Architecture and responsibilities

```text
Native iOS application ── authenticated device API ─┐
                                                  ├── Device service ── Database
ChatGPT / Claude ── authenticated MCP ── MCP server ┘
       │
       └── Sandboxed MCP App UI ── host bridge ── MCP tools

Native app / host authorization flow ── Authentication service
                                      ├── Accounts and password verification
                                      ├── Sessions and token issuance/revocation
                                      └── Hosted username/password UI for OAuth
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

These are logical boundaries. A modular backend deployment is sufficient for version 1; separate microservices are not required.

## 4. Domain model and rules

### 4.1 Account

| Field | Rule |
| --- | --- |
| `id` | Server-generated immutable account identifier. |
| `username` | Display value; 3–32 characters from letters, digits, `.`, `_`, and `-`. Trim surrounding whitespace. |
| `normalizedUsername` | Case-insensitive unique lookup value. |
| `passwordHash` | Salted password hash; never returned to a client. |
| `createdAt` | Server-generated UTC timestamp. |

Proposed password policy: 12–128 characters, allow spaces and password-manager generated values, and do not silently trim or truncate. Sign-up and login have no email, phone, or password-confirmation field.

### 4.2 Device

| Field | Rule |
| --- | --- |
| `id` | Server-generated immutable identifier. |
| `ownerId` | Derived from authenticated identity; not accepted from a device creation request. |
| `name` | Trimmed, nonempty display name, 1–64 characters. |
| `state` | Exactly `on` or `off`; new devices start `off`. |
| `version` | Integer starting at 1; incremented when the state actually changes. |
| `createdAt` | Server-generated UTC timestamp. |
| `updatedAt` | UTC timestamp of the most recent persisted change. |

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
| Empty | “No devices yet” and an Add Device action. |
| Loaded | All owned devices, sorted by creation time with a stable ID tie-breaker. |
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
- On a name conflict, show “A device with this name already exists” and retain the input.

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
| Add device | `POST /v1/devices` | `{ "name": string }` | `201 { "device": Device }` |

The list endpoint returns the full owned list for this prototype. Pagination can be added in a later version without introducing another business operation.

### 6.1 Control semantics

- `expectedVersion` is required and must match the current version; otherwise return `409 DEVICE_VERSION_CONFLICT` without mutation.
- When the version matches and the requested state already matches, return the current device without incrementing the version.
- When the version matches and the state differs, persist the target state and increment the version atomically.
- Repeated requests never invert the state. A retry carrying an old version may receive a conflict and must reconcile through a read.
- The native UI and MCP App obtain versions from their latest read; an assistant must fetch a device before controlling it when it has no current version.

### 6.2 Creation and retry semantics

- Derive the owner from the authenticated session and set the initial state to Off.
- Enforce normalized-name uniqueness per owner in the database, including simultaneous requests.
- A duplicate submission must not create another device with the same normalized name.
- After an ambiguous create timeout, refetch the list and reconcile by the requested name before submitting again.

### 6.3 Common errors

```json
{
  "error": {
    "code": "DEVICE_VERSION_CONFLICT",
    "message": "This device changed. Refresh it and try again.",
    "requestId": "req_01"
  }
}
```

| HTTP status | Meaning |
| --- | --- |
| `400` | Malformed request. |
| `401` | Missing, invalid, revoked, or expired credentials. |
| `403` | Authenticated caller lacks the required scope. |
| `404` | Device does not exist or is not owned by this account; responses must not reveal other users' devices. |
| `409` | Duplicate device name or stale device version, distinguished by error code. |
| `422` | Valid JSON with invalid field values. |
| `429` | Rate limit exceeded; include retry guidance. |
| `500` / `503` | Unexpected error or temporary unavailability; no stack traces or secrets in the response. |

## 7. Authentication service

### 7.1 Application authentication operations

The following are additional authentication APIs, separate from the four device APIs:

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/auth/signup` | Register using `{ "username", "password" }`; establish a first-party session on success. |
| `POST /v1/auth/login` | Verify `{ "username", "password" }`; establish a first-party session. |
| `GET /v1/auth/me` | Return authenticated account ID and username. |
| `POST /v1/auth/refresh` | Renew a valid first-party session according to the refresh policy. |
| `POST /v1/auth/logout` | Revoke the current first-party session and its refresh credentials. |

Native login responses may contain access and refresh tokens for the first-party app. Browser login uses a secure session cookie. Neither mechanism is an OAuth password grant for third-party clients.

### 7.2 Authentication security requirements

- Store passwords with a maintained password-hashing implementation such as Argon2id, using unique salts; never store reversible passwords.
- Rate-limit registration and login; use a generic “Invalid username or password” login error.
- Keep passwords out of tool arguments/results, model context, chat messages, analytics, URLs, and logs.
- Keep tokens out of MCP UI state and model-visible results. Native credentials belong in Keychain; browser sessions use Secure, HttpOnly cookies with appropriate SameSite and CSRF protection.
- Validate token issuer, audience, expiration, revocation/session status, and required scopes on every protected request.
- Do not authorize by an MCP connection ID, a client-provided username, or a device owner parameter.
- Revoke the relevant session on logout. Subsequent protected requests using it must fail, including previously issued access tokens.
- Native logout and disconnecting an external MCP account are separate sessions. Logging out of one does not silently claim to disconnect all others.
- Users of both interfaces must authenticate against the same account directory and reach the same owned devices.

### 7.3 External MCP authorization

ChatGPT/Claude authenticate an MCP connection using a host-managed authorization flow. The server must support authorization-code OAuth with PKCE, publish protected-resource and authorization-server metadata, and issue correctly scoped/audience-bound tokens. The authorization page authenticates the person with the requested username and password. Credentials are entered into that page, never into the conversation. [OpenAI MCP authentication](https://developers.openai.com/plugins/build/auth), [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

Required OAuth infrastructure includes discovery metadata, an authorization endpoint, token endpoint, revocation support, and a supported client registration method. Use compatible pre-registration/DCR/CIMD as needed by each host; do not assume every host supports the same registration options. The actual redirect URIs must be registered exactly for each client.

Define the following device permissions:

- `devices:read`: list and retrieve owned devices.
- `devices:control`: set the state of an owned device.
- `devices:create`: add an owned device.

Tokens received for the MCP resource must not be blindly forwarded to a different backend resource. Use an internal trusted identity context or a correctly audience-bound internal credential.

### 7.4 Authentication as MCP UI

**Requested experience:** when an unauthenticated user tries to use the integration, present Sign Up / Log In, using username and password, before showing or controlling any devices.

Provide `ui://iot/auth.html` as a public MCP UI resource and `show_auth` as a public presentation tool. The screen must show the product name, signed-out state, Sign Up and Log In choices, loading/error states, and an explanation that authentication is needed to access devices.

There are two presentation profiles:

| Profile | Requirement |
| --- | --- |
| First-party host under our control | It may render the complete username/password form using the shared authentication UI. Submit credentials directly to the authentication service through an explicitly trusted channel. Do not send them through MCP tools or model-visible messages. |
| ChatGPT / Claude on iOS | The MCP authentication screen acts as the sign-up/login entry point. Credential entry occurs in the authorization page opened by the host's OAuth flow when inline entry is unavailable. The page contains exactly Username and Password fields with Sign Up / Log In modes. |

Connecting to an MCP server does not, by itself, guarantee that an external host will render any custom UI. A host may show its own Connect prompt or open authorization before it renders an MCP App. Therefore:

- A first-party MCP host may open `show_auth` immediately when its connection is unauthenticated.
- An external host can render `show_auth` when the tool is invoked; the server must not promise unsolicited UI at connection time.
- Sign Up / Log In actions must enter the host-supported authorization flow. Where no explicit connect action is exposed to the UI, request a protected, read-only operation such as `list_devices` to obtain the host's authentication challenge. Never initiate authentication by attempting a device mutation.
- The authorization page must offer both modes even if the host cannot preserve the mode selected in the MCP card. Do not open an unrelated login URL and assume its browser session will become the host's MCP token.
- The integration must remain usable through the host's supported authorization flow even when the custom authentication card is not shown.
- A form displayed inside a widget must not claim it has authenticated the MCP connection unless the host subsequently supplies a valid bearer token.
- If inline credential entry on initial connection is mandatory on every client, external-host support remains an unresolved compatibility constraint rather than a guaranteed feature.

### 7.5 Public discovery and protected tools

Support anonymous initialization, tool discovery, the public authentication presentation/status tools, and static UI resource reads. These must not expose private user/device data. Every device operation remains protected.

An unauthenticated protected call must produce a transport-level `401 Unauthorized` with a `WWW-Authenticate` challenge pointing to protected-resource metadata. For Claude, returning HTTP 200 with only `isError: true` does not trigger the authentication flow. Host-specific additional metadata may be used where documented, but cannot replace the required challenge. [Claude lazy authentication](https://claude.com/docs/connectors/building/lazy-authentication)

After successful OAuth, the host owns the token and sends it with subsequent tool calls. A read can resume automatically. A write must satisfy the host's approval rules and the device-version check; the server must not silently replay rejected writes itself.

## 8. MCP server requirements

### 8.1 Connection and protocol

- Expose a remotely reachable HTTPS MCP endpoint using Streamable HTTP, suitable for mobile host connections.
- Implement initialization, tool discovery/calling, resource discovery/reading, and the negotiated MCP Apps extension.
- Advertise UI resources using the `ui://` scheme and `text/html;profile=mcp-app` content type.
- Link presentation tools using `_meta.ui.resourceUri` and declare tool visibility intentionally.
- Retain text and structured-data results for hosts that cannot render the UI.
- Do not require the user to run a desktop subprocess or local Node/Python server on their iPhone.

### 8.2 Tool catalog

Device mutation tools are separate from presentation helpers so a switch click can update existing UI without requiring a new app view.

| Tool | Input | Authorization | Result / UI |
| --- | --- | --- | --- |
| `list_devices` | None | `devices:read` | Owned device list; links `ui://iot/devices.html`. |
| `get_device` | `deviceId` | `devices:read` | Owned device; links `ui://iot/device.html`. |
| `control_device` | `deviceId`, `state`, `expectedVersion` | `devices:control` | Updated device; data-only result. |
| `add_device` | `name` | `devices:create` | Created device; data-only result. |
| `show_add_device` | None | `devices:create` | Form presentation; links `ui://iot/add-device.html`. No mutation. |
| `show_auth` | Optional `mode`: `login` or `signup` | Public | Authentication entry UI; links `ui://iot/auth.html`. |
| `get_auth_status` | None | Public, with optional verified token | `authenticated: false`, or minimal authenticated account information. No tokens. |

The four device tools map to the four device business APIs. The remaining tools are presentation/authentication helpers, not additional device APIs. There is deliberately no model-callable password-based `login` or `signup` tool.

All listed tools may be available to the model and app where supported. Device tools must carry accurate read/write, destructive, and idempotency annotations for their implemented behavior; annotations are hints, never substitutes for permission checks.

### 8.3 Tool contracts and results

- Declare input and output schemas with required fields, allowed enum values, and validation limits.
- Return concise human-readable `content` and consistent `structuredContent` containing the authoritative result.
- Include device IDs and versions required for subsequent actions.
- Treat both text and structured content as potentially model-visible; include no credentials or unnecessary personal data.
- Restrict presentation-only metadata to safe UI details. Being outside model context does not make it appropriate for passwords or access tokens.
- Map validation, ownership, conflict, and service errors predictably. Preserve authentication challenges at the transport layer.
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
| `ui://iot/auth.html` | Authentication entry, Sign Up / Log In modes, and supported-host handoff described in section 7.4. |
| `ui://iot/devices.html` | Device rows with On/Off switches, refresh, empty/error states, and Add Device navigation. |
| `ui://iot/device.html` | One device, its current state, switch, and last-updated information. |
| `ui://iot/add-device.html` | Device Name input, default-Off explanation, submit/cancel, and validation feedback. |

These resources may share a frontend bundle. They must use the same state labels, validation rules, and interaction behavior as the native app.

### 9.2 Bridge and lifecycle

- Use the standard MCP Apps initialization handshake and receive host capabilities/context before depending on a feature.
- Register event handlers before completing connection to avoid losing initial inputs/results.
- Render initial data from host-delivered tool input/result messages.
- Invoke `control_device` and `add_device` through the host's tool bridge; update the active view from the returned result.
- Route requests through the originating server connection and enforce the permitted tool set.
- Provide an explicit device-list refresh. Refetch after creation and when a view resumes, where host lifecycle events are available.
- Preserve harmless presentation state when possible, but keep authoritative device/account state on the backend.
- Handle resize, theme changes, teardown, failed initialization, cancellation, expired sessions, and unavailable capabilities.
- A widget cannot assume that logging into an unrelated browser tab changes its host's MCP authorization.
- A host-mediated tool call can return an authentication challenge before device data arrives. Keep the view in a signed-out/loading state, and refetch through the host after authorization rather than passing tokens into the iframe.

MCP Apps separates the server connection from the sandboxed UI-to-host bridge. Its host controls rendering and capability availability. [MCP Apps overview](https://apps.extensions.modelcontextprotocol.io/api/documents/overview.html)

### 9.3 iOS presentation

- Work at 320 CSS pixels and wider without page-level horizontal scrolling.
- Favor a single-column device list and touch-sized switches/forms.
- Support light/dark themes, accessible labels, zoom/text scaling, safe-area insets, and keyboard-visible forms.
- Keep primary controls reachable without hover and avoid nested scrolling where possible.
- Use compact inline UI for a list or device; request a larger display mode for longer forms or lists only if the host supports it.
- Do not require picture-in-picture, desktop-sized modals, or a ChatGPT-specific API for the core flow.
- Use feature detection for optional host extensions and preserve a usable standard flow.

### 9.4 Isolation and content policy

- Run server-supplied UI within the host's sandbox and declared content security policy.
- Bundle frontend assets where practical; explicitly declare necessary asset/network origins.
- Device views obtain protected device data through host-mediated tools, not by storing bearer tokens in JavaScript.
- Escape device names and all other user-supplied strings before rendering.
- Open authentication and external navigation only through supported host actions; do not navigate the parent application arbitrarily.
- Never place per-user data into a globally cached HTML template. Supply it through authorized results.
- A host we control must implement equivalent sandbox/bridge restrictions; a bare web view alone is not a complete MCP Apps host.

## 10. Core end-to-end flows

### 10.1 Native app: sign up and add the first device

1. User opens the app and sees Log In / Sign Up.
2. User selects Sign Up and enters username and password.
3. Authentication service creates the account and session.
4. Devices screen loads and shows its empty state.
5. User selects Add Device, enters “Bedroom Lamp,” and submits.
6. Device service creates the owned device in Off state.
7. Devices screen displays the new device and switch.

### 10.2 Native app or MCP UI: control a device

1. An authenticated user views the latest device and version.
2. User sets its switch to On.
3. Native app calls the control API, or MCP UI requests `control_device` through the host.
4. Backend verifies identity, ownership, scope, and version, then persists the change.
5. The initiating view updates from the returned device.
6. Another client sees the change on its next refresh/resume; immediate cross-client push is not a version 1 requirement.

### 10.3 External MCP host: unauthenticated use

1. User connects or selects the integration.
2. If the host permits anonymous discovery, public tools and static UI resources are available; no private data is returned.
3. The host may invoke `show_auth`, or the first protected operation triggers a 401 authorization challenge.
4. The user sees the MCP authentication entry screen or the host's own Connect prompt.
5. The host opens the authorization page, where the user selects Log In / Sign Up and supplies only username and password.
6. After successful authentication/consent, the host receives its token through OAuth.
7. The host retries a permitted read and renders the device UI. Mutations still require applicable approval and fresh version validation.
8. Cancellation leaves the integration signed out and performs no device mutation.

### 10.4 Session expiry

1. A protected request fails because the session is expired or revoked.
2. The client may refresh a valid refresh session once under its session policy.
3. If refresh fails, clear protected presentation data and show authentication.
4. Preserve a non-secret destination where useful, but do not retain password input or queue an unapproved write.

## 11. Quality and operational requirements

- Persist accounts and devices across backend restarts; do not use an in-memory map as the only store.
- Enforce database uniqueness and atomic version updates, including concurrent API/MCP requests.
- Keep the interface responsive while waiting for requests and allow read retries without restarting the app.
- Use bounded timeouts and display uncertainty explicitly when a write response is lost.
- Retry reads with limits; reconcile writes before retrying rather than blindly resubmitting.
- Store minimal audit events for device mutations: verified actor, device ID, old/new state, timestamp, outcome, and request ID. Do not record passwords/tokens or request bodies containing them.
- Return safe diagnostics with correlation IDs, without exposing internal stack traces.
- Version API/tool contracts and UI assets so cached resources do not silently break current data shapes.
- Establish demo acceptance targets of a visible pending indicator within 200 ms of interaction and device API p95 latency below 1 second under a documented test environment. External host/network delays must be measured separately.
- Device polling/refresh must stop when the app/view is inactive; background continuous connectivity is not required.

## 12. Acceptance criteria

| ID | Scenario | Pass condition |
| --- | --- | --- |
| AC-01 | New registration | Username/password creates one account and opens an empty owned-device list. |
| AC-02 | Invalid or duplicate registration | Clear validation; no duplicate account or leaked password data. |
| AC-03 | Login/logout | Correct credentials restore access; wrong credentials fail; logout invalidates that session. |
| AC-04 | Add a device | One device is created for the current account, initially Off, and appears in both native and MCP reads. |
| AC-05 | Fetch all | Only the signed-in account's devices are returned; zero devices produces an empty array. |
| AC-06 | Fetch particular device | Correct owned device is returned; unknown/another user's ID yields indistinguishable not-found behavior. |
| AC-07 | Control | Switches work in both directions, persist across reload/restart, and update from server results. |
| AC-08 | Exactly two states | Invalid states are rejected; pending/error never become persisted device states. |
| AC-09 | Duplicate creation | Repeated/concurrent same-name creation cannot create duplicate owned devices. |
| AC-10 | Concurrent control | A stale version is rejected and refreshed; no silent lost update. |
| AC-11 | Ambiguous network outcome | UI reconciles through a read; no automatic inverse command or duplicate device. |
| AC-12 | Anonymous MCP connection | Public discovery/authentication UI is accessible where supported; device tools expose no private data. |
| AC-13 | MCP authentication entry | `show_auth` renders Sign Up / Log In in a compatible host; supported OAuth fallback works when inline credentials cannot. |
| AC-14 | External authorization | Both target hosts complete username/password account authorization and send valid scoped tokens to protected tools. |
| AC-15 | Credential isolation | Passwords/tokens are absent from tool schemas/results, model context, device HTML, analytics, and application logs. |
| AC-16 | Expired authorization | Protected calls fail appropriately; reauthentication works; canceled login causes no mutation. |
| AC-17 | MCP device UI | List, detail, add form, switches, refresh, loading, empty, and error states are functional. |
| AC-18 | Text fallback | Tool data and summaries remain usable when UI rendering is unavailable. |
| AC-19 | iOS usability | Core flows pass on a real iPhone, including keyboard, scrolling, light/dark appearance, and accessibility. |
| AC-20 | iPad layout | Core screens and MCP web layouts remain usable at supported iPad sizes. |
| AC-21 | User isolation | Account A cannot read/control Account B's device via any API, tool, guessed ID, or stale UI. |
| AC-22 | Cross-client consistency | A mutation through one client is reflected in another client's next successful refresh. |
| AC-23 | Sandbox | Embedded content cannot obtain host credentials or call unapproved native/host functions. |

External-host acceptance must record the client app/version, account plan, enabled connector capabilities, observed authentication presentation, and test date. A host capability limitation must be reported explicitly; native-app success alone does not establish ChatGPT/Claude iOS compatibility.

## 13. Suggested implementation sequence

1. Build persistent accounts, authentication, device model, and the four API operations.
2. Build the native iOS authentication and device-control screens.
3. Expose the same operations through MCP tools and validate authorization/ownership.
4. Add device MCP UI resources and verify the UI-to-tool-to-backend round trip.
5. Add the MCP authentication entry UI and interoperable hosted OAuth login/sign-up.
6. Test the complete workflows in ChatGPT and Claude on iOS and document their actual capabilities.
7. Run the acceptance scenarios, especially two-account isolation, lost responses, and concurrent state changes.

## 14. Decisions awaiting clarification

1. Confirm simulated devices for version 1, or identify the real hardware protocol if required.
2. Confirm whether the native iOS app plus external ChatGPT/Claude MCP UIs are both in scope.
3. Confirm the hosted username/password fallback for external clients. If an inline credential form on initial connection is mandatory, define which first-party host must guarantee it.

The draft uses the defaults in section 2 until these decisions are supplied. It does not claim that external apps can be forced to render an authentication form when the connection is first established.
