# Authentication, Consent and Isolation in MCP Apps, OpenAI Apps SDK and mcp-ui (state as of 2026-10-17)

All sources were retrieved on 2026-10-17 unless another date is given. The tags mean:
- **[STABLE]**: in the 2026-01-26 stable MCP Apps spec.
- **[DRAFT]**: only in `specification/draft/apps.mdx`, so it may change.
- **[HOST-DOC]**: vendor documentation (Anthropic or OpenAI), not spec text.

Shorthand: "Stable spec" means https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx and "Draft spec" means https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/draft/apps.mdx.

---

## Q1. What MCP Apps is (SEP-1865 / ext-apps), its status, versions and architecture

### Takeaway
MCP Apps is the first official MCP extension, `io.modelcontextprotocol/ui`. It was proposed as SEP-1865 on 2025-11-21 and marked "Stable (2026-01-26)". A server pre-declares `ui://` HTML templates (`text/html;profile=mcp-app`) and links them to tools with `_meta.ui.resourceUri`. The host renders the template in a sandboxed iframe. The View then talks to the host as a quasi-MCP client using JSON-RPC 2.0 over `postMessage`, and the host proxies `tools/call` and `resources/read` to the server.

The protocol version `2026-01-26` is confirmed: it appears in the stable spec's `ui/initialize` examples. The SDK (`@modelcontextprotocol/ext-apps`) reached v2.0.3 on 2026-09-25 with the wire protocol unchanged. Draft-only additions since then are sampling, app-provided tools, `ui/download-file` and `ui/notifications/request-teardown`.

### Cited Findings
**Status and versions**
- The stable spec header reads "SEP-1865: MCP Apps: Interactive User Interfaces for MCP", "**Track:** Extensions", "**Status:** Stable (2026-01-26)", "**Created:** 2025-11-21". The extension identifier is `io.modelcontextprotocol/ui`. — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- The draft spec at the same repo is labelled "**Status:** Draft". — [Draft spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/draft/apps.mdx)
- Recent commits to the draft spec:
  - 2026-02-19: `ui/download-file`
  - 2026-03-19: `ui/notifications/request-teardown`
  - 2026-04-21: sampling support, and "tool registration for Apps, to be called by Host (WebMCP-style!)"
  - 2026-07-07: missing `HostCapabilities` fields added
  - 2026-07-17: `object-src` synced with `default-src`
  - 2026-07-22: last commit
  - Source: [ext-apps commit history for draft/apps.mdx (GitHub API)](https://github.com/modelcontextprotocol/ext-apps/commits/main/specification/draft/apps.mdx)
- The View's handshake uses `protocolVersion: "2026-01-26"` (`initialize`/`ui/initialize` example and the `McpUiInitializeResult` example). The host↔server MCP `initialize` example separately shows core MCP `"protocolVersion": "2024-11-05"`. The two version strings belong to different layers. — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- SDK releases:
  - v2.0.0 (2026-09-08) moves to the split MCP TypeScript SDK 2.0 packages. "The MCP Apps wire protocol is unchanged: 2.x Views run in 1.x hosts and 2.x hosts render 1.x Views."
  - v2.0.3 was released 2026-09-25 and v1.7.5 on 2026-07-23.
  - Source: [ext-apps releases](https://github.com/modelcontextprotocol/ext-apps/releases)
- The official announcement (2026-01-26) says MCP Apps are "now live as an official MCP extension", "the first official MCP extension, and it's ready for production". Client availability at launch:
  - Claude: web and desktop
  - Goose: available
  - VS Code: Insiders
  - ChatGPT: "starting this week"
  - Source: [MCP blog, 2026-01-26](https://blog.modelcontextprotocol.io/posts/2026-01-26-mcp-apps/)
- The spec says MCP-UI and OpenAI's Apps SDK "significantly informed the design". It describes the extension as unifying "the approaches pioneered by MCP-UI and the Apps SDK into a single, open standard". — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)

**Capability negotiation**
- The host advertises `capabilities.extensions["io.modelcontextprotocol/ui"] = { mimeTypes: ["text/html;profile=mcp-app"] }` in MCP `initialize`.
- "Servers SHOULD check client capabilities before registering UI-enabled tools" and "Tools MUST return meaningful content array even when UI is available" (text fallback).
- Source: [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)

**UI resource**
- The URI "MUST use the `ui://` URI scheme". The `mimeType` "MUST be `text/html;profile=mcp-app`". Content is `text` or base64 `blob`, and it "MUST be valid HTML5 document".
- Security and rendering metadata sits under `_meta.ui`: `csp`, `permissions`, `domain` and `prefersBorder`.
- Source: [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- [DRAFT] `_meta.ui` may appear on the `resources/list` entry, on the `resources/read` content item, or both. The content item wins, and "Hosts MUST check both locations". — [Draft spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/draft/apps.mdx)

**Tool linkage and visibility**
- `Tool._meta.ui = { resourceUri?, visibility?: Array<"model"|"app"> }`, with default `["model","app"]`. The flat `_meta["ui/resourceUri"]` is deprecated and "will be removed before GA".
- Host MUSTs:
  - "Host MUST NOT include tools in the agent's tool list when their visibility does not include `"model"`"
  - "Host MUST reject `tools/call` requests from apps for tools that don't include `"app"` in visibility"
  - "Cross-server tool calls are always blocked for app-only tools"
  - "`"app"`: Tool is callable by the app from the same server connection only"
- "Host MUST use `resources/read` to fetch the referenced resource URI" and "Host MAY prefetch and cache UI resource content".
- Source: [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)

**Transport and roles**
- "Conceptually, UI iframes act as MCP clients, connecting to the host via a `postMessage` transport". "Hosts act as MCP servers (that can proxy the actual MCP server)". — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- Standard MCP methods a View may use [STABLE]: `tools/call`, `resources/read`, `notifications/message` (logging) and `ping`, plus the `ui/initialize` → `ui/notifications/initialized` handshake. — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- [DRAFT] Additions:
  - `tools/list` and `tools/call` become bidirectional, so the host can call app-registered tools.
  - `sampling/createMessage` from the View. The host "SHOULD apply rate limiting, cost controls, and user approval (human-in-the-loop)".
  - `ui/download-file`.
  - `ui/notifications/request-teardown`.
  - Source: [Draft spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/draft/apps.mdx)

**View → Host requests [STABLE]**
- `ui/open-link {url}`: "Host SHOULD open the URL in the user's default browser". The error example is "Link opening denied by user".
- `ui/message {role:"user", content:{type:"text",text}}`: the host "SHOULD add the message to the conversation context, preserving the specified role" and "MAY request user consent".
- `ui/request-display-mode {mode: inline|fullscreen|pip}`.
- `ui/update-model-context {content?, structuredContent?}`: overwrite semantics. The host "MAY defer sending the context to the model until the next user message" and "MAY display context updates to the user".
- Source: [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)

**Host → View notifications [STABLE]**
- `ui/notifications/tool-input` is required, sent once after init.
- `ui/notifications/tool-input-partial` is optional streaming. Views "MUST NOT rely on partial arguments for critical operations".
- `ui/notifications/tool-result` carries a full `CallToolResult`.
- Also: `ui/notifications/tool-cancelled`, `ui/notifications/host-context-changed`, the `ui/resource-teardown` request, and `ui/notifications/size-changed` (View → Host).
- "The Host MUST NOT send any request or notification to the View before it receives an `initialized` notification."
- Source: [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)

**Host context (`McpUiInitializeResult.hostContext`)**
- Fields: `toolInfo {id, tool}`, `theme`, `styles`, `displayMode`, `availableDisplayModes`, `containerDimensions`, `locale`, `timeZone`, `userAgent`, `platform`, `deviceCapabilities`, `safeAreaInsets`.
- The list has no identity, user or token field.
- `hostCapabilities` includes `openLinks`, `serverTools`, `serverResources`, `logging`, and `sandbox {permissions, csp}` (the CSP and permissions the host actually granted).
- Source: [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- [DRAFT] adds `downloadFile`, `updateModelContext`, `message` and `sampling` to `hostCapabilities`. — [Draft spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/draft/apps.mdx)

**Data passing guidance**
- "`content`: Text representation for model context". "`structuredContent`: Structured data optimized for UI rendering (not added to model context)". "`_meta`: … not intended for model context". — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)

**Lifecycle, usable as a diagram script**
1. Host gets `resources/list` and `tools/list`.
2. Host → Server: `tools/call`. In parallel, the host renders the iframe. A web host first renders the Sandbox Proxy, which then exchanges `ui/notifications/sandbox-proxy-ready` and `ui/notifications/sandbox-resource-ready {html, sandbox?, csp?, permissions?}` with the host.
3. View → Host: `ui/initialize`. Host → View: `McpUiInitializeResult`. View → Host: `ui/notifications/initialized`.
4. Host → View: `tool-input-partial*`, then `tool-input`, then `tool-result` or `tool-cancelled`.
5. Interactive loop:
   - View → Host → Server: `tools/call`
   - View → Host: `ui/message`
   - View → Host: `ui/update-model-context`
   - View → Host → Server: `resources/read`
6. Host → View: `ui/resource-teardown`.

Source: [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)

### Inferences
- The protocol makes the host a mediating proxy and policy enforcement point. The View never addresses the MCP server directly over MCP. Its only path to server tools is a JSON-RPC message to the host, which the host may filter by visibility, block or put to the user for approval.
- Because `hostContext` has no user-identity or credential fields, a View learns who the user is only from tool results the server chooses to return.

### Gaps
- The extension has no standalone protocolVersion history beyond `2026-01-26`. The SDK's version (2.0.x) is separate from the spec revision. I found no newer dated stable spec directory: only `2026-01-26/` and `draft/` exist.

---

## Q2. Where credentials live: does the View hold a token, how app-initiated `tools/call` is forwarded, and what happens on 401

### Takeaway
By design, the View holds no MCP OAuth token. It sends `tools/call` to the host over `postMessage`. The host forwards the call on its own authenticated MCP connection, which for Claude and ChatGPT runs from the vendor's backend.

The ext-apps project documents a "UI-initiated auth escalation" pattern for app calls that hit protected tools:
1. The server answers HTTP 401 with `WWW-Authenticate`.
2. The host runs OAuth.
3. The host retries the call.
4. The result returns to the View as the `tools/call` response.

Hosts differ in how a server triggers linking:
- **Claude** requires a transport-level **HTTP 401**. A 200 with `isError` does not trigger it.
- **ChatGPT** surfaces tool-level linking from an **error result carrying `_meta["mcp/www_authenticate"]`** plus per-tool `securitySchemes`.

The only sanctioned case where the View holds credentials is when it runs its own OAuth or API flow against a third-party API. That case requires a stable `ui.domain` origin and a `connectDomains` entry.

### Cited Findings
- The spec gives the host a forwarding role: "The Host MAY forward any message from the View (coming via the Sandbox) to the MCP Apps server, for any method that doesn't start with `ui/`. While the Host SHOULD ensure the View's MCP connection is spec-compliant, it MAY decide to block some messages or subject them to further user approval." The spec text itself contains no OAuth or token language. — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- The ext-apps "Authorization" doc (Security group, added 2026-03-06, revised 2026-07-15) describes two models:
  - "Per-server authorization": every `/mcp` request needs a Bearer token, otherwise HTTP 401, and "the host must complete the OAuth flow before the client can use any tools".
  - "Per-tool authorization": public tools pass, and protected `tools/call` gets 401.
  - Source: [ext-apps docs/authorization.md](https://github.com/modelcontextprotocol/ext-apps/blob/main/docs/authorization.md)
- The same doc's "UI-initiated auth escalation" pattern:
  1. "A public tool … loads the UI without requiring authorization".
  2. "The user clicks a button that calls a protected tool via `app.callServerTool()`".
  3. "The MCP host receives HTTP `401` and automatically runs the OAuth flow".
  4. "After the user completes the OAuth flow, the host retries the tool call with the acquired token".
  5. "The protected data appears in the UI".
  - It adds: "The host manages the entire OAuth flow — the app code simply calls the tool and handles the result." It names "Claude Desktop" as the example host that "sees the `401`, discovers the authorization server via the metadata URL, runs the OAuth flow with the user, and retries the request".
  - Source: [ext-apps docs/authorization.md](https://github.com/modelcontextprotocol/ext-apps/blob/main/docs/authorization.md)
- The doc also covers server enforcement: the 401 must come from the HTTP layer: "authorization is enforced at the HTTP boundary … not as a tool-level error". Tool handlers re-check `authInfo` as "defence-in-depth". Tokens are verified as JWTs against JWKS, and servers "must validate that tokens were issued specifically for them". — [ext-apps docs/authorization.md](https://github.com/modelcontextprotocol/ext-apps/blob/main/docs/authorization.md)
- The `lazy-auth-server` reference example shows the full flow:
  - The public app's "Auth me" button calls a protected tool via `callServerTool`.
  - "The host sees the 401, runs the OAuth flow, retries, and the result renders inline."
  - Discovery runs PRM (RFC 9728), then AS metadata (RFC 8414), then auth code + PKCE.
  - Defaults are a 30 s access-token TTL and a 5 min refresh-token TTL, to show "direct success (<30s), silent refresh (30s–5min), and full re-auth (>5min)".
  - The example notes "MCP hosts send the MCP server URL as the `resource` parameter in OAuth authorization and token requests" (RFC 8707).
  - It also demonstrates URL elicitation (`elicitInput` and the `-32042` `UrlElicitationRequired` error) as a complementary sign-in pattern.
  - Source: [ext-apps examples/lazy-auth-server/README.md](https://github.com/modelcontextprotocol/ext-apps/tree/main/examples/lazy-auth-server)
- [HOST-DOC, Claude] Tool calls go through Claude's backend: "MCP tool calls are proxied through Claude's backend and egress from Anthropic's published IP ranges, not the user's device." In contrast, assets and API calls the app makes from client-side code come from the device with `Origin: {hash}.claudemcpcontent.com`. — [Claude: Troubleshoot MCP Apps](https://claude.com/docs/connectors/building/mcp-apps/troubleshooting)
- [HOST-DOC, Claude] Anthropic's outbound traffic comes from `160.79.104.0/21`. — [Claude: Authentication for connectors](https://claude.com/docs/connectors/building/authentication)
- [HOST-DOC, Claude] "Claude starts sign-in only when the HTTP request itself fails with `401 Unauthorized` and a `WWW-Authenticate` header … once the MCP SDK is running a tool, whatever the handler returns is wrapped in a `200`." Also: "A `200` with `isError: true` … Claude passes the error text to the model as the tool result and moves on, and there is no auth prompt." — [Claude: Lazy authentication](https://claude.com/docs/connectors/building/lazy-authentication)
- [HOST-DOC, Claude] The user sees: Claude calls the protected tool, "your server refuses it, and an inline **Connect** card appears in the conversation". The user signs in "in a popup", and "Claude retries the same tool call automatically with the new token". With Enterprise Managed Auth, "the same refusal triggers a silent token exchange instead of the **Connect** card". — [Claude: Lazy authentication](https://claude.com/docs/connectors/building/lazy-authentication)
- [HOST-DOC, Claude] On step-up: "A `403` triggers re-authentication only when accompanied by `WWW-Authenticate: Bearer error="insufficient_scope"` … any other `403` is surfaced as a terminal error." — [Claude: Lazy authentication](https://claude.com/docs/connectors/building/lazy-authentication)
- [HOST-DOC, Claude] The case where a View holds its own credentials: setting `_meta.ui.domain` "opts your app into a stable sandbox origin, which you need if your app runs its own OAuth flow". — [Claude: Troubleshoot MCP Apps](https://claude.com/docs/connectors/building/mcp-apps/troubleshooting)
- The spec's `domain` field is described as "Useful when views need stable, dedicated origins for OAuth callbacks, CORS policies, or API key allowlists". — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- [HOST-DOC, OpenAI] Token handling in ChatGPT:
  - "ChatGPT attaches the token as `Authorization: Bearer <token>` on subsequent MCP requests."
  - Linking UI needs "both metadata (`securitySchemes` and the resource metadata document) **and** runtime errors that carry `_meta["mcp/www_authenticate"]`. Without both halves ChatGPT will not show the linking UI for that tool." The error result must have `isError: true`, and the challenge must contain `error` and `error_description`.
  - Source: [OpenAI Apps SDK: Authentication](https://developers.openai.com/apps-sdk/build/auth)
- [HOST-DOC, OpenAI] "OpenAI routes each tool call using the selected connection's authenticated credentials" (multi-account). — [OpenAI Apps SDK: Authentication](https://developers.openai.com/apps-sdk/build/auth)
- [HOST-DOC, OpenAI] "Avoid embedding secrets or tokens in component props." — [OpenAI Apps SDK: Security & Privacy](https://developers.openai.com/apps-sdk/guides/security-privacy)
- [HOST-DOC, OpenAI] `window.openai.toolResponseMetadata` exposes the "full MCP result envelope, including hidden `_meta`" to the widget. — [OpenAI Apps SDK: Reference](https://developers.openai.com/apps-sdk/reference)

**Step-by-step flow for a diagram: View-initiated protected call (Claude-style host)**

Steps 1–8 are assembled from the [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx), [ext-apps authorization.md](https://github.com/modelcontextprotocol/ext-apps/blob/main/docs/authorization.md), [Claude: Authentication](https://claude.com/docs/connectors/building/authentication), [Claude: Lazy authentication](https://claude.com/docs/connectors/building/lazy-authentication) and [Claude: Troubleshoot MCP Apps](https://claude.com/docs/connectors/building/mcp-apps/troubleshooting).

1. The user clicks in the View (inner iframe).
2. The View calls `window.parent.postMessage({jsonrpc:"2.0", id:N, method:"tools/call", params:{name, arguments}})`. On web hosts this goes to the Sandbox proxy, which relays it unchanged to the host page.
3. The host checks that the tool's `visibility` includes `"app"` and that it is the same server connection. The host MAY require user approval.
4. The host (vendor backend) sends `POST /mcp tools/call` with `Authorization: Bearer <host-stored token>`, if one exists.
5. If the server returns `401` with `WWW-Authenticate: Bearer resource_metadata="…", scope="…"`, the host:
   - fetches PRM, then AS metadata;
   - registers via CIMD or DCR;
   - shows the Connect UI or popup;
   - runs the authorization code + PKCE (S256) flow with `resource=<MCP URL>`;
   - receives the redirect at `https://claude.ai/api/mcp/auth_callback`;
   - exchanges the code for a token in its backend.
6. The host retries `tools/call` with the token.
7. Host → View: a JSON-RPC response with `id:N` and `result: CallToolResult`, or an error.
8. The token is never in any message to the View.

### Inferences
- The token lives in the host's backend credential store (Claude backend or ChatGPT connector platform), bound to the user's connection. The View sees only results. This is an inference from the "proxied through Claude's backend" statement, the absence of any token field in `hostContext` or the notifications, and OpenAI's guidance not to put tokens in component props.
- Hosts that pass raw `_meta` through to the View expose server-set `_meta` to the View: ChatGPT exposes it via `toolResponseMetadata`, and the MCP Apps `tool-result` notification passes `CallToolResult` with `_meta` intact. Servers must therefore never put secrets in result `_meta`.
- Claude's and ChatGPT's triggers are incompatible. A server that wants linking in both should:
  - return HTTP 401 with `WWW-Authenticate` for Claude, and
  - declare `securitySchemes` and be able to return `_meta["mcp/www_authenticate"]` for ChatGPT.
  - ChatGPT's own docs also say to "return `401 Unauthorized` with a `WWW-Authenticate` header" on token-verification failure, so a 401-based gate may work in both. That is unverified for ChatGPT tool-level linking.
- If a View runs its own OAuth (via `ui.domain`), its token sits in browser JS or storage on a vendor-controlled sandbox origin such as `*.claudemcpcontent.com` or `*.oaiusercontent.com`. That token is outside the host's credential store and outside host consent UX.

### Gaps
- Claude's own docs describe the Connect card and retry only for calls Claude (the model) makes. I found no Anthropic page that explicitly says a View-initiated `tools/call` that gets a 401 shows the same Connect card. The ext-apps doc asserts it for "the MCP host (e.g., Claude Desktop)".
- I found no OpenAI statement on whether `window.openai.callTool` / `tools/call` from a widget triggers the linking UI on `mcp/www_authenticate`, or whether it fails back to the widget.
- No source specifies what JSON-RPC error a View receives if the user cancels OAuth.
- No source says whether Claude's sandbox iframe allows popups, which a View-run OAuth flow would need.

---

## Q3. Sandboxing and isolation: iframe attributes, double-iframe proxy, CSP, permissions, postMessage validation, what a View can do

### Takeaway
The spec requires two layers of isolation.
- **Sandboxing.** Views must render in sandboxed iframes. A **web** host MUST use an intermediate **Sandbox proxy** on a **different origin** with `allow-scripts allow-same-origin`. The proxy loads the View in an inner iframe and relays every message except `ui/notifications/sandbox-*`.
- **CSP.** The host MUST build a CSP from `_meta.ui.csp` (`connectDomains`, `resourceDomains`, `frameDomains`, `baseUriDomains`). It must use a deny-by-default policy when none is declared, and it "MUST NOT allow undeclared domains".

The View cannot navigate the top window, download files, or open links on its own. Each of those is a host-mediated request (`ui/open-link`, draft `ui/download-file`) that the host can gate. The reference SDK validates `event.source`, and the reference sandbox validates `event.origin`. The spec's own minimal example posts with `'*'` and does no checks.

### Cited Findings
- "All View content MUST be rendered in sandboxed iframes with restricted permissions. … All communication with the host is done via `postMessage`, where the host is in control." — [Stable spec, Security Implications](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- Sandbox proxy (web hosts) [STABLE]:
  - "If the Host is a web page, it MUST wrap the View and communicate with it through an intermediate Sandbox proxy."
  - "The Host and the Sandbox MUST have different origins."
  - "The Sandbox MUST have the following permissions: `allow-scripts`, `allow-same-origin`."
  - "The Sandbox MUST forward messages … for any method that doesn't start with `ui/notifications/sandbox-`."
  - "The Sandbox SHOULD NOT create/send any requests to the Host or to the View."
  - The CSP must "Block dangerous features (`object-src 'none'`)".
  - Source: [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
  - [DRAFT] relaxes proxy-ready and resource-ready from MUST to SHOULD (commit "Change Host <> Sandbox communication protocol to 'SHOULD'", 2026-02-12). — [Draft spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/draft/apps.mdx)
- `ui/notifications/sandbox-resource-ready` params: `{ html, sandbox? (override for inner iframe sandbox attribute), csp?, permissions? }`. "The `permissions` field maps to the inner iframe's `allow` attribute." — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- The default CSP when `ui.csp` is omitted ("Host MUST use") is `default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self' data:; connect-src 'none';`. The spec adds "No Loosening: Host MAY further restrict but MUST NOT allow undeclared domains" and "Audit Trail: Host SHOULD log CSP configurations". — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- CSP field mapping:
  - `connectDomains` maps to `connect-src` ("Empty or omitted = no external connections").
  - `resourceDomains` maps to `script-src`, `style-src`, `img-src`, `font-src` and `media-src`, with wildcard subdomains allowed.
  - `frameDomains` maps to `frame-src`, defaulting to `'none'`.
  - `baseUriDomains` maps to `base-uri`, defaulting to `'self'`.
  - Security requirements: "Host MUST block connections to undeclared domains"; "Host SHOULD warn users when UI requires external domain access".
  - Source: [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- The spec's CSP-construction sample uses `connect-src 'self' ${connectDomains}`, while the "Restrictive Default" text uses `connect-src 'none'`. The spec does not reconcile this internal inconsistency. — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- Permissions (`camera`, `microphone`, `geolocation`, `clipboardWrite`) map to Permission Policy. "Hosts MAY honor these" and "Apps SHOULD NOT assume permissions are granted". The host reports what it granted in `hostCapabilities.sandbox`. — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- [DRAFT] "MCP Apps run in sandboxed iframes where direct file downloads are blocked (`allow-downloads` is not set). `ui/download-file` provides a host-mediated mechanism". — [Draft spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/draft/apps.mdx)
- The reference host sandbox (`examples/basic-host/src/sandbox.ts`):
  - It validates `document.referrer` against an allowlist and derives `EXPECTED_HOST_ORIGIN`.
  - It deliberately probes `window.top` and expects a `SecurityError` ("If you see this, the sandbox is not setup securely").
  - The inner iframe gets `sandbox="allow-scripts allow-same-origin allow-forms"`.
  - Messages from the parent are rejected unless `event.origin === EXPECTED_HOST_ORIGIN`.
  - "CSP is enforced via HTTP headers on sandbox.html … tamper-proof unlike meta tags."
  - Source: [ext-apps basic-host sandbox.ts](https://github.com/modelcontextprotocol/ext-apps/blob/main/examples/basic-host/src/sandbox.ts)
- The SDK's `PostMessageTransport`:
  - "The `eventSource` parameter is required and validates the message source window by checking `event.source`. For views, pass `window.parent`. For hosts, pass `iframe.contentWindow`."
  - It sends with `"*"`: "visible to all frames. The receiver should validate the message source for security."
  - Source: [ext-apps src/message-transport.ts](https://github.com/modelcontextprotocol/ext-apps/blob/main/src/message-transport.ts)
- The spec's "you don't need an SDK" sample uses `window.parent.postMessage(…, '*')` and checks neither `event.source` nor `event.origin`. — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- Host message validation: "Validate all incoming messages from UI iframes; Reject malformed message types; Log View-initiated RPC calls for security review." Predeclared-resource review: "Generate hash/signature for resources … Implement allowlists/blocklists based on resource hashes." — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- Origins:
  - The spec: "If omitted, Host uses default sandbox origin (typically per-conversation)". Examples: `{hash}.claudemcpcontent.com` and `www-example-com.oaiusercontent.com`. — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
  - Claude requires `ui.domain` to equal "the first 32 hexadecimal characters of the SHA-256 digest of your full connector URL" + `.claudemcpcontent.com`. Otherwise it shows `Invalid ui.domain format` / `ui.domain mismatch` and does not render. Local stdio connectors cannot use `ui.domain`. — [Claude: Troubleshoot MCP Apps](https://claude.com/docs/connectors/building/mcp-apps/troubleshooting)
  - ChatGPT: `ui.domain` is "required for plugins with UI and unique per plugin", with the default `https://web-sandbox.oaiusercontent.com`. — [OpenAI Apps SDK: Reference](https://developers.openai.com/apps-sdk/reference)
- [HOST-DOC, Claude] "Interactive connectors run in sandboxed iframes with strict Content Security Policies." On iOS the app renders MCP Apps in a `WKWebView`. — [Claude support: Use interactive connectors](https://support.claude.com/en/articles/13454812-use-interactive-connectors-in-claude) (search-result summary); [Claude: Troubleshoot MCP Apps](https://claude.com/docs/connectors/building/mcp-apps/troubleshooting)
- [HOST-DOC, OpenAI] On widget restrictions:
  - "Widgets run inside an isolated iframe with a strict Content Security Policy. They cannot access privileged browser APIs such as `window.alert`, `window.prompt`, `window.confirm`, or `navigator.clipboard`."
  - Nested frames are blocked unless declared in `frameDomains`.
  - "An embedded page follows its own CSP. The widget `connectDomains` and `resourceDomains` allowlists do not restrict network requests made inside that page."
  - Source: [OpenAI Apps SDK: Security & Privacy](https://developers.openai.com/apps-sdk/guides/security-privacy)
- [HOST-DOC, OpenAI] Legacy and redirect keys:
  - `openai/widgetCSP` (snake_case `connect_domains`, `resource_domains`, `frame_domains`, `redirect_domains`) is "legacy".
  - `redirect_domains` is "still required to allowlist `window.openai.openExternal` targets". `ui.csp` "does not support `redirect_domains`".
  - `frameDomains` "requires a justification at submission and may face extra review".
  - Source: [OpenAI Apps SDK: Reference](https://developers.openai.com/apps-sdk/reference)

**What a View may do (through host-mediated requests)**
- [HOST-DOC, Claude] Opening links:
  - A `ui/open-link` shows an "Open external link" confirmation modal; "The modal protects users from being silently redirected by an embedded app."
  - Directory connectors can allowlist HTTPS origins or custom schemes. The modal is skipped only after "a real user gesture".
  - "Custom connectors and locally configured servers always show it."
  - Generic schemes (`javascript`, `data`, `file`, `blob`, `intent`, `http`, `https` as a bare scheme, and others) are rejected as custom-scheme entries.
  - Source: [Claude: Open external links from MCP Apps](https://claude.com/docs/connectors/building/mcp-apps/external-links)

### Inferences
- The double-iframe design gives three origins:
  - the host (e.g. claude.ai)
  - the sandbox proxy (a separate origin with `allow-same-origin`, so it can own a CSP header and real origin)
  - the inner View
  
  Because the View cannot reach the host's DOM, cookies or storage, it cannot read the host's session cookie or the OAuth tokens the host backend holds.
- The reference inner iframe omits `allow-popups`, `allow-top-navigation` and `allow-downloads`. That explains why links and downloads are host-mediated RPCs that hosts can confirm. Production hosts' exact attribute sets are not documented.
- `'unsafe-inline'` scripts are always permitted, so CSP restricts egress, not code execution. The main exfiltration control is `connect-src`, plus `img-src`/`resourceDomains` for GET-beacon exfiltration.

### Gaps
- Neither Anthropic nor OpenAI publishes the exact `sandbox` attribute list or Permission Policy their production iframes use.
- No source says whether Claude or ChatGPT warn users about declared `connectDomains`, which the spec rates SHOULD.
- No vendor documents hash-pinning or a review of resource HTML, which the spec suggests.

---

## Q4. Guidance against credential collection in Views, phishing UI, clickjacking/UI redressing and host-UI impersonation

### Takeaway
The MCP Apps spec names phishing and social engineering in its threat model. Its mitigations are generic: sandboxing, reviewable predeclared templates, and "Hosts should clearly indicate sandboxed UI boundaries". The spec has **no normative rule against password fields** in Views and no clickjacking-specific control.

The concrete prohibitions come from host store policies:
- **OpenAI's plugin guidelines** forbid collecting "access credentials and authentication secrets (such as API keys, MFA/OTP codes, or passwords)" and forbid "misleading or copycat designs, impersonation".
- **Claude's** documented controls are the `ui/open-link` confirmation modal and directory review. I found no explicit Anthropic rule about password fields in Views.

### Cited Findings
- Threat model: "Malicious server delivers harmful HTML content; Compromised View attempts to escape sandbox; View attempts unauthorized tool execution; View exfiltrates sensitive host data; View performs phishing or social engineering." — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- "Social engineering: UI can still display misleading content. Hosts should clearly indicate sandboxed UI boundaries." Also "Resource consumption: … Hosts should implement resource limits." — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- Predeclared-template review rationale: "Allows hosts to review UI templates". External-URL content was deferred because of "concerns around model visibility, inability to screenshot content, and review process". — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- [DRAFT] For app-provided tools, hosts SHOULD "Reject results that appear malicious (e.g., phishing content)" and "Show app name and version in tool call confirmations". — [Draft spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/draft/apps.mdx)
- [HOST-DOC, OpenAI plugin guidelines] (the page fetched from `/apps-sdk/app-submission-guidelines` is titled "Plugin Guidelines" and is undated):
  - Plugins must not collect "Access credentials and authentication secrets (such as API keys, MFA/OTP codes, or passwords)", PCI payment data, PHI or government IDs.
  - Metadata must not "seek secrets or protected context".
  - "misleading or copycat designs, impersonation" is prohibited, and plugins "should not imply that they are made or endorsed by OpenAI".
  - Authentication "flow must be transparent and explicit".
  - Source: [OpenAI Plugin/App submission guidelines](https://developers.openai.com/apps-sdk/app-submission-guidelines)
- [HOST-DOC, OpenAI] Iframe embeds:
  - These should come from the MCP server's "own registrable domain".
  - Third-party iframes are allowed only where "the embedded experience is essential", with justification.
  - "Sharing the MCP server's domain does not guarantee approval."
  - Commerce must use "external checkout on the merchant's own domain". "No other third-party checkout may be embedded or hosted in the plugin UI."
  - Source: [OpenAI guidelines](https://developers.openai.com/apps-sdk/app-submission-guidelines)
- [HOST-DOC, OpenAI] Widgets cannot call `window.alert`, `window.prompt` or `window.confirm`. — [OpenAI Security & Privacy](https://developers.openai.com/apps-sdk/guides/security-privacy)
- [HOST-DOC, Claude] The `ui/open-link` modal shows the destination URL, and the allowlist bypass requires user activation. Look-alike hosts such as `https://example.com.attacker.net` still prompt. — [Claude: Open external links](https://claude.com/docs/connectors/building/mcp-apps/external-links)
- [HOST-DOC, Claude] Directory review rejects tool descriptions with prompt-injection patterns, including "hidden, obfuscated, or encoded instructions". Connectors must not "query Claude's memory, chat history, conversation summaries, or user files". — [Claude: Connector pre-submission checklist](https://claude.com/docs/connectors/building/review-criteria)
- [HOST-DOC, Claude] The consent screen must show the redirect hostname: "On your consent screen, display the redirect URI's hostname clearly." — [Claude: Authentication](https://claude.com/docs/connectors/building/authentication)

### Inferences
- Account linking is designed to happen in a **host-owned, top-level browser context**: Claude's popup or same-tab redirect, and ChatGPT's linking UI. That keeps the real IdP origin visible in the address bar, which an in-iframe login form would hide. A View that renders its own username/password form defeats this and would breach OpenAI's guidelines.
- Clickjacking defences rely on hosts:
  - drawing visible boundaries (`prefersBorder`, host chrome)
  - confirming sensitive actions in host-owned modals that the View cannot overlay, because the View is confined to its iframe box
  
  No source states explicit anti-overlay or `frame-ancestors` rules for Views.

### Gaps
- I found no Anthropic document that explicitly bans password or credential collection inside MCP App Views. The Anthropic Software Directory Policy (support.claude.com/en/articles/13145358) is referenced but was not retrieved.
- No source covers fullscreen or PiP spoofing of host chrome.
- I found no independent security research paper on MCP Apps clickjacking; the search returned vendor blogs only.

---

## Q5. How hosts gate writes: confirmations, annotations, `securitySchemes`, mixed auth, linking, refresh and re-auth

### Takeaway
Write gating is host policy, driven by MCP tool annotations.
- **Claude:** read-only tools "can run without per-call confirmation, and destructive tools always prompt". Users get per-tool "Always allow / Needs approval / Blocked" settings.
- **ChatGPT:** requires `readOnlyHint`, `destructiveHint` and `openWorldHint` on every tool, and treats them as UX hints that "do not grant permission".
- **The MCP Apps spec** only allows hosts to "subject [View messages] to further user approval". The draft recommends confirmations for non-read-only *app-provided* tools.

Mixed auth works differently per host:
- **Claude:** "lazy authentication" with HTTP 401 per protected tool.
- **ChatGPT:** per-tool `securitySchemes` (`noauth` / `oauth2` + scopes, or both for optional auth), plus `mcp/www_authenticate`.

Refresh is host-managed. Claude refreshes reactively on 401 and proactively 5 minutes before expiry. ChatGPT may send `id_token_hint` when re-authorizing.

### Cited Findings
- Spec: the host "MAY decide to block some messages or subject them to further user approval". The announcement says "Hosts can require explicit approval for UI-initiated tool calls". — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx); [MCP blog 2026-01-26](https://blog.modelcontextprotocol.io/posts/2026-01-26-mcp-apps/)
- [DRAFT] Approval guidance for app tools:
  - Approval granularity options: "Per-app-instance", "Per-server", "Per-tool approval (approve based on tool annotations, e.g. `readOnlyHint`)" and hybrid.
  - "Require explicit user approval for tools with `readOnlyHint: false`". No annotation means "User confirmation required (safe default)".
  - The rationale section suggests "Per-app-instance approval (confirm each time a specific app instance calls a tool)".
  - Source: [Draft spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/draft/apps.mdx)
- [HOST-DOC, Claude] Tool permissions:
  - "Claude can ask for your approval before it uses one of the connector's tools. Select **Allow once** … or **Always allow**".
  - Per tool or group: "**Always allow**, **Needs approval**, or **Blocked**".
  - On lost access the row shows "**Reconnect**". "Disconnect" signs Claude out of the service.
  - Source: [Claude: Get started with connectors](https://claude.com/docs/connectors/overview)
- [HOST-DOC, Claude] "Every tool must include a `title` and the applicable hint: `readOnlyHint: true` for read-only tools, and `destructiveHint: true` for tools that modify or delete data. These determine auto-permissions in Claude. Read-only tools can run without per-call confirmation, and destructive tools always prompt." Catch-all tools must be split into read and write tools. — [Claude: Connector pre-submission checklist](https://claude.com/docs/connectors/building/review-criteria)
- [HOST-DOC, Claude] Lazy auth ("sometimes called mixed auth"): the server lets Claude "connect, list tools, and call the tools that don't need the person's account right away, and asks for sign-in only when Claude calls a tool that does". The `scope` on the 401 controls requested scopes. Without it Claude requests all `scopes_supported` plus `offline_access`, "which can produce an over-broad consent prompt". — [Claude: Lazy authentication](https://claude.com/docs/connectors/building/lazy-authentication)
- [HOST-DOC, Claude] Scope step-up uses `403` + `error="insufficient_scope", scope="orders:write"`. The guidance is "List every scope the user still needs alongside the newly required ones". — [Claude: Lazy authentication](https://claude.com/docs/connectors/building/lazy-authentication)
- [HOST-DOC, Claude] Refresh: "Claude refreshes tokens reactively on a `401` response, and proactively up to five minutes before the stored expiry". Servers should return `invalid_grant` and "Rotate refresh tokens for public-client connections". Refresh timeout is 30 s; other OAuth endpoints get 10 s. — [Claude: Authentication](https://claude.com/docs/connectors/building/authentication)
- [HOST-DOC, OpenAI] `securitySchemes`:
  - It is per tool. "`noauth`: The tool is callable anonymously". "`oauth2`: … include the scopes you will request so the consent screen is accurate". "Declaring both `noauth` and `oauth2` tells ChatGPT it can start with anonymous calls but that linking unlocks privileged behavior."
  - "Regardless of what you signal to the client, your server must still verify the token, scopes, and audience on every invocation."
  - "server-level defaults make it difficult to evolve individual tools later."
  - Source: [OpenAI Apps SDK: Authentication](https://developers.openai.com/apps-sdk/build/auth)
  - The reference lists `securitySchemes` in tool `_meta` as a "back-compat mirror for clients that only read `_meta`". — [OpenAI Apps SDK: Reference](https://developers.openai.com/apps-sdk/reference)
- [HOST-DOC, OpenAI] Annotations:
  - `readOnlyHint`, `destructiveHint` and `openWorldHint` are **required**; `idempotentHint` is optional.
  - `destructiveHint` means "the host should elicit explicit approval first".
  - The hints "only shape how ChatGPT or Codex frames the call to the user".
  - "For approval-gated tools, … `toolInput` may be missing initially, and the host sends it via `ui/notifications/tool-input` after approval."
  - Source: [OpenAI Apps SDK: Reference](https://developers.openai.com/apps-sdk/reference)
- [HOST-DOC, OpenAI] Guidelines:
  - "do not grant permission or replace authentication, authorization and scope checks".
  - `destructiveHint: true` applies to "deletion, overwriting, cancellation, access revocation, or irreversible sends or transactions". "Being able to undo an action does not, by itself, justify" false.
  - Mis-annotation "may be rejected" or the plugin removed.
  - Source: [OpenAI guidelines](https://developers.openai.com/apps-sdk/app-submission-guidelines)
- [HOST-DOC, OpenAI] "Use the host's confirmation prompts for destructive actions" and "Requiring human confirmation for irreversible operations." — [OpenAI Security & Privacy](https://developers.openai.com/apps-sdk/guides/security-privacy)
- [HOST-DOC, OpenAI] Re-auth and accounts:
  - "ChatGPT may send the prior OIDC ID token as `id_token_hint` when reauthorizing, including for additional scopes."
  - Multi-account: users can connect several accounts. An `_meta["openai/profile"]: true` read-only profile tool returns a stable opaque `id`, which must not be an email and must persist across refresh and reconnect.
  - Source: [OpenAI Apps SDK: Authentication](https://developers.openai.com/apps-sdk/build/auth)
- [Secondary; search summary only, page not fetched] ChatGPT developer mode reportedly says "write actions by default require confirmation", and tools without `readOnlyHint` are treated as writes. Approval can be remembered per tool within a conversation. — [OpenAI developer mode guide (via search)](https://developers.openai.com/api/docs/guides/developer-mode)

### Inferences
- For a View-initiated write, two independent gates can apply:
  1. The **host approval gate** for the `tools/call` (per-tool permission or annotation policy).
  2. The **authorization gate** at the server (401 or `mcp/www_authenticate` leading to OAuth).
  
  The report's diagrams should show both. Annotations are advisory, so the server's token, scope and audience checks are the authoritative control.
- `visibility: ["app"]` tools are hidden from the model but still run with the user's token and are callable by the View. They are not "safe" because the model cannot see them. Servers should annotate and authorize them like any other tool.

### Gaps
- No vendor documents whether View-initiated `tools/call` passes through the same approval prompts ("Allow once" in Claude, the write confirmation in ChatGPT) as model-initiated calls.
- The ChatGPT developer-mode confirmation details came from a search summary. The `.md` fetch returned a redirect stub, so they are unverified.

---

## Q6. OpenAI Apps SDK authentication and widget security documentation

### Takeaway
As of October 2026 OpenAI's docs describe "plugins" that run in ChatGPT and Codex.
- They require OAuth 2.1 per the MCP authorization spec (2025-11-25), with PKCE S256 and the `resource` parameter.
- CIMD is preferred (`https://chatgpt.com/oauth/client.json`), with DCR as a fallback.
- RFC 9207 `iss` governs the redirect: the stable redirect `https://chatgpt.com/connector_platform_oauth_redirect` versus a per-callback fallback.
- Tool-level linking is triggered via `securitySchemes` + `_meta["mcp/www_authenticate"]`.

The docs now steer widget authors to MCP Apps standard fields (`ui.resourceUri`, `ui.csp`, `ui.domain`, `ui.visibility`) and bridge methods. `openai/*` keys and `window.openai` remain as compatibility aliases or ChatGPT-only extensions.

### Cited Findings
- The page addresses "Published plugins can run in ChatGPT and Codex". "anything that exposes customer-specific data or write actions should authenticate users". Roles are resource server (MCP server), authorization server (IdP) and client (ChatGPT/Codex). — [OpenAI Apps SDK: Authentication (.md)](https://developers.openai.com/apps-sdk/build/auth)
- Required metadata:
  - PRM at `/.well-known/oauth-protected-resource`, or referenced from a 401 `WWW-Authenticate`, with `resource` and `authorization_servers`.
  - AS metadata (RFC 8414 or OIDC discovery) with `issuer`, `authorization_endpoint`, `token_endpoint`, `code_challenge_methods_supported` including `S256` ("Servers without it are unsupported"), and optional `client_id_metadata_document_supported`, `registration_endpoint`, `token_endpoint_auth_methods_supported`, `authorization_response_iss_parameter_supported` and `scopes_supported`.
  - Source: [OpenAI Apps SDK: Authentication](https://developers.openai.com/apps-sdk/build/auth)
- CIMD:
  - "ChatGPT prioritizes CIMD when it is available, but the plugin builder can choose DCR."
  - The `client_id` is `https://chatgpt.com/oauth/client.json`, or `https://chatgpt.com/oauth/{callback_id}/client.json` for non-RFC 9207 servers.
  - Auth methods are `none` (public + PKCE) and `private_key_jwt`, with JWKS at `/oauth/jwks.json`.
  - DCR "once per MCP server connection".
  - Source: [OpenAI Apps SDK: Authentication](https://developers.openai.com/apps-sdk/build/auth)
- `resource`: ChatGPT appends `resource=<MCP URL>` to authorization and token requests. The AS should put it in `aud`, and servers should reject wrong-audience tokens with a `WWW-Authenticate` challenge. — [OpenAI Apps SDK: Authentication](https://developers.openai.com/apps-sdk/build/auth)
- Redirects:
  - The stable redirect is `https://chatgpt.com/connector_platform_oauth_redirect` (RFC 9207-compliant AS). Otherwise it is `https://chatgpt.com/connector/oauth/{callback_id}`.
  - When the AS advertises `iss` support, "ChatGPT and Codex reject responses that omit `iss` or return a mismatch".
  - Source: [OpenAI Apps SDK: Authentication](https://developers.openai.com/apps-sdk/build/auth)
- Client authenticity:
  - ChatGPT presents an OpenAI-managed mTLS client certificate (SAN `mtls.prod.connectors.openai.com`), or servers can allowlist egress IPs.
  - ChatGPT "does **not** support machine-to-machine OAuth grants such as client credentials, service accounts, or JWT bearer assertions, nor can it present custom API keys".
  - Source: [OpenAI Apps SDK: Authentication](https://developers.openai.com/apps-sdk/build/auth)
- Token verification on the server: signature (JWKS), `iss`, `exp`/`nbf`, `aud`/`resource` and scopes. On failure, return "`401 Unauthorized` with a `WWW-Authenticate` header". — [OpenAI Apps SDK: Authentication](https://developers.openai.com/apps-sdk/build/auth)
- Client-provided `_meta` to servers:
  - `openai/subject` ("anonymized user ID"), `openai/session`, `openai/organization`, `openai/locale`, `openai/userAgent` and `openai/userLocation`.
  - "servers must never rely on `userAgent` or `userLocation` for authorization."
  - Host-provided `openai/widgetSessionId` on results.
  - Source: [OpenAI Apps SDK: Reference](https://developers.openai.com/apps-sdk/reference)
- Templates and aliases:
  - `ui.resourceUri` is recommended, and `openai/outputTemplate` is a "ChatGPT-specific alias".
  - `openai/widgetAccessible` (default false) and `openai/visibility` (`public`/`private`) are compatibility fields; the docs say to prefer `ui.visibility`.
  - `openai/widgetDomain` is an alias for `ui.domain`, and `openai/widgetCSP` is "legacy".
  - Source: [OpenAI Apps SDK: Reference](https://developers.openai.com/apps-sdk/reference)
  - The ext-apps migration table maps `widgetAccessible: true/false` to including or excluding `"app"`, and `visibility: "public"/"private"` to including or excluding `"model"`. — [ext-apps migrate_from_openai_apps.md](https://github.com/modelcontextprotocol/ext-apps/blob/main/docs/migrate_from_openai_apps.md)
- `window.openai`:
  - `toolInput`, `toolOutput`, `toolResponseMetadata` and `widgetState`.
  - `setWidgetState`, `callTool(name,args)` and `sendFollowUpMessage({prompt})`.
  - `uploadFile`, `selectFiles` and `getFileDownloadUrl`.
  - `requestDisplayMode`, `requestModal`, `requestClose`, `notifyIntrinsicHeight`, `openExternal({href, redirectUrl})` and `setOpenInAppUrl`.
  - "Use `window.openai` only for ChatGPT-specific features, and use the MCP Apps bridge where an equivalent exists."
  - Source: [OpenAI Apps SDK: Reference](https://developers.openai.com/apps-sdk/reference)
- Widget state:
  - `modelContent` is "Text or JSON the model should see". `privateContent` is "UI-only state the model should not see".
  - "Widget state belongs to one rendered UI instance".
  - `ui/update-model-context` is "the portable MCP Apps mechanism for updating model-visible context".
  - Treat `structuredContent` as "untrusted input".
  - For checkout: "Never trust totals calculated only in the component."
  - Source: [OpenAI Apps SDK: Build your ChatGPT UI](https://developers.openai.com/apps-sdk/build/chatgpt-ui)
  - ext-apps notes `widgetState`/`setWidgetState` have no MCP Apps equivalent and suggest `localStorage` or server-side state. — [ext-apps migration guide](https://github.com/modelcontextprotocol/ext-apps/blob/main/docs/migrate_from_openai_apps.md)
- Caching: "Treat the resource URI as a cache key. When you make a breaking change to the HTML, JavaScript, or CSS, publish a new URI". — [OpenAI: Build your ChatGPT UI](https://developers.openai.com/apps-sdk/build/chatgpt-ui); [OpenAI: Build your MCP server](https://developers.openai.com/apps-sdk/build/mcp-server)
- OpenAI's own example uses `postMessage(..., "*")` and checks `event.source === window.parent` but not `event.origin`. That is per the WebFetch summary of [OpenAI: Build your ChatGPT UI](https://developers.openai.com/apps-sdk/build/chatgpt-ui).

### Inferences
- OpenAI has converged on MCP Apps for the UI layer but keeps proprietary auth signalling (`securitySchemes`, `mcp/www_authenticate`) and identity features (`openai/profile`, multi-account, mTLS). An auth diagram for ChatGPT should show the linking trigger as a tool-result path, not only HTTP 401.

### Gaps
- No OpenAI page gives a date or "last updated" stamp, so OpenAI facts can only be dated by retrieval (2026-10-17).
- OpenAI does not document where ChatGPT stores tokens or how refresh works (proactive or reactive).

---

## Q7. Anthropic/Claude documentation: remote connectors, custom connectors, callback URL, supported auth, CIMD, MCP Apps on web/desktop/mobile

### Takeaway
One auth stack serves claude.ai, Desktop, mobile, Cowork and Claude Code.
- **Supported auth:** `oauth_dcr`, `oauth_cimd`, `oauth_anthropic_creds`, `custom_connection`, `static_headers` (beta) and `none`.
- **Callback:** `https://claude.ai/api/mcp/auth_callback` for the hosted apps; port-agnostic loopback for Claude Code.
- **CIMD:** used only if AS metadata has `client_id_metadata_document_supported: true` and `none` in `token_endpoint_auth_methods_supported`.
- **Trigger:** sign-in starts only on HTTP 401.

MCP Apps ("interactive connectors") render on claude.ai web and Desktop (launched 2026-01-26), on mobile (iOS WKWebView), and in Cowork. App origins are `{sha256(url)[:32]}.claudemcpcontent.com`, and links pass through a confirmation modal.

### Cited Findings
- "The same authentication infrastructure backs claude.ai, Claude Desktop, Claude mobile, Claude Code, and Cowork." — [Claude: Authentication for connectors](https://claude.com/docs/connectors/building/authentication)
- Supported types table (`oauth_dcr` default, `oauth_cimd` default, `oauth_anthropic_creds` by contact, `custom_connection` by contact, `static_headers` beta, `none` default). "A machine-to-machine `client_credentials` grant isn't supported". — [Claude: Authentication](https://claude.com/docs/connectors/building/authentication)
- CIMD selection: "Claude selects CIMD only when your authorization server metadata advertises both `"client_id_metadata_document_supported": true` and `"none"` in `token_endpoint_auth_methods_supported` … If either is missing, Claude falls back to DCR." DCR "register[s] a new client on every fresh connection". — [Claude: Authentication](https://claude.com/docs/connectors/building/authentication)
- Discovery strictness:
  - "Claude uses only the first entry in your metadata's `authorization_servers` list".
  - "Claude ignores a `WWW-Authenticate` header on a `200` response".
  - PRM `resource` "must equal the URL as the user enters it in Claude, including any path".
  - The fallback probe order is `/.well-known/oauth-protected-resource/<path>`, then root.
  - Source: [Claude: Authentication](https://claude.com/docs/connectors/building/authentication)
- Callbacks: hosted apps use exactly `https://claude.ai/api/mcp/auth_callback`. Claude Code uses RFC 8252 loopback (`http://localhost:<port>/callback`, `http://127.0.0.1/callback`) declared in its CIMD. — [Claude: Authentication](https://claude.com/docs/connectors/building/authentication)
- PKCE S256 is on every request. Claude appends `offline_access` when the AS lists it. Static header credentials must "Never [be accepted] in the URL" and are "the organization's credential, not a person's". — [Claude: Authentication](https://claude.com/docs/connectors/building/authentication)
- Enterprise Managed Auth: SSO identity assertions replace the consent screen. On a protected-tool refusal it performs a "silent token exchange instead of the Connect card". — [Claude: Lazy authentication](https://claude.com/docs/connectors/building/lazy-authentication); [Claude: Authentication](https://claude.com/docs/connectors/building/authentication)
- Where connectors work:
  - "claude.ai on the web: remote connectors, including MCP Apps that display interactive content in the conversation"
  - Desktop: remote + local MCPB
  - Mobile: remote connectors
  - Claude Code and Cowork
  - On claude.ai, sign-in "opens in the same browser tab". In Desktop it "opens in your browser".
  - Source: [Claude: Get started with connectors](https://claude.com/docs/connectors/overview)
- Interactive connectors are "available for all users on Claude, Cowork, Claude Desktop, and Claude for iOS/Android". They render inline or fullscreen, and "run in sandboxed iframes with strict Content Security Policies". Announced 2026-01-26. — [Claude support: Use interactive connectors in Claude](https://support.claude.com/en/articles/13454812-use-interactive-connectors-in-claude) (via search summary)
- On iOS "the Claude app renders your MCP App inside a `WKWebView`". iOS WebKit omits `Referer` on cross-origin subresources, so servers should allowlist on `Origin` matching `*.claudemcpcontent.com`. — [Claude: Troubleshoot MCP Apps](https://claude.com/docs/connectors/building/mcp-apps/troubleshooting)
- `ui.domain` for Claude is "the first 32 hex characters of the SHA-256 of your server URL, followed by `.claudemcpcontent.com`". The example `https://example.com/mcp` gives `c3d80a4ed901ee05b21755a88273b4a4.claudemcpcontent.com`. — [Claude: Get started with MCP Apps](https://claude.com/docs/connectors/building/mcp-apps/getting-started)
- Large results: above about 150,000 characters with code execution active, Claude writes the result to the sandbox filesystem and "Your app receives a pointer … so it never hydrates". — [Claude: Troubleshoot MCP Apps](https://claude.com/docs/connectors/building/mcp-apps/troubleshooting)
- Instance supersession, via a server key and `BroadcastChannel`, is a documented Claude pattern (page title only reviewed). — [Claude: Supersede older widget instances](https://claude.com/docs/connectors/building/mcp-apps/instance-supersession)
- Directory submission needs "Test credentials … for a fully populated account" and "Allowed link URIs" if the app uses `ui/open-link`. — [Claude: Connector pre-submission checklist](https://claude.com/docs/connectors/building/review-criteria)

### Inferences
- Claude's design keeps OAuth entirely in host-owned surfaces: a same-tab redirect, a system browser or a popup, with the callback on `claude.ai`. The token exchange and storage sit in Anthropic's backend, consistent with "proxied through Claude's backend". The View's origin (`*.claudemcpcontent.com`) is never an OAuth redirect target for MCP auth.
- Because the `ui.domain` hash is derived from the connector URL, a View origin is bound to one server URL. Two different servers cannot share an origin and its storage on Claude.

### Gaps
- No Anthropic doc found describes whether `ui/message` or `ui/update-model-context` from a View is shown to or confirmed by the user in Claude.
- No source gives the default (non-`ui.domain`) origin scheme Claude uses, for example whether it is per conversation.

---

## Q8. The mcp-ui project (mcpui.dev): auth handling, UI-action messaging and relation to MCP Apps

### Takeaway
mcp-ui (now at `MCP-UI-Org/mcp-ui`, formerly `idosal/mcp-ui`) was the community precursor that MCP Apps standardized.
- **Today:** its `@mcp-ui/*` SDKs (client v7.1.1, 2026-05-09) implement MCP Apps. `AppRenderer` uses the double-iframe sandbox proxy.
- **Legacy protocol:** a `{type, messageId?, payload}` postMessage format with action types `tool`, `prompt`, `link`, `intent` and `notify`, plus `ui-lifecycle-*` messages. An adapter maps these to MCP Apps methods.
- **Auth:** mcp-ui defines no auth of its own. Tool actions are executed by the host on its MCP connection, the same delegation model as MCP Apps.

### Cited Findings
- "The `@mcp-ui/*` packages are an SDK for building MCP Apps". The original MCP-UI "pioneered interactive UI over MCP and influenced the MCP Apps specification", and the packages now "implement this standard". Packages: `@mcp-ui/server`, `@mcp-ui/client`, Ruby `mcp_ui_server` and Python `mcp-ui-server`. — [mcpui.dev Introduction](https://mcpui.dev/guide/introduction)
- The repo is `MCP-UI-Org/mcp-ui` (the GitHub API resolves `idosal/mcp-ui` to it), last pushed 2026-09-16. Client releases: v7.0.0 on 2026-03-12, v7.1.1 on 2026-05-09. — [GitHub MCP-UI-Org/mcp-ui releases](https://github.com/MCP-UI-Org/mcp-ui/releases)
- `AppRenderer` "implements the MCP Apps standard, handling … resource fetching, sandbox setup, JSON-RPC communication". It "requires a sandbox proxy HTML file … double-iframe architecture". — [mcp-ui docs: AppRenderer](https://github.com/MCP-UI-Org/mcp-ui/blob/main/docs/src/guide/client/app-renderer.md)
- The legacy protocol is labelled "legacy MCP-UI `postMessage` protocol". Message: `{ type: string; messageId?: string; payload }`. Types:
  - `intent`: user intent the host should act on
  - `notify`: the iframe already acted
  - `prompt`: run a prompt
  - `tool`: run a tool call
  - `link`: navigate
  - Lifecycle messages: `ui-lifecycle-iframe-ready`, `ui-lifecycle-iframe-render-data`, `ui-request-render-data`, `ui-request-data`, `ui-message-received` and `ui-message-response`.
  - The sample host code just comments "// Add origin checks for security".
  - Source: [mcp-ui docs: Embeddable UI](https://github.com/MCP-UI-Org/mcp-ui/blob/main/docs/src/guide/embeddable-ui.md)
- Adapter mappings:
  - `tool` → `tools/call`
  - `prompt` → `ui/message`
  - `link` → `ui/open-link`
  - `notify` → `notifications/message`
  - `intent` → `ui/message`
  - `ui-size-change` → `ui/notifications/size-changed`
  - `tool-input`/`tool-result`/`host-context-changed` → `ui-lifecycle-iframe-render-data`
  - `ui/resource-teardown` → `ui-lifecycle-teardown`
  - Source: [mcp-ui docs: Legacy MCP-UI Adapter](https://github.com/MCP-UI-Org/mcp-ui/blob/main/docs/src/guide/mcp-apps.md)
- Supported MCP Apps hosts listed: Claude, VS Code, Postman, Goose, MCPJam, LibreChat, mcp-use and Smithery. ChatGPT shows "Rendering ✅ / UI Actions ⚠️ (partial)". — [mcp-ui docs: Supported Hosts](https://github.com/MCP-UI-Org/mcp-ui/blob/main/docs/src/guide/supported-hosts.md)
- The spec explains the change from pre-SEP MCP-UI: the `ui/initialize` handshake instead of `iframe-ready`, capabilities negotiated, tool data via notifications. "Embedded resources … [were] deferred due to the gaps in performance optimization and the challenges in the UI review process." The legacy `externalUrl` and remote-DOM types are deferred. — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- The mcpui.dev intro example `onOpenLink` handler only opens `http(s)` URLs. The page "does not describe sandbox attributes, origin checks, authentication, or tokens". — [mcpui.dev Introduction](https://mcpui.dev/guide/introduction)

### Inferences
- In both legacy mcp-ui and MCP Apps, a `tool` action is a request to the host. The host decides whether and how to call the server with its own credentials, so neither model gives the iframe a token.
- Legacy mcp-ui's free-form `intent` and `prompt` messages became `ui/message` (role `user`). The prompt-injection surface therefore carried over into the standard.

### Gaps
- I found no mcp-ui documentation on authentication or authorization specifically.
- The legacy `externalUrl` type (embedding a remote site, which may carry its own cookies and session) is not covered in current docs, so its credential implications are undocumented.

---

## Q9. Risks specific to embedded views: postMessage spoofing, exfiltration via CSP-allowed domains, prompt injection via `ui/message`, model-context leakage, shared cached templates

### Takeaway
The spec and vendors acknowledge most of these risks, but mitigations are mostly host-discretionary (MAY or SHOULD).
1. **postMessage spoofing or leakage.** The spec sample and SDK send with `'*'`. Safety depends on receivers checking `event.source`/`event.origin`. A mainstream host SDK (Vercel AI SDK) shipped origin validation only in July 2026.
2. **Exfiltration.** Any declared `connectDomains`/`resourceDomains`, and anything inside a `frameDomains` page (whose own CSP applies), is an egress channel.
3. **Prompt injection.** `ui/message` injects text with role `"user"`, and `ui/update-model-context` silently feeds future turns. Hosts only "MAY request user consent" or "MAY display".
4. **Context leakage.** `structuredContent` is meant to stay out of the model's context, but a View can re-inject anything via `ui/update-model-context`.
5. **Shared cached templates.** Hosts MAY prefetch and cache `ui://` HTML, and OpenAI treats the URI as a cache key, so templates must hold no per-user data.

### Cited Findings
**postMessage spoofing and leakage**
- The SDK sends with `"*"` ("visible to all frames. The receiver should validate the message source") and filters by `event.source`. — [ext-apps message-transport.ts](https://github.com/modelcontextprotocol/ext-apps/blob/main/src/message-transport.ts)
- The reference sandbox validates the parent `event.origin` against the referrer-derived host origin. — [ext-apps basic-host sandbox.ts](https://github.com/modelcontextprotocol/ext-apps/blob/main/examples/basic-host/src/sandbox.ts)
- `@ai-sdk/react@4.0.31` (Vercel AI SDK, 2026-07-15) patch notes, which are an independent signal that earlier host implementations lacked these checks:
  - "Derive a concrete `postMessage` target origin and validate inbound message origins"
  - "limit `resources/read` to `ui://` resources"
  - "only `https`/`http`/`mailto` in `ui/open-link`"
  - permissions "deny-by-default via a new `sandbox.allowedPermissions` allowlist"
  - "Runtime-validate `_meta.ui`"
  - resource fingerprinting/drift detection (`fingerprintMCPAppResource`, `detectMCPAppResourceDrift`)
  - Source: [releases.sh mirror of @ai-sdk/react 4.0.31 notes](https://releases.sh/release/rel_C741RVCbIV3Y8N-MK0vIR). This is an aggregator page; the original changelog was not fetched.

**Visibility scoping**
- "Cross-server tool calls are always blocked for app-only tools", and `"app"` scope is "per-server, preventing cross-server tool calls". — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)

**Exfiltration**
- "Host MUST block connections to undeclared domains". "Host SHOULD warn users when UI requires external domain access". — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- OpenAI: "An embedded page follows its own CSP. The widget `connectDomains` and `resourceDomains` allowlists do not restrict network requests made inside that page." — [OpenAI Security & Privacy](https://developers.openai.com/apps-sdk/guides/security-privacy)
- OpenAI says "The plugin review process checks the declared policy against the UI behavior" and "Keep each allowlist as narrow as possible". — [OpenAI: Build your ChatGPT UI](https://developers.openai.com/apps-sdk/build/chatgpt-ui)

**Prompt injection via UI messages**
- `ui/message` uses `role: "user"`. The host "SHOULD add the message to the conversation context, preserving the specified role" and "MAY request user consent". — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- `ui/update-model-context`: "This context will be used in future turns". The host "MAY defer sending … until the next user message" and "MAY display context updates to the user". — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- [DRAFT] `sampling/createMessage` from Views: the host "SHOULD apply rate limiting, cost controls, and user approval (human-in-the-loop)".
- [DRAFT] App-provided tools risks: "Apps may describe tools in ways that don't fully capture side effects"; "Namespace conflicts: Apps could register tools with names conflicting with server tools". Mitigations include namespacing, limits (50 tools, 30 s timeouts, 10 MB results) and "Hosts MUST NOT persist app tool registrations across sessions".
- Source for both draft items: [Draft spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/draft/apps.mdx)
- OpenAI: "Assume prompt injection and malicious inputs will reach your server"; "Validate inputs on the server, even when the model supplied them." — [OpenAI Security & Privacy](https://developers.openai.com/apps-sdk/guides/security-privacy)

**Model-context leakage**
- `structuredContent` is "not added to model context" and `_meta` is "not intended for model context". — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- ChatGPT exposes the full envelope "including hidden `_meta`" to the widget via `toolResponseMetadata`. — [OpenAI Reference](https://developers.openai.com/apps-sdk/reference)
- ChatGPT widget state separates `modelContent` (model-visible) from `privateContent`. — [OpenAI: Build your ChatGPT UI](https://developers.openai.com/apps-sdk/build/chatgpt-ui)
- ext-apps patterns recommend `updateModelContext` "to keep the model informed about what the user is viewing". — [ext-apps docs/patterns.md](https://github.com/modelcontextprotocol/ext-apps/blob/main/docs/patterns.md)

**Cached templates**
- "Host MAY prefetch and cache UI resource content". The benefits listed include "Caching: Separate template (static) from data (dynamic)" and "Host can review UI templates during connection setup". — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- OpenAI: "Treat the resource URI as a cache key". — [OpenAI: Build your ChatGPT UI](https://developers.openai.com/apps-sdk/build/chatgpt-ui)
- ext-apps patterns: use `localStorage` keyed by a server-provided `viewUUID` for recoverable view state. For "state that represents user effort … consider persisting it server-side using app-only tools". — [ext-apps docs/patterns.md](https://github.com/modelcontextprotocol/ext-apps/blob/main/docs/patterns.md)

**Other**
- "Resource consumption: Malicious View can consume CPU/memory. Hosts should implement resource limits." — [Stable spec](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- Users "should still vet MCP servers before connecting them". — [MCP blog 2026-01-26](https://blog.modelcontextprotocol.io/posts/2026-01-26-mcp-apps/)

### Inferences
- **Template caching.** `ui://` HTML is fetched once per connection and may be cached or prefetched by the host, possibly before any user-specific auth (lazy auth lets `resources/read` run unauthenticated). Templates must therefore be identical for all users and contain no secrets. Per-user data should arrive only via authenticated tool results (`structuredContent`) or app-only tool calls.
- **Origin-scoped storage.**
  - Views on a stable `ui.domain` origin share `localStorage` across all conversations and instances of that server for that user's browser. That is useful for continuity but a leakage path if the server serves multiple tenants or accounts.
  - ChatGPT multi-account adds a twist: one widget origin may serve two connected accounts.
- **Injection chain.**
  1. A malicious or compromised server, or a server reflecting attacker-controlled data such as an email body rendered in a View, causes the View to send `ui/message` text that reads as user intent.
  2. The model may then invoke **other** connectors' write tools.
  
  This cross-connector pivot is not blocked by the per-server `"app"` visibility rule, because the model, not the app, makes the call. Host confirmation of `ui/message` and of subsequent writes is the main defence.
- **Exfiltration.** With `connectDomains` declared, a View can send anything it can see (tool results and host context such as locale, timezone and theme) to that domain. Host-held tokens are not exposed this way.

### Gaps
- I found no published independent security research (CVE, academic paper or red-team report) specifically on MCP Apps or ChatGPT widget sandbox escapes, postMessage spoofing in production hosts, or `ui/message` prompt injection. The search returned vendor and tutorial blogs such as sunpeak.ai, which were not fetched or verified.
- I found no documentation of whether Claude or ChatGPT show users the text of `ui/message` or `ui/update-model-context` before it reaches the model.
- No spec text explicitly says "do not put per-user data in `ui://` resources". The guidance is inferred from caching statements.
