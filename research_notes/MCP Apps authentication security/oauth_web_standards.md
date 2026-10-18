# OAuth, Identity, and Web-Platform Security Standards for MCP Server Authentication and Embedded MCP App Views (state as of 17 October 2026)

Scope note: these notes cover the underlying IETF, OpenID Foundation, WHATWG/W3C and OWASP standards. Where a standard is explicitly referenced by the current MCP authorization specification (revision 2026-07-28, served at modelcontextprotocol.io/specification/latest), this is flagged with "[MCP ref]". MCP-specific text and vendor products are covered by other researchers.

---

## 1. OAuth 2.1 (draft-ietf-oauth-v2-1): current status, what it removes, what it mandates

### Takeaway
OAuth 2.1 is still an Internet-Draft. The latest revision is -16, dated 3 September 2026, and the WG milestone is to send it to the IESG by December 2026. It consolidates RFC 6749 and RFC 6750 with the security BCP: PKCE is mandatory (S256 only, `plain` now removed), redirect URIs must match exactly, the implicit and ROPC grants are gone, bearer tokens may not go in query strings, and public-client refresh tokens must be sender-constrained or rotated. MCP still cites -13, so the -14 to -16 changes (`plain` removed, `iss` made required, consent-phishing text) are not yet reflected in MCP's normative pointer.

### Cited Findings
**Status**
- The latest revision is draft-ietf-oauth-v2-1-16, dated 3 September 2026 (datatracker shows last updated 2026-09-02). It is an active oauth WG Standards Track I-D with IESG state "I-D Exists". It expires 7 March 2027, and its WG milestone is "Submit the document to the IESG by Dec 2026". It obsoletes RFC 6749 and RFC 6750. — [IETF Datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
- Changelog for -16: removed the PKCE `plain` method, mentioned PAR in the authorization-endpoint section, added a security consideration on OAuth consent phishing, and "Made the `iss` response parameter required from the AS". It also added a "Value Sizes" section and clarified authorization-endpoint error responses. — [draft-ietf-oauth-v2-1-16](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.html)
- Changelog for -15: added JWT client-auth context and recommended RFC7523bis, synced the AS open-redirect text from RFC 9700, and applied RFC 6750 errata 3500 and 6613. Changelog for -14: clarified that native-app guidance applies primarily to mobile platforms, and replaced "sanitize" language with "treat input as untrusted". — [draft-ietf-oauth-v2-1-16](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.html)
- [MCP ref] The MCP authorization spec says "Authorization servers MUST implement OAuth 2.1" and lists "OAuth 2.1 IETF DRAFT (draft-ietf-oauth-v2-1-13)" under Standards Compliance. It is the -13 pin, not -16. — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)

**Section 10 "Differences from OAuth 2.0" (full list in -16)** — [draft-ietf-oauth-v2-1-16 §10](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.html)
1. The authorization code grant incorporates PKCE, so the PKCE parameters are required by default.
2. Redirect URIs must be compared using exact string matching.
3. The Implicit grant (`response_type=token`) is omitted.
4. The Resource Owner Password Credentials grant is omitted.
5. Bearer tokens may not be sent in URI query strings.
6. Refresh tokens for public clients must be sender-constrained or one-time use.
7. The token endpoint request no longer includes `redirect_uri`.
8. Authorization servers must support client credentials in the request body.
9. The PKCE `plain` method is removed.

**Normative text (quotes)** — [draft-ietf-oauth-v2-1-16](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.html)
- PKCE (§4.1.1):
  - "Authorization servers MUST support the `code_challenge` and `code_verifier` parameters."
  - "Clients MUST use `code_challenge` and `code_verifier`." Authorization servers "MUST enforce their use except under the conditions described in Section 7.5.1".
  - `code_challenge_method` is "REQUIRED, the value `S256` or a value defined by a future extension". "Currently, `S256` is the only such method". `plain` is "removed and explicitly prohibited in this specification."
- PKCE exception (§7.5.1.1): enforcement may be skipped only if both "The client is a confidential client" and "there is reasonable assurance by the authorization server that the client implements the OpenID Connect" nonce mechanism. Even then, "using and enforcing `code_challenge` and `code_verifier` is still RECOMMENDED."
- Redirect URIs (§2.3.1):
  - AS "MUST reject authorization requests that specify a redirect URI that doesn't exactly match one that was registered", "except for the port URI component" (loopback).
  - AS "MUST require clients to register their complete redirect URI (including the path component)".
- Removed grants (§1.8): grants "such as the Implicit or Resource Owner Credentials grant types, are not specified in OAuth 2.1". §4 defines only authorization_code, client_credentials and refresh_token.
- Refresh tokens:
  - §4.3: "When client authentication is not possible, the authorization server SHOULD issue sender-constrained refresh tokens" (or use rotation).
  - §4.3.1: "Authorization servers MUST utilize one of these methods to detect refresh token replay" for public clients. The two methods are sender-constraining ("cryptographically binds the refresh token to a certain client instance") and rotation ("issues a new refresh token with every access token refresh response").
  - §4.3.2: "the client MUST discard the old refresh token and replace it with the new refresh token."
  - §3.2.3: refresh tokens "MUST be bound to the scope and resource servers as consented by the resource owner."
- Bearer token transport (§5.1):
  - "clients MUST NOT send the access token in a URI query parameter" and "resource servers MUST ignore access tokens in a URI query parameter".
  - Clients "MUST NOT use more than one method to transmit the token in each request".
  - §5.1.1: "Clients SHOULD make authenticated requests with a bearer token using the `Authorization` request header field."
- Error codes (§5.3.2):
  - `invalid_request` → "SHOULD respond with the HTTP 400".
  - `invalid_token` ("expired, revoked, malformed, or invalid for other reasons") → 401.
  - `insufficient_scope` ("requires higher privileges (scopes) than provided") → 403.
- Audience restriction:
  - §7.1.3.6: "Authorization servers SHOULD issue bearer tokens that contain an audience restriction".
  - §7.1.4: tokens "SHOULD be restricted to certain resource servers (audience restriction), preferably to a single resource server."
- Sender-constraining (§1.4.3): AS and RS "SHOULD use mechanisms for sender-constraining access tokens" (DPoP, mTLS).
- Clickjacking (§7.11): "Authorization servers MUST prevent clickjacking attacks" and "SHOULD also use Content Security Policy (CSP) level 2" or greater.
- Open redirectors (§7.13):
  - "Clients MUST NOT expose open redirectors."
  - The AS "MUST always authenticate the user first" and "SHOULD only automatically redirect the user agent if it trusts the redirect URI."
- Native apps (§8.2): "Native apps MUST use an external user agent to perform OAuth authorization requests." §8.5.1 says embedded user agents are unsafe for third parties, can expose full user credentials, and break least privilege even for same-party apps.

### Inferences
- The -16 change making `iss` required from the AS goes beyond MCP's current text, which leaves AS inclusion of `iss` at SHOULD (see §4 of these notes). MCP's pin to -13 also predates the explicit `plain` prohibition. Both are likely alignment items for a future MCP revision.
- For an MCP report, the OAuth 2.1 "baseline" for any MCP client or AS is: authorization code + PKCE S256 + exact redirect match + `resource` + `state`/`iss` checks + header-only bearer + rotated or sender-constrained refresh tokens. Implicit and password grants are never acceptable, including inside an embedded view.

### Gaps
- No final RFC number exists yet. Whether OAuth 2.1 reaches the IESG by the December 2026 milestone is unknown.
- I did not read the exact wording of the new -16 "consent phishing" security consideration, only its changelog entry.

### Status roll-up (all standards covered in these notes, as of 17 Oct 2026)
| Standard | Type / status | Date | Source |
|---|---|---|---|
| OAuth 2.1 (draft-ietf-oauth-v2-1-16) | WG I-D, Standards Track intent; IESG "I-D Exists" | 3 Sep 2026 | [Datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) |
| RFC 9700 OAuth 2.0 Security BCP | BCP 240; updates 6749/6750/6819 | Jan 2025 | [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) |
| RFC 7636 PKCE | Proposed Standard | Sep 2015 | [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html) |
| RFC 8252 OAuth for Native Apps | BCP 212 | Oct 2017 | [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html) |
| RFC 8707 Resource Indicators | Proposed Standard | Feb 2020 | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) |
| RFC 9728 Protected Resource Metadata | Proposed Standard | Apr 2025 | [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) |
| RFC 8414 AS Metadata | Proposed Standard | Jun 2018 | [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html) |
| RFC 9207 AS Issuer Identification (`iss`) | Proposed Standard | Mar 2022 | [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html) |
| RFC 7591 Dynamic Client Registration | Proposed Standard | Jul 2015 | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html) |
| CIMD (draft-ietf-oauth-client-id-metadata-document-02) | WG I-D, Standards Track intent | 6 Jul 2026 | [Datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) |
| RFC 9449 DPoP | Proposed Standard | Sep 2023 | [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) |
| RFC 8705 mTLS client auth + cert-bound tokens | Proposed Standard | Feb 2020 | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html) |
| RFC 8693 Token Exchange | Proposed Standard | Jan 2020 | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) |
| RFC 9396 Rich Authorization Requests | Proposed Standard | May 2023 | [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) |
| RFC 9470 Step-up Authentication Challenge | Proposed Standard | Sep 2023 | [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470.html) |
| RFC 6750 Bearer Token Usage | Proposed Standard (to be obsoleted by OAuth 2.1) | Oct 2012 | [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) |
| RFC 7009 Token Revocation | Proposed Standard | Aug 2013 | [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html) |
| RFC 7662 Token Introspection | Proposed Standard | Oct 2015 | [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html) |
| RFC 9068 JWT Access Token Profile | Proposed Standard | Oct 2021 | [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) |
| ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant-04) | WG I-D (replaces draft-parecki-...) | 21 May 2026 | [Datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) |
| draft-ietf-oauth-rfc7523bis-11 (JWT client-auth audience fix) | In RFC Editor queue ("In Final Review"); not yet an RFC | 26 Mar 2026 (dt 28 Apr 2026) | [Datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/) |
| draft-ietf-wimse-aims-00 (AI Identity Management System) | WIMSE WG I-D, Informational; replaces draft-klrc-aiagent-auth | 15 Sep 2026 | [Datatracker](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/) |
| draft-oauth-ai-agents-on-behalf-of-user-02 | Individual I-D, expired | 25 Aug 2025 | [Datatracker](https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/) |
| OIDF "Identity Management for Agentic AI" whitepaper | OpenID Foundation AIIM CG whitepaper (not a spec) | 7 Oct 2025 | [OpenID Foundation](https://openid.net/new-whitepaper-tackles-ai-agent-identity-challenges/) |

---

## 2. RFC 9700 (OAuth 2.0 Security BCP, January 2025): threats and the countermeasures it mandates

### Takeaway
RFC 9700 (BCP 240) is the normative threat catalogue behind OAuth 2.1. Its core rules:
- MUST: exact redirect-URI matching, CSRF prevention, PKCE support and downgrade protection, mix-up defence when there are multiple ASes, no open redirectors, AS clickjacking prevention, exact-origin postMessage handling, no tokens in query strings, and ROPC "MUST NOT be used".
- SHOULD: audience-restricted and sender-constrained access tokens.
- Public-client refresh tokens MUST be either rotated or sender-constrained.

Almost every row of an "MCP auth risk → standard" table can cite a section of RFC 9700.

### Cited Findings
**Metadata**
- RFC 9700 "Best Current Practice for OAuth 2.0 Security", BCP 240, January 2025, by T. Lodderstedt, J. Bradley, A. Labunets and D. Fett. It updates RFC 6749, 6750 and 6819. — [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)

**Threat-by-threat normative requirements** (all from [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html))
- **Insufficient redirect URI validation (§2.1, §4.1):** "authorization servers MUST utilize exact string matching except for port numbers". For native-app `localhost`/loopback, the AS "MUST allow variable port numbers" (§4.1.3).
- **CSRF (§2.1, §4.7):**
  - "Clients MUST prevent Cross-Site Request Forgery (CSRF)."
  - CSRF can be prevented by PKCE, by an OIDC nonce, or by "one-time use CSRF tokens carried in the `state` parameter that are securely bound to the user agent".
  - §4.7.1: "Clients MUST ensure that the authorization server supports PKCE before using PKCE for CSRF protection."
- **PKCE (§2.1.1):**
  - "Authorization servers MUST support PKCE".
  - "clients SHOULD use PKCE code challenge methods that do not expose the PKCE verifier"; "S256 is the only such method".
  - The AS "MUST enforce the correct usage of `code_verifier` at the token endpoint".
- **PKCE downgrade (§4.8.2):** the AS "MUST ensure that if there was no `code_challenge` in the authorization request, a request to the token endpoint containing a `code_verifier` is rejected." The attack is to strip the challenge from the front-channel request, then inject a stolen code.
- **Authorization code injection (§2.1.1, §4.5):** "Clients MUST prevent authorization code injection attacks"; public clients "MUST use PKCE" for this.
- **Mix-up attacks (§2.1, §4.4):**
  - A mix-up defence is "REQUIRED" when a client interacts with more than one AS.
  - Using "the `iss` parameter as a countermeasure according to" RFC 9207 is recommended.
  - §4.4.2: "clients MUST prevent mix-up attacks".
  - §4.4.2.1: "If there is a mismatch, the client MUST abort the interaction."
  - The fallback defence of a distinct redirect URI per AS (§4.4.2.2) "SHOULD therefore only be used if other options are not available."
- **Implicit grant and ROPC:**
  - §2.1.2: "clients SHOULD NOT use the implicit grant (response type `token`)". This is SHOULD NOT in the BCP; OAuth 2.1 removes the grant outright.
  - §2.4: ROPC "MUST NOT be used."
- **Token privilege and audience restriction (§2.3):** "access tokens SHOULD be audience-restricted to a specific resource server". If a token's privileges don't cover the request, "the resource server MUST refuse to serve the respective request".
- **Token replay and theft (§2.2.1, §4.10):**
  - "Authorization and resource servers SHOULD use mechanisms for sender-constraining access tokens" (DPoP, mTLS).
  - §4.10: "Authorization servers therefore SHOULD ensure that access tokens are sender-constrained and audience-restricted".
- **Refresh token protection (§2.2.2, §4.14):**
  - "Refresh tokens for public clients MUST be sender-constrained or use refresh token rotation".
  - §4.14.2: the AS "MUST determine, based on a risk assessment, whether to issue refresh tokens", and refresh tokens "MUST be bound to the scope and resource servers as consented by the resource owner".
  - "Authorization servers MUST utilize one of these methods to detect refresh token replay".
  - With rotation, if an invalidated refresh token is presented, the AS cannot tell attacker from legitimate client, so "it will revoke the active refresh token", forcing a new grant.
  - The AS "MAY revoke refresh tokens automatically in case of a security event" (e.g., password change, logout).
  - "Refresh tokens SHOULD expire if the client has been inactive for some time".
- **Open redirectors (§2.1, §4.11):**
  - "Clients and authorization servers MUST NOT expose URLs that forward the user's browser to arbitrary URIs"; "Clients MUST NOT expose open redirectors."
  - The AS "MUST take precautions" and "SHOULD only automatically redirect the user agent if it trusts the redirection URI". If it does not trust the URI, it MAY inform the user and let them decide.
- **307 redirect (§4.12):** an AS redirecting a request that may contain credentials "MUST NOT use the HTTP 307 status code"; it "SHOULD use HTTP status code 303 (See Other)".
- **TLS-terminating reverse proxies (§4.13):** "A reverse proxy MUST therefore sanitize any inbound requests". The proxy–app-server link "MUST be protected against eavesdropping" (and injection and replay).
- **Client impersonating resource owner (§4.15):** the AS "SHOULD NOT allow clients to influence their `client_id`" or `sub` in a way that could be confused with a user. Otherwise the AS "MUST provide other means for the resource server to distinguish" the two.
- **Clickjacking (§4.16):**
  - "Authorization servers MUST prevent clickjacking attacks." It names RFC 6819 countermeasures including "the use of the X-Frame-Options HTTP response header field" and frame-busting JS.
  - "authorization servers SHOULD also use Content Security Policy (CSP) level 2" or greater. Because some user agents lack CSP support, "this technique SHOULD be combined with others".
  - "The client MAY permit being framed by some other origin than the one used in its redirection endpoint", and the AS "SHOULD allow administrators to configure allowed origins for particular clients".
  - Example headers: `Content-Security-Policy: frame-ancestors https://ext.example.org:8000`, `Content-Security-Policy: script-src 'self'`, `X-Frame-Options: ALLOW-FROM https://ext.example.org:8000`.
- **In-browser communication flows / postMessage (§4.17.2):**
  - The AS "MUST send postMessages to trusted client receiver origins" using "exact string matching". "Wildcard origins like "*" in postMessage MUST NOT be used".
  - "Clients MUST prevent injection of in-browser messages on the client receiver endpoint" and "MUST utilize exact string matching to compare the initiator origin" with the AS origin.
  - "all measures protecting the authorization response listed in Section 2.1 MUST be applied equally."
- **Credential leakage via Referer (§4.2.4):** the redirect-target page and authorization endpoint "SHOULD NOT include third-party resources or links to external sites". The section recommends suppressing Referer with a Referrer Policy, using the code flow rather than token-in-front-channel, and invalidating `state` after first use.
- **Browser history (§4.3):** "Clients MUST NOT pass access tokens in a URI query parameter" (§4.3.2). Codes are one-time and PKCE-bound, which mitigates leakage of codes from history.
- **Client authentication (§2.5):** "Authorization servers SHOULD enforce client authentication if it is feasible"; "It is RECOMMENDED to use asymmetric cryptography for client authentication" (mTLS or `private_key_jwt`).
- **TLS (§2.6):**
  - "Authorization responses MUST NOT be transmitted over unencrypted network connections."
  - `http` redirect URIs are prohibited except for native-app loopback.
  - "It is RECOMMENDED to use end-to-end TLS according to" BCP 195.
- **Resource server discovery for audience restriction (§4.10.3):** describes a non-standard AS metadata parameter `resource_servers` for telling clients which RSs a token is valid for. RFC 8707 and RFC 9728 later address this.

**Related audience-injection fix (post-RFC 9700)**
- draft-ietf-oauth-rfc7523bis-11 updates RFC 7521, 7522, 7523 and 9126. For client-authentication JWTs (`private_key_jwt`), the AS issuer identifier must be the sole audience value, and the AS must reject JWTs that don't carry its own issuer as the only `aud`. It also introduces the explicit `typ` `client-authentication+jwt` and deprecates SAML bearer assertions for client auth. University of Stuttgart researchers found the flaw. State: "Submitted to IESG", IESG "RFC Ed Queue", RFC Editor "In Final Review", no RFC number yet. — [Datatracker draft-ietf-oauth-rfc7523bis](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/)

### Inferences
Threat → countermeasure → standard mapping (draft for the report's table; RFC 9700 section in brackets):

| Threat | Primary countermeasure | Standard(s) |
|---|---|---|
| Code interception / injection | PKCE S256, one-time codes | RFC 7636; RFC 9700 §4.5; OAuth 2.1 §4.1.1 |
| PKCE downgrade | AS rejects `code_verifier` when no challenge was sent | RFC 9700 §4.8.2 |
| CSRF on redirect endpoint | `state` bound to user agent, or PKCE | RFC 9700 §4.7 |
| Mix-up (malicious / honest AS confusion) | `iss` response param + per-request expected issuer | RFC 9207; RFC 9700 §4.4 |
| Redirect URI manipulation | Exact string matching (loopback port exception) | RFC 9700 §4.1; OAuth 2.1 §2.3.1 |
| Open redirector → phishing / code theft | No open redirectors; AS redirects only to trusted URIs | RFC 9700 §4.11 |
| Token replay at another RS (confused deputy / counterfeit RS) | Audience restriction via `resource` + RS `aud` validation | RFC 8707; RFC 9068; RFC 9728 §7.4; RFC 9700 §4.9–4.10 |
| Stolen access / refresh token replay | Sender-constraining | RFC 9449 (DPoP); RFC 8705 (mTLS) |
| Refresh token theft (public client) | Rotation with reuse detection, or sender-constraining | RFC 9700 §4.14; OAuth 2.1 §4.3 |
| Clickjacking of consent / login UI | CSP `frame-ancestors`, X-Frame-Options | RFC 9700 §4.16; CSP; OWASP |
| postMessage injection / leakage | Exact origin match, no `*` | RFC 9700 §4.17; WHATWG HTML |
| Credential entry in embedded webview | External user agent only | RFC 8252 §8.12; OAuth 2.1 §8.2 |
| Token leakage via URL / history / Referer | Header-only bearer, Referrer-Policy, code flow | RFC 9700 §4.2–4.3; RFC 6750 §5.3 |
| Client impersonation in registration | Self-asserted metadata warnings, hostname display, allowlists | RFC 7591 §5; CIMD §8 |
| Audience injection on `private_key_jwt` | Issuer as sole `aud` | draft-ietf-oauth-rfc7523bis |

- RFC 9700 §4.9.1 (counterfeit resource server phishing tokens) maps directly onto "malicious MCP server" scenarios. The §4.10 combination of audience restriction plus sender-constraining is the BCP's answer. This mapping is my inference from the BCP structure; RFC 9700 does not mention MCP.

### Gaps
- My fetch did not return the full verbatim text of §4.9 (Access Token Leakage at the RS) or §4.6 (Access Token Injection). The section titles and their countermeasures (audience restriction, sender-constraining) are referenced in §4.10, but no direct quotes were captured.

---

## 3. PKCE (RFC 7636): S256 mechanism and why `plain` is disallowed

### Takeaway
PKCE binds the authorization code to a secret (`code_verifier`) that only the initiating client instance knows, which defeats code interception and injection. S256 sends only a SHA-256 hash in the front channel, so an attacker who sees the authorization request still can't redeem the code. `plain` puts the verifier itself in the front channel, so it gives no protection when the request is observable. `plain` was already "MUST use S256 if capable" in RFC 7636, and OAuth 2.1 -16 removes it entirely.

### Cited Findings
- RFC 7636 (September 2015, Proposed Standard). It was motivated by a malicious app on the same device registering the same custom URI scheme and intercepting the authorization code. — [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html)
- Mechanism — [RFC 7636 §4](https://www.rfc-editor.org/rfc/rfc7636.html):
  - The client creates a high-entropy `code_verifier` of 43–128 characters from the unreserved set `[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"`. Recommended: a 32-octet random value, base64url-encoded.
  - `code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))` with `code_challenge_method=S256`, sent on the authorization request.
  - The AS stores the challenge with the code. At the token endpoint the client sends `code_verifier`; the AS recomputes and compares, and on mismatch returns `invalid_grant`.
- S256 is mandatory: "If the client is capable of using "S256", it MUST use "S256", as "S256" is Mandatory To Implement (MTI) on the server." `plain` was allowed only if the client "cannot support "S256" for some technical reason". "Clients MUST NOT downgrade to "plain" after trying the "S256" method." — [RFC 7636 §4.2, §7.2](https://www.rfc-editor.org/rfc/rfc7636.html)
- Why `plain` is weak (§7.2): with `plain`, the challenge equals the verifier. Anyone who observes the authorization request (logs, browser history, a malicious app, an OS-level intent sniffer) learns the verifier. S256 protects even if the challenge is observed, because the hash can't be inverted. — [RFC 7636 §7.2](https://www.rfc-editor.org/rfc/rfc7636.html)
- OAuth 2.1 -16: `plain` is "removed and explicitly prohibited". RFC 9700 says clients "SHOULD use PKCE code challenge methods that do not expose the PKCE verifier", and S256 is the only such method. — [draft-ietf-oauth-v2-1-16](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.html); [RFC 9700 §2.1.1](https://www.rfc-editor.org/rfc/rfc9700.html)
- Discovery: RFC 8414 defines `code_challenge_methods_supported` in AS metadata; if it is omitted, the AS does not support PKCE. — [RFC 8414 §2](https://www.rfc-editor.org/rfc/rfc8414.html)
- [MCP ref] The MCP flow diagram has the client "Generate PKCE parameters" and send `code_challenge` and `code_verifier`. — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)

### Inferences
- In an MCP App or embedded-view context, the PKCE verifier must stay in the MCP client (host) process, never in the sandboxed view. If the view saw the verifier and could also observe the redirect, it could redeem the code. This follows from PKCE's threat model.

### Gaps
- None material.

---

## 4. Discovery, audience binding, and client registration: RFC 8707, RFC 9728, RFC 8414, RFC 9207, RFC 7591, CIMD

### Takeaway
Discovery works as a chain:
1. The resource (MCP server) returns 401 with `WWW-Authenticate: Bearer resource_metadata="…"` (RFC 9728).
2. The client fetches Protected Resource Metadata and must check that `resource` equals the URL it used.
3. It picks an AS from `authorization_servers` and fetches AS metadata (RFC 8414), checking that `issuer` equals the identifier used.
4. It registers or identifies itself via CIMD (URL-as-client_id, SSRF-hardened) or the now-deprecated-in-MCP DCR (RFC 7591, metadata is self-asserted).
5. It requests a token bound to the server via `resource` (RFC 8707), and checks `iss` on the response (RFC 9207).

Each identity-equality check exists to defeat impersonation of a resource, AS or client.

### Cited Findings
**RFC 8707 Resource Indicators (Feb 2020)** — [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)
- The `resource` parameter is used on authorization and token requests. Its value "MUST be an absolute URI", "MUST NOT include a fragment component" and "SHOULD NOT include a query component". Multiple `resource` parameters are permitted.
- The error `invalid_target` means "The requested resource is invalid, missing, unknown, or malformed."
- Purpose: lets the AS audience-restrict the token so that a token presented to one resource cannot be replayed by that resource at another (security considerations).
- [MCP ref] MCP clients "MUST implement Resource Indicators", and `resource` "MUST be included in both authorization requests and token requests" and "MUST use the canonical URI of the MCP server". MCP servers "MUST validate that access tokens were issued specifically for them as the intended audience"; "MCP servers MUST NOT accept or transit any other tokens". — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)

**RFC 9728 OAuth 2.0 Protected Resource Metadata (Apr 2025)** — [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html)
- Authors: M.B. Jones, P. Hunt, A. Parecki. Standards Track.
- Metadata fields:
  - `resource` (REQUIRED), `authorization_servers`, `jwks_uri`.
  - `scopes_supported` (RECOMMENDED), `bearer_methods_supported` (`header`/`body`/`query`), `resource_signing_alg_values_supported` ("`none` MUST NOT be used").
  - `resource_name` (RECOMMENDED), `resource_documentation`, `resource_policy_uri`, `resource_tos_uri`.
  - `tls_client_certificate_bound_access_tokens`, `authorization_details_types_supported` (RAR), `dpop_signing_alg_values_supported`, `dpop_bound_access_tokens_required`.
  - `signed_metadata` (a JWT that "MUST be digitally signed or MACed").
- Well-known URI: `/.well-known/oauth-protected-resource` is inserted between the host and the path. Example: `https://resource.example.com/resource1` → `GET /.well-known/oauth-protected-resource/resource1`.
- WWW-Authenticate (§5.1): `HTTP/1.1 401 Unauthorized` + `WWW-Authenticate: Bearer resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"`. It works with other schemes (e.g., DPoP), and a resource can send a new challenge to signal changed metadata (§5.2).
- Validation (§3.3): "The `resource` value returned MUST be identical to the protected resource's resource identifier value" used to build the URL, or the metadata must not be used. When the metadata URL came from `resource_metadata`, `resource` must match the URL the client used to call the resource.
- Security Considerations (§7):
  - TLS (BCP 195).
  - Clients should request minimal scopes despite `scopes_supported`.
  - **Impersonation (7.3):** clients must check TLS certificates and that `resource` matches.
  - **Audience-restricted tokens (7.4):** a malicious RS could replay a client's token elsewhere, so RFC 8707 is recommended.
  - **AS selection (7.6):** picking a trustworthy AS is out of scope, and a wrong choice enables adversary-in-the-middle.
  - **SSRF (7.7):** block internal address ranges when fetching from untrusted issuers.
  - **Phishing (7.8):** a user-supplied resource URL may be malicious; show the AS domain and use reputation checks.
  - Signed vs unsigned metadata (7.9); HTTP caching may serve stale metadata (7.10).
- [MCP ref] "MCP servers MUST implement OAuth 2.0 Protected Resource Metadata (RFC9728). MCP clients MUST use OAuth 2.0 Protected Resource Metadata for authorization server discovery." — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)

**RFC 8414 AS Metadata (Jun 2018)** — [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html)
- `/.well-known/oauth-authorization-server` is inserted between host and path. The issuer must be `https` with no query or fragment.
- §3.3: "The "issuer" value returned MUST be identical to the authorization server's issuer identifier value into which the well-known URI string was inserted to create the URL used to retrieve the metadata. If these values are not identical, the data contained in the response MUST NOT be used." This defends against AS impersonation (§6.2).
- Key fields: `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `code_challenge_methods_supported`, `revocation_endpoint`, `introspection_endpoint`, plus extension fields such as `authorization_response_iss_parameter_supported` (RFC 9207).
- [MCP ref] MCP ASs "MUST provide at least one of" RFC 8414 or OpenID Connect Discovery 1.0, and clients "MUST support both". — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)

**RFC 9207 Authorization Server Issuer Identification (Mar 2022)** — [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html)
- The AS adds `iss` to authorization responses, including error responses, and advertises `authorization_response_iss_parameter_supported: true`.
- The client decodes `iss` and compares it with the issuer it sent the request to, using simple string comparison (RFC 3986 §6.2.1). On mismatch, "clients MUST reject the authorization response and MUST NOT proceed with the authorization grant." This is the primary mix-up defence.
- [MCP ref] The MCP client "MUST record the `issuer` value from the selected authorization server's validated metadata" alongside the PKCE verifier. MCP ASs "SHOULD include the `iss` parameter", and the spec says a future revision is expected to upgrade this to MUST. On mismatch the client "MUST NOT act on or display `error`, `error_description`, or `error_uri`". — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)

**RFC 7591 Dynamic Client Registration (Jul 2015)** — [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html)
- Registration may be open or protected by an initial access token. The endpoint "SHOULD allow registration requests with no authorization", and open requests "MAY be rate-limited".
- §5: "the authorization server MUST treat all client metadata as self-asserted" (unless it comes from a trusted software statement). "a rogue client might use the name and logo of a legitimate client that it is trying to impersonate"; a `policy_uri` might point to "a drive-by download".
- The AS "SHOULD check" that `logo_uri`, `tos_uri`, `client_uri` and `policy_uri` share host and scheme with the redirect URIs, and may show warnings or interstitials.
- Redirect URIs must be registered for redirect-based grants.
- Software statements must be JWS-signed with `iss`, but their trust criteria are out of scope.
- Duplicate registrations (same `software_id`/`software_version`) "SHOULD" be treated as suspect.
- TLS is required. Client secrets "MUST be unique for each" client_id, and the same secret "SHOULD NOT" be issued to multiple instances.
- [MCP ref] In MCP 2026-07-28, DCR is "MAY" and "is deprecated and retained for backwards compatibility with authorization servers that do not support Client ID Metadata Documents". — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)

**CIMD: OAuth Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document-02, 6 Jul 2026)** — [CIMD -02](https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html); [Datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)
- Status: oauth WG document, Standards Track intent, IESG "I-D Exists", expires 7 Jan 2027. Authors: Aaron Parecki (Okta) and Emelia Smith.
- Changelog:
  - -01 added guidance on metadata changes, mixed registered/unregistered ASs, the HTTP 200 requirement, and more SSRF text.
  - -02 clarified the SSRF loopback exception and URL comparison, moved "CIMD services" to a non-normative appendix, and added Privacy Considerations.
- **Client ID URL rules (§3):**
  - `https` scheme; no userinfo; must contain a path (bare `/` not recommended); no `.`/`..` segments; no fragment; query SHOULD NOT be used.
  - Compared by simple string comparison, so `https://example.com:443/client` ≠ `https://example.com/client`.
- **Document (§4):**
  - JSON using IANA client metadata. The `client_id` inside must equal the URL fetched, and it must be served with HTTP 200.
  - Shared-secret auth methods (`client_secret_basic`/`_post`/`_jwt`) and `client_secret` are prohibited. Only public keys (`jwks`/`jwks_uri`) are allowed.
  - Redirect URIs are registered at fetch time and matched exactly.
- **Fetching (§5):** the AS "MUST NOT automatically follow HTTP redirects", must treat non-200 as an error, SHOULD abort the authorization on fetch failure, MAY cache per HTTP cache headers, and "MUST NOT cache error responses".
- **SSRF (§8.6):** the AS "MUST NOT" fetch CIMD URLs, or URLs inside the document, that resolve to special-use IP addresses (RFC 6890). The loopback exception is for development and testing only and "MUST NOT be used in production". Response size should be capped (5 KB recommended, §8.7).
- **Display of client identity (§8.5, §8.8):**
  - The AS SHOULD fetch the document to show name and logo, and "SHOULD display the hostname of the `client_id`" even when other information is shown.
  - On fetch failure the URL is the only identity indicator.
  - `logo_uri` SHOULD be prefetched and cached (helps moderation and avoids cross-domain tracking).
- **Trust (§8.1, §8.9, §8.10):**
  - The AS may require `redirect_uris` to be same-origin with `client_id`; without such restrictions impersonation risk rises.
  - Reputation checks, warnings for new domains, and allowlists are suggested.
  - "CIMD Services" that host documents for developers are effectively static registration and should not get the same trust.
- **Client authentication (§8.2):** if the document advertises `private_key_jwt`, the AS MUST require it per RFC 7523 using the discovered key. Key or metadata changes may warrant re-consent or token revocation (§8.4).
- [MCP ref] MCP ASs and clients "SHOULD support" CIMD, citing draft -00 rather than -02. — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)

### Inferences
- Architecture diagram sequence (consistent with RFC 9728 §5, RFC 8414 §3, CIMD §5 and the MCP flow):
  1. 401 + `resource_metadata`
  2. GET PRM → verify `resource`
  3. GET AS metadata → verify `issuer`
  4. AS fetches CIMD → verify `client_id` and the redirect URI
  5. Browser authorization request (PKCE, `state`, `resource`)
  6. Redirect with `code` + `iss` → verify `iss`
  7. Token request (`code_verifier`, `resource`, optionally DPoP)
  8. Call MCP server with the header token → RS checks `aud`
- CIMD shifts the client-impersonation risk from "anyone can register any name/logo" (RFC 7591 self-asserted metadata) to "identity = control of an HTTPS URL". The hostname display requirement makes the consent screen show the domain, not just a chosen display name.
- RFC 9728 explicitly leaves AS trust to the client (§7.6). A malicious MCP server can therefore point clients at an attacker-run AS; the defences are `iss` checks, user-visible AS domain display, and audience binding.

### Gaps
- CIMD -02 does not specifically mention warnings for localhost redirect URIs or `token_endpoint_auth_method=none` (per my read of the -02 text).
- Whether CIMD will be WG-last-called in 2026 is unknown.

---

## 5. Sender-constrained tokens: DPoP (RFC 9449) and mTLS (RFC 8705)

### Takeaway
Sender-constraining binds a token to a key the legitimate client holds, so a stolen or leaked token (from logs, a malicious RS, an XSS-exfiltrated store, or a compromised proxy) is useless without the private key. DPoP does this at the application layer with a signed per-request proof JWT and suits public clients and browsers. mTLS uses the TLS client certificate and suits confidential and server-side clients. RFC 9700 and OAuth 2.1 say SHOULD for access tokens and make it one of two MUST options for public-client refresh tokens. MCP's core spec does not require either, though RFC 9728 lets a resource advertise `dpop_bound_access_tokens_required`.

### Cited Findings
**DPoP, RFC 9449 (Sep 2023, Standards Track; Fett, Campbell, Bradley, Lodderstedt, Jones, Waite)** — [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)
- Purpose: sender-constrains access and refresh tokens at the application layer. It is not a client authentication method.
- The proof JWT is sent in the `DPoP` HTTP header:
  - Header: `typ` = `dpop+jwt`; `alg` asymmetric ("the algorithm `none` MUST NOT be allowed"); `jwk` = public key.
  - Claims: `jti`, `htm` (HTTP method), `htu` (target URI without query or fragment), `iat`, plus `ath` (hash of the access token) when calling a resource and `nonce` when a server supplied one.
- Server checks (§4.3): header, signature, claims, method/URI match, nonce, `iat` window, and for resources `ath` plus key-to-token binding. "The resource server MUST NOT grant access to the resource unless all checks are successful."
- Binding: the access token carries `cnf: {"jkt": <base64url SHA-256 JWK thumbprint>}` (also in introspection). The token response `token_type` is `DPoP`.
- Usage: `Authorization: DPoP <token>` + `DPoP: <proof>`. RS challenge is `WWW-Authenticate: DPoP` (with optional `algs`). A DPoP-bound token presented as `Bearer` must be rejected.
- Nonces: servers issue `DPoP-Nonce`. A missing nonce gets error `use_dpop_nonce` (400 at the AS, 401 at the RS). "A server MUST NOT accept any DPoP proofs without the `nonce` claim when a DPoP nonce has been provided to the client."
- Code binding: the `dpop_jkt` authorization request parameter binds the code to the key, and the token request must present a proof with the same key. PAR + DPoP header gives the same binding.
- Refresh tokens: for public clients they are bound to the DPoP key; confidential clients' refresh tokens are not DPoP-bound because client authentication already constrains them.
- Security considerations (§11):
  - Proof replay: short acceptance window, optional `jti` tracking.
  - Pre-generated proofs are limited by server nonces and `ath`.
  - DPoP does not protect against XSS: running malicious code can still create proofs while online, even with non-extractable keys. CSP is recommended as a second layer.
  - `typ` must be checked to prevent swapping in other signed JWTs.
  - DPoP does not replace TLS.

**mTLS, RFC 8705 (Feb 2020, Standards Track)** — [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html)
- Two client-auth methods: `tls_client_auth` (PKI-validated certificate with subject DN/SAN registered) and `self_signed_tls_client_auth` (certificate pinned via `jwks`).
- Certificate-bound access tokens carry `cnf: {"x5t#S256": <cert SHA-256 thumbprint>}`. The RS compares this with the certificate presented on the mTLS connection, so a token is unusable without the private key.
- AS metadata `tls_client_certificate_bound_access_tokens` and `mtls_endpoint_aliases`; RS metadata `tls_client_certificate_bound_access_tokens` (also in RFC 9728). — [RFC 9728 §2](https://www.rfc-editor.org/rfc/rfc9728.html)

**Normative weight**
- RFC 9700 §2.2.1 says AS and RS "SHOULD use mechanisms for sender-constraining access tokens", and §2.2.2 says public-client refresh tokens "MUST be sender-constrained or use refresh token rotation". — [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)
- ID-JAG supports DPoP: the ID-JAG may carry `cnf.jkt`, which must match the DPoP key at the Resource AS. — [ID-JAG -04](https://www.ietf.org/archive/id/draft-ietf-oauth-identity-assertion-authz-grant-04.html)

### Inferences
- Relevance to MCP:
  - DPoP is the natural fit for MCP clients that are public (desktop or IDE hosts), because it needs no PKI or TLS-terminator cooperation.
  - mTLS fits server-to-server MCP gateways.
  - Neither is mandated by MCP core (no MUST appears in the MCP authorization page's list), so most MCP deployments today rely on bearer tokens plus audience binding.
- Per RFC 9449 §11, DPoP does not protect against code running inside the client. A malicious embedded view that can reach the host's signing function could still mint proofs. DPoP keys must therefore live only in the host or MCP client process, never be exposed to the view, and should be generated non-extractable (WebCrypto) in browsers.

### Gaps
- I found no source quantifying DPoP adoption among MCP servers or authorization servers as of October 2026.
- The draft-ietf-wimse-aims-00 listing I retrieved does not mention DPoP.

---

## 6. Delegation, fine-grained consent, and token lifecycle: RFC 8693, RFC 9396, RFC 9470, RFC 6750, RFC 7009, RFC 7662, RFC 9068

### Takeaway
These specs supply the building blocks:
- Agent "acting on behalf of" a user: token exchange + `act`/`may_act` (RFC 8693).
- Per-action consent: `authorization_details` (RFC 9396).
- Stronger user authentication for sensitive tools: `insufficient_user_authentication` challenge (RFC 9470).
- Machine-readable failures: `invalid_token` / `insufficient_scope` (RFC 6750).
- Kill-switch: revocation (RFC 7009).
- Server-side validity check: introspection (RFC 7662).
- Typed, audience-checked JWT access tokens (RFC 9068), which defeat token substitution.

### Cited Findings
**RFC 8693 Token Exchange (Jan 2020)** — [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html)
- Request: `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`; `subject_token` + `subject_token_type` (REQUIRED); optional `actor_token` + `actor_token_type`, `requested_token_type`, `audience`, `resource`, `scope`. The response adds `issued_token_type`.
- §1.1 distinguishes impersonation (the new token is indistinguishable from the subject) from delegation (the token records that actor A acts for subject S).
- The `act` (actor) claim (§4.1) identifies the current actor; nesting `act` records a delegation chain. Access-control decisions consider only the top-level claims and the current (outermost) actor; prior nested actors are informational.
- The `may_act` claim (§4.4) states who is authorized to act for the subject.

**RFC 9396 Rich Authorization Requests (May 2023)** — [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html)
- The `authorization_details` parameter is a JSON array of objects with a required `type` and common fields `locations`, `actions`, `datatypes`, `identifier`, `privileges`.
- It is used for transaction-specific consent (e.g., "pay €123 to X") that scopes can't express. The AS displays and records the details, and they are echoed in the token response or introspection. Error: `invalid_authorization_details`.
- AS metadata `authorization_details_types_supported`; RS metadata has the same field. — [RFC 9728 §2](https://www.rfc-editor.org/rfc/rfc9728.html)

**RFC 9470 Step-up Authentication Challenge (Sep 2023)** — [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470.html)
- The RS returns `401` + `WWW-Authenticate: Bearer error="insufficient_user_authentication", error_description="…", acr_values="…"` and/or `max_age="…"`.
- The client re-runs authorization with `acr_values` / `max_age`. The new token (JWT claims or introspection) conveys `acr` and `auth_time` so the RS can verify.
- ID-JAG reuses this: the IdP "may return `insufficient_user_authentication`" for step-up. — [ID-JAG -04](https://www.ietf.org/archive/id/draft-ietf-oauth-identity-assertion-authz-grant-04.html)

**RFC 6750 Bearer Token Usage (Oct 2012)** — [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html)
- Three transmission methods: header, form body, query (query later forbidden by OAuth 2.1).
- `WWW-Authenticate: Bearer` with `realm`, `scope`, `error`, `error_description`, `error_uri`.
- Errors: `invalid_request` (400), `invalid_token` (401), `insufficient_scope` (403).
- If the request has no authentication information, the RS "SHOULD NOT include an error code or other error information" (§3.1).
- Recommendations (§5.3): don't store bearer tokens in cookies sent in the clear; issue short-lived and scoped tokens; don't pass bearer tokens in page URLs.
- [MCP ref] MCP servers "SHOULD include a `scope` parameter in the `WWW-Authenticate` header as defined in RFC 6750 Section 3". Runtime `insufficient_scope` uses 403 + `error="insufficient_scope"`, `scope=…`, `resource_metadata=…`. Clients compute the union of prior and challenged scopes for step-up. — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)

**RFC 7009 Token Revocation (Aug 2013)** — [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html)
- `POST` to the revocation endpoint with `token` and optional `token_type_hint` (`access_token`/`refresh_token`). The AS authenticates confidential clients and checks the token belongs to the requesting client.
- It returns 200 even for invalid tokens, which avoids a token-validity oracle.
- Revoking a refresh token SHOULD also invalidate access tokens from the same grant, if the AS supports access-token revocation.

**RFC 7662 Token Introspection (Oct 2015)** — [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html)
- The RS POSTs `token` and gets `active` (REQUIRED) plus `scope`, `client_id`, `username`, `token_type`, `exp`, `iat`, `nbf`, `sub`, `aud`, `iss`, `jti` (and `cnf` for bound tokens per RFC 9449/8705).
- "To prevent token scanning attacks, the endpoint MUST also require some form of authorization to access this endpoint" (§2.1).
- Caching introspection results trades latency against revocation freshness (security considerations).

**RFC 9068 JWT Profile for OAuth 2.0 Access Tokens (Oct 2021)** — [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html)
- Header `typ` = `at+jwt`. Required claims: `iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti`. Optional: `auth_time`, `acr`, `amr`, `scope`, plus groups, roles and entitlements.
- RS validation (§4): verify `typ` is `at+jwt`/`application/at+jwt` and reject anything else; `iss` matches the expected AS; "`aud` claim contains a resource indicator value corresponding to an identifier the resource server expects for itself"; signature valid with the AS key and `alg` not `none`; `exp` not passed.
- Explicit typing prevents substitution of other JWTs (e.g., ID tokens) as access tokens (security considerations).

### Inferences
- For "agent acting for user" MCP chains (host → MCP server → downstream API), RFC 8693 delegation with `act` is the standards-based alternative to token passthrough. MCP's "MUST NOT accept or transit any other tokens" rule pushes servers toward exchange, not forwarding.
- RFC 9396 + RFC 9470 together give the standards basis for "per-tool-call consent" and "re-authenticate before destructive action" UX in MCP Apps.
- RFC 9068 `aud` validation is the RS-side half of RFC 8707.

### Gaps
- I did not fetch RFC 8693/9396/9470/7009/7662/9068 text in this session. The parameter and claim names above come from the published RFCs (stable since publication), but verbatim quotes were limited to well-known phrases. The report writer should re-verify any quote used verbatim.
- MCP core does not reference RFC 8693, 9396 or 9470 in its standards list. I did not verify whether MCP extensions do.

---

## 7. Enterprise-managed and AI-agent authorization: ID-JAG / Cross App Access, agent-specific IETF drafts, OpenID Foundation AIIM work

### Takeaway
ID-JAG (now an oauth WG draft, -04, May 2026) lets an enterprise IdP mint a short-lived signed assertion. The client exchanges it at a third-party resource AS for an access token, which removes per-app interactive consent and puts IdP policy in control. Okta markets this as "Cross App Access (XAA)", and secondary sources say MCP adopted it as the stable "Enterprise-Managed Authorization" extension in June 2026. Agent-specific IETF work is still early:
- The WSO2 on-behalf-of draft has expired.
- The KLRC agent-auth draft was adopted into WIMSE as draft-ietf-wimse-aims-00 (Informational, Sept 2026).
- The OpenID Foundation AIIM CG's October 2025 whitepaper names recursive delegation and cross-domain trust as the main gaps.

### Cited Findings
**ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant-04)** — [ID-JAG -04](https://www.ietf.org/archive/id/draft-ietf-oauth-identity-assertion-authz-grant-04.html); [Datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)
- Status: published 21 May 2026, expires 22 Nov 2026. oauth WG I-D, intended status not set, IESG "I-D Exists". Replaces draft-parecki-oauth-identity-assertion-authz-grant. Authors: Aaron Parecki (Okta), Karl McGuinness, Brian Campbell (Ping). It names the pattern "Cross-App Access (XAA)".
- Roles: Client; IdP Authorization Server (trusted by the Resource AS for SSO); Resource Authorization Server; Resource Server.
- **Step 1, RFC 8693 exchange at the IdP:**
  - `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`.
  - `subject_token` = the user's ID Token, a SAML 2.0 assertion, or (optionally) a refresh token.
  - `audience` = the Resource AS issuer; optional `resource`, `scope`, `authorization_details`. `actor_token` is optional and left for future profiles.
  - The client must authenticate.
  - The response carries the ID-JAG in `access_token` with `token_type=N_A`.
- **ID-JAG format:**
  - JWT `typ` = `oauth-id-jag+jwt`. Required: `iss`, `sub`, `aud`, `client_id`, `jti`, `exp`, `iat`.
  - Optional: `resource`, `scope`, `authorization_details`, `act`, `tenant`, `aud_tenant`, `aud_sub`, `email`, `auth_time`, `acr`, `amr`, `cnf` (DPoP).
- **Step 2, RFC 7523 JWT-bearer grant at the Resource AS:**
  - `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion=<ID-JAG>`, with client authentication.
  - The Resource AS checks `typ`, that `aud` exactly equals its issuer, and that `client_id` equals the authenticated client. It applies local policy and may down-scope.
- The Resource AS "SHOULD NOT issue refresh tokens"; the client re-presents the ID-JAG or gets a new one from the IdP.
- Security:
  - Confidential clients only; public clients should use the authorization code flow.
  - An ID-JAG must not be reused across Resource ASs.
  - The Resource AS must not trust `sub_id.issuer` on its own.
  - DPoP binding via `cnf.jkt`; IdP step-up via `insufficient_user_authentication`.
  - Actor delegation (`act`) is not yet normatively defined.
  - Appendix A.4 gives an "AI Agent using External Tools" example.
- [MCP ref, secondary] Per vendor and ecosystem sources (not the MCP spec text I read):
  - MCP's "Enterprise-Managed Authorization" extension is built on ID-JAG and reached Stable in June 2026 (one source gives 18 June 2026).
  - The flow is SSO → RFC 8693 exchange for ID-JAG → RFC 7523 grant at the MCP AS.
  - Okta is the first IdP supporting it.
  - Sources: [WorkOS](https://workos.com/blog/mcp-enterprise-managed-authorization-id-jag); [MCP blog](https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/); [Auth0 docs](https://auth0.com/docs/ai-agents-mcp/cross-app-access). The MCP core page lists extensions in the [ext-auth repository](https://modelcontextprotocol.io/specification/latest/basic/authorization).

**Agent-specific IETF drafts**
- **draft-oauth-ai-agents-on-behalf-of-user-02** (WSO2): latest 25 Aug 2025, expired.
  - -00 (May 2025) defined `requested_agent` and grant type `urn:ietf:params:oauth:grant-type:agent-authorization_code`.
  - -02 replaced these with a `requested_actor` authorization-request parameter and an `actor_token` at the token endpoint, so the agent is authenticated when redeeming the code and consent names the agent.
  - Commentary notes it is single-hop only and does not define how agents obtain actor tokens. A WorkOS article dated April 2026 calls it "new" despite its 2025 dates.
  - Sources: [Datatracker](https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/); [WorkOS blog](https://workos.com/blog/oauth-on-behalf-of-ai-agents).
- **draft-klrc-aiagent-auth** (Kasselman, Lombardo, Rosomakho, Campbell, Steele, Parecki): -03, 6 Jul 2026, now "Replaced" by **draft-ietf-wimse-aims-00** "AI Identity Management System".
  - AIMS: WIMSE WG, 15 Sep 2026, Informational, expires 19 Mar 2027.
  - It composes existing standards rather than defining protocols: WIMSE workload identity (WIT/WIC, Workload Proof Tokens, HTTP Signatures), SPIFFE, RFC 6749/9068/7662/9700, RFC 8693, Transaction Tokens, OAuth identity and authorization chaining across domains, the identity assertion JWT grant, RFC 7523/8705, RFC 8414/9728, OIDC Discovery, CIMD, RFC 7591, CIBA, Shared Signals (CAEP/RISC), RFC 9421, FAPI 2.0, and it cites MCP and A2A.
  - Sources: [Datatracker klrc](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/); [Datatracker AIMS](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/).
- **draft-aap-oauth-profile-00** (Feb 2026): an individual "Agent Authorization Profile" for OAuth 2.0/JWT for machine-to-machine agent scenarios. — [Datatracker](https://datatracker.ietf.org/doc/html/draft-aap-oauth-profile-00)
- **draft-song-oauth-ai-agent-authorization-00** (2025): individual proposal adding a `target_id` for granular authorization. — [IETF archive](https://www.ietf.org/archive/id/draft-song-oauth-ai-agent-authorization-00.html)

**OpenID Foundation AI Identity Management CG**
- Whitepaper "Identity Management for Agentic AI: The new frontier of authorization, authentication, and security for an AI agent world", published 7 Oct 2025 by the OpenID Foundation AIIM Community Group, lead author Tobin South (arXiv 2510.25819). — [OpenID Foundation](https://openid.net/new-whitepaper-tackles-ai-agent-identity-challenges/); [arXiv](https://arxiv.org/abs/2510.25819)
  - Its position: current frameworks work for simple, single-domain agents, but "significant cracks" appear with autonomy. Existing frameworks "weren't designed for recursive delegation chains"; it also flags cross-domain trust propagation, authorization at scale and fragmentation.
  - Recommendations:
    - Apply existing standards now.
    - Standards bodies should accelerate agent identity and delegation work.
    - Enterprises should treat agents as identity-managed entities with lifecycle and governance.
    - Use specialized authorization servers rather than custom security per system.
  - It calls MCP "the leading standard" for connecting models to tools.
- A third-party summary lists gaps including agent identity fragmentation, user impersonation, consent fatigue, recursive delegation, and browser agents bypassing API controls. This is secondary; verify against the PDF. — [arXiv record via search](https://arxiv.org/pdf/2510.25819)
- In March 2026, the AIIM CG Threat Modelling subgroup submitted a response to NIST's RFI on AI agent security. — [OpenID Foundation PDF](https://openid.net/wp-content/uploads/2026/03/Attachment1_NIST-2025-0035-0001.pdf)

### Inferences
- ID-JAG addresses "consent fatigue" and "shadow OAuth grants" in enterprises by moving the consent decision to IdP policy. Its limits are confidential clients only and no normative `act` semantics yet, so it does not by itself express "agent X for user Y" chains.
- Multi-hop agent delegation is not standardized as of Oct 2026. The pieces are RFC 8693 `act` nesting, Transaction Tokens, identity chaining, and WIMSE AIMS (Informational). A report should label agent delegation chains as an open standards gap.

### Gaps
- I did not verify the exact current status (WG state or revision) of draft-ietf-oauth-transaction-tokens or draft-ietf-oauth-identity-chaining.
- I did not read the MCP Enterprise-Managed Authorization extension text itself (out of scope). Its "Stable, June 2026" status comes from secondary sources only.
- I could not confirm the full contents of the OIDF whitepaper beyond the announcement and summaries.

---

## 8. Native-app OAuth (RFC 8252): system browser, not embedded webviews; redirect URI options

### Takeaway
RFC 8252 (BCP 212) is the primary normative basis for "never type credentials inside a view": native apps "MUST NOT use embedded user-agents to perform authorization requests". The host app controls an embedded webview and can read keystrokes and cookies, and training users to type passwords into un-verifiable chrome enables phishing. Authorization must happen in the system browser (or an in-app browser tab) and return via a private-use scheme, a claimed https link, or a loopback IP redirect, always with PKCE. OAuth 2.1 §8 carries the same rule forward.

### Cited Findings
- RFC 8252 "OAuth 2.0 for Native Apps", BCP 212, October 2017, by W. Denniss (Google) and J. Bradley (Ping Identity). Updates RFC 6749. — [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html)
- §8.12: "This best current practice requires that native apps MUST NOT use embedded user-agents to perform authorization requests". Embedded user-agents "are unsafe for use by third parties to the authorization server by definition". The host can "record every keystroke entered in the login form to capture usernames and passwords", and the practice "trains them that it's OK to enter credentials without validating the site first." — [RFC 8252 §8.12](https://www.rfc-editor.org/rfc/rfc8252.html)
- AS countermeasures: authorization endpoints "MAY take steps to detect and block authorization requests in embedded user-agents" (§8.12). An AS can defeat fake external user-agents by "requiring an authentication factor only available to true external user-agents" (§8.7). — [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html)
- Redirect options (§7): the AS "MUST offer at least the three redirect URI options":
  - Private-use URI scheme in reverse-domain form, e.g. `com.example.app:/oauth2redirect/example-provider` (§7.1).
  - Claimed `https` scheme (§7.2).
  - Loopback `http://127.0.0.1:{port}/{path}` or `http://[::1]:{port}/{path}`; the AS "MUST allow any port to be specified at the time of the request" (§7.3).
  — [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html)
- Loopback (§8.3): open the port only when starting the request, listen on the loopback interface only, and "the use of localhost is NOT RECOMMENDED" (use IP literals). — [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html)
- PKCE (§6, §8.1): "Public native app clients MUST implement" PKCE; AS "SHOULD reject authorization requests from native apps that don't use PKCE". — [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html)
- Client authentication (§8.5): secrets embedded in distributed apps "should not be treated as confidential secrets", and the AS "MUST treat the client as a public client". — [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html)
- Impersonation (§8.6): the AS "SHOULD NOT process authorization requests automatically without user consent or interaction, except when the identity of the client can be assured". Claimed-https redirects "MAY be accepted … as identity proof." — [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html)
- OAuth 2.1 -16: "Native apps MUST use an external user agent to perform OAuth authorization requests" (§8.2). §8.5.1 says embedded agents are unsafe for third parties and can expose full credentials. §8.5.3 warns a malicious app set as the default `https` handler could intercept requests. — [draft-ietf-oauth-v2-1-16](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.html)
- RFC 9700 §4.16 requires the AS to prevent clickjacking, i.e. to refuse to be framed by untrusted origins. A login page embedded in a third-party iframe is therefore expected to be blocked by `frame-ancestors` / X-Frame-Options. — [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)

### Inferences
- An MCP App view (sandboxed iframe inside a host) is functionally an "embedded user-agent" from the AS's perspective. Credential entry or consent rendered inside it violates RFC 8252 §8.12 and OAuth 2.1 §8.2. A correctly configured AS should refuse to render inside it per RFC 9700 §4.16.
- The compliant pattern is for the host or MCP client to open the system browser (or a top-level popup on the web) and receive the code at a loopback, claimed-https or private-use redirect. The view at most triggers or is notified of the flow, never handles credentials.
- A view that renders its own "Sign in" form imitating an IdP is the phishing pattern RFC 8252 warns about ("trains them that it's OK to enter credentials without validating the site first").

### Gaps
- I found no standard that specifically addresses OAuth initiated from inside a sandboxed iframe within a desktop or chat host. The mapping above is by analogy to RFC 8252's embedded user-agent definition.

---

## 9. Web-platform isolation for embedded views: iframe sandbox, postMessage, CSP frame-ancestors / X-Frame-Options, OWASP guidance, cross-origin isolation

### Takeaway
Embedded views rely on five platform controls:
- **Sandbox:** `sandbox` without `allow-same-origin` gives the view an opaque origin (no cookies or storage of its real origin, no same-origin DOM access). Each `allow-*` token re-grants one capability, and `allow-scripts` + `allow-same-origin` on same-origin content defeats the sandbox entirely.
- **postMessage:** the view-to-host channel must use an explicit `targetOrigin` (never `*` for sensitive data). The receiver must validate `event.origin` (and, for opaque-origin sandboxed frames, `event.source`, since their origin serializes to `"null"`) plus the message schema.
- **Framing:** CSP `frame-ancestors` (preferred over X-Frame-Options) stops pages such as AS login and consent from being framed for clickjacking.
- **Cross-origin isolation:** COOP/COEP severs opener relationships and mitigates XS-Leaks and side channels.

### Cited Findings
**iframe sandbox**
- An empty `sandbox` treats content as a unique opaque origin and blocks scripts, forms, popups, top-level navigation, modals, downloads and auto-triggered features. Each `allow-*` token lifts one restriction:
  - `allow-scripts`, `allow-same-origin` (keep the real origin), `allow-forms`, `allow-popups`, `allow-popups-to-escape-sandbox`, `allow-top-navigation`, `allow-top-navigation-by-user-activation`, `allow-modals`, `allow-downloads`, `allow-storage-access-by-user-activation`, `allow-top-navigation-to-custom-protocols`, `allow-pointer-lock`, `allow-presentation`, `allow-orientation-lock`.
  - Sources: [MDN iframe](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe); [OWASP HTML5 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) ("All markup is treated as being from a unique origin", "All forms and scripts are disabled", "All links are prevented from targeting other browsing contexts").
- WHATWG: "Setting both the allow-scripts and allow-same-origin keywords together when the embedded page has the same origin" as the parent lets the page remove the sandbox attribute and reload, "effectively breaking out of the sandbox altogether". "To limit the damage that can be caused by hostile HTML content, it should be served from a separate dedicated domain." `allow-top-navigation` and `allow-top-navigation-by-user-activation` "must not both be specified". — [WHATWG HTML §4.8.5](https://html.spec.whatwg.org/multipage/iframe-embed-object.html)
- MDN: with `allow-same-origin`, a same-origin parent can access the iframe DOM even without `allow-scripts`. — [MDN iframe](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe)
- Related iframe attributes — [MDN iframe](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe):
  - `allow` (Permissions Policy for camera, mic, etc.; "a further restriction on top of the policy specified in the `Permissions-Policy` header").
  - `credentialless` (ephemeral context with no cookies or storage of its origin).
  - `csp` (policy enforced on the embedded resource).
  - `referrerpolicy` (default `strict-origin-when-cross-origin`; `no-referrer` suppresses Referer).
- Opaque-origin serialization: the ASCII serialization of an opaque origin is the string `"null"`. Messages from sandboxed (no `allow-same-origin`) frames therefore arrive with `event.origin === "null"`. — [WHATWG HTML origin serialization](https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin)

**postMessage**
- WHATWG §9.3.2.1: authors should "check the origin attribute to ensure that messages are only accepted from domains that they expect" and "check that the data in question is of the expected format". They "should not use the wildcard keyword (*) in the targetOrigin argument in messages that contain any confidential information". A `targetOrigin` of `"/"` (the default) restricts delivery to same-origin targets. On origin mismatch the message is discarded. `event.source` is the sender's WindowProxy. — [WHATWG Web Messaging](https://html.spec.whatwg.org/multipage/web-messaging.html)
- WHATWG §9.4: MessageChannel ports "can be viewed as a way to expose limited capabilities" (capability-style channels). — [WHATWG Web Messaging](https://html.spec.whatwg.org/multipage/web-messaging.html)
- OWASP: "explicitly state the expected origin as the second argument to `postMessage` rather than `*`"; "Check the origin properly exactly to match the FQDN(s) you expect"; "Don't assume you have control over the `data` attribute"; "Never evaluate passed messages as code (e.g. via `eval()`) or insert it to a page DOM (e.g. via `innerHTML`)"; use `textContent`. — [OWASP HTML5 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)
- OWASP: "Do not store session identifiers in local storage as the data is always accessible by JavaScript." — [OWASP HTML5 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)
- RFC 9700 §4.17 (OAuth-specific): exact-origin matching, "Wildcard origins like "*" in postMessage MUST NOT be used", clients "MUST prevent injection of in-browser messages". — [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)

**Clickjacking (frame-ancestors / X-Frame-Options)** — [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- Preferred defence is CSP `frame-ancestors` (`'none'`, `'self'`, or explicit origins). Per CSP, "the X-Frame-Options header MUST be ignored" when `frame-ancestors` is present. It "must be configured as an HTTP Response Header, not in a `<meta>` tag."
- X-Frame-Options: "The "DENY" setting is recommended unless a specific need has been identified for framing". `ALLOW-FROM` is obsolete and fails open; meta-tag XFO does not work; only one value is honored.
- SameSite cookies help but "SameSite does not block framing".
- Frame-busting JS is defeatable, e.g. a sandboxed iframe disables it.
- DoubleClickjacking targets top-level windows, so "framing restrictions such as `X-Frame-Options` and CSP `frame-ancestors` do not prevent this attack". The cheat sheet recommends transaction authorization for high-risk actions.
- RFC 9700 §4.16: "Authorization servers MUST prevent clickjacking attacks" and "SHOULD also use Content Security Policy (CSP) level 2" or greater. — [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)

**Cross-origin isolation** — [MDN crossOriginIsolated](https://developer.mozilla.org/en-US/docs/Web/API/Window/crossOriginIsolated)
- Enabled by `Cross-Origin-Opener-Policy: same-origin` + `Cross-Origin-Embedder-Policy: require-corp` (or `credentialless`). It gates `SharedArrayBuffer`, high-precision `performance.now()` and `measureUserAgentSpecificMemory()`.
- It mitigates "side-channel attacks and cross-origin attacks referred to as XS-Leaks" and severs the relationship with cross-origin openers and popups. A COEP document can embed non-CORP third parties only via `credentialless` iframes.

### Inferences
- Embedded MCP App views should follow these rules:
  - Sandbox without `allow-same-origin`, or with it only when the view is served from a dedicated origin distinct from the host (per the WHATWG dedicated-domain advice).
  - Avoid `allow-top-navigation` (lets the view redirect the host to a phishing page) and `allow-popups-to-escape-sandbox` unless needed.
  - Use `allow` to deny sensitive Permissions-Policy features.
  - The host must validate `event.source === iframe.contentWindow`. An origin check alone is insufficient when every sandboxed frame reports `"null"`.
  - Never expose tokens, DPoP keys or PKCE verifiers over the message channel.
- `frame-ancestors` on the AS is what makes "log in inside the view" fail closed. DoubleClickjacking shows that framing controls do not protect top-level consent popups, so high-risk consents need re-confirmation (RFC 9396/9470 patterns).

### Gaps
- I did not retrieve the W3C CSP Level 3 text directly; the `frame-ancestors`-overrides-XFO rule is cited via OWASP.
- I found no standards-body guidance specific to "double-iframe" or "sandbox proxy" host architectures.

---

## 10. Refresh-token rotation with reuse detection: specification text, race conditions, grace periods

### Takeaway
OAuth 2.1 and RFC 9700 require public-client refresh tokens to be either sender-constrained or rotated with replay detection. If an already-used refresh token reappears, the AS revokes the active token (in practice the whole token family). Rotation has a well-known failure mode: concurrent or retried refreshes look like theft and log users out, and non-atomic consume-and-issue can let two requests both succeed. Vendors add a short grace or reuse window (about 30–60 s) that returns the same rotated tokens. This is not standardized, and it opens a small replay window. DPoP-bound refresh tokens avoid the problem entirely.

### Cited Findings
- OAuth 2.1 -16 §4.3.1: for public clients "Authorization servers MUST utilize one of these methods to detect refresh token replay". Rotation means "the authorization server issues a new refresh token with every access token refresh response". §4.3.2: "the client MUST discard the old refresh token and replace it with the new refresh token." — [draft-ietf-oauth-v2-1-16](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.html)
- RFC 9700 §4.14.2: when an invalidated refresh token is presented, the AS cannot tell which party is legitimate and "it will revoke the active refresh token", so the legitimate client must obtain a new grant. Refresh tokens "SHOULD expire if the client has been inactive for some time". The AS "MAY revoke refresh tokens automatically in case of a security event". — [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)
- DPoP alternative: public-client refresh tokens are bound to the DPoP key and each refresh must prove possession of the same key. — [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)
- Race condition: two near-simultaneous refreshes with the same token can, with naive read-check-write, both succeed and fork the token family. Consume-and-issue must be atomic at the database level; application locks are insufficient across processes. — [DEV Community: race conditions in refresh token rotation](https://dev.to/silentwatcher_95/race-conditions-in-jwt-refresh-token-rotation-3j5k)
- Grace-period designs:
  - Lucid caches newly issued tokens (encrypted, short TTL) and returns the same tokens if the old refresh token is reused within the grace period. It notes that Auth0, Okta, Fitbit and Slack support some grace period, that the concept "isn't formalized in the spec", and that grace periods could be shortened or disabled for public clients. — [Lucid tech blog (Sep 2023)](https://lucid.co/techblog/2023/09/18/avoiding-false-positives-in-oauth-2-0-refresh-token-theft-detection)
  - WorkOS documents a 30-second grace period in which replaying a just-exchanged token returns the same rotated tokens; retrying with the same token is safe only inside that window. — [WorkOS Session resilience](https://workos.com/docs/authkit/session-resilience)
  - Endurain uses a 60-second window and treats reuse after it as theft (family revocation). — [Endurain docs](https://docs.endurain.com/reference/users/users_sessions/rotated_refresh_tokens)

### Inferences
- For MCP hosts that run several concurrent sessions or tool calls against the same MCP server, implementations need:
  - single-flight refresh on the client side (one in-flight refresh per grant, others await it);
  - atomic consume on the AS;
  - a short idempotent grace window that returns identical tokens rather than minting new ones.
- Otherwise reuse detection will produce false-positive revocations, which users experience as random logouts.
- The grace window is a deliberate security trade-off: a thief replaying within it isn't detected. Sender-constrained (DPoP) refresh tokens remove the need for rotation-based detection.

### Gaps
- The search surfaced a reference to a 2026 Keycloak CVE about non-atomic refresh-token rotation enforcement, but I did not retrieve the CVE identifier or advisory, so it is unverified.
- I did not fetch Auth0's or Okta's current documentation for their exact reuse-interval defaults. The Lucid blog (2023) is the only source here asserting that those vendors offer grace periods.
