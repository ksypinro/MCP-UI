# Testing and verification

339 automated tests, plus harnesses for the things tests cannot reach. This
document explains what each layer proves — and, as importantly, what it does
not.

---

## The layers

| | Count | Command | What it establishes |
| --- | --- | --- | --- |
| Server | 279 | `npm test` | Domain rules, HTTP contract, OAuth, DPoP and PAR, passkeys, account pages, stores, KMS, the split, MCP protocol, views |
| Server on real backends | the same 279 | `npm run test:pg` | The same suite on PostgreSQL 17 and Redis 7: real row locks, shared stores, four processes |
| iOS | 60 | `xcodebuild … test` | View-model state machines, browser sign-in, DPoP proofs, refresh, transport |
| Acceptance | 47 criteria | `npm run acceptance` | Which criteria of requirement §12 the suites actually establish |
| Client conformance | 18 checks | `npm run client-check` | That a compliant MCP client can find its way through |
| Host readiness | 9 checks | `npm run host-check` | That everything failable without a host has already failed |
| Views | manual | `node tools/mock-host/run.mjs` | What a view looks like and does |
| Load | manual | `npm run load` | Throughput and latency of the tool-call and refresh paths, against a running server |

---

## Running them

```bash
cd server
npm install
npm test                                   # 279
npm run test:pg                            # the same on PostgreSQL and Redis
npm run typecheck
npm run acceptance                         # the criteria map

cd ../ios
xcodebuild -project IoTSwitch.xcodeproj -scheme IoTSwitch \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' test
```

The server suite needs nothing installed — PGlite is real PostgreSQL compiled
to WebAssembly, so there is no database to provision. On PGlite the tests that
need Redis or several processes are skipped, and the acceptance report says
which criteria that leaves unproven. `npm run test:pg` needs a PostgreSQL 17
and a Redis 7; it defaults to local containers on ports 55432 and 56379, or
takes `TEST_DATABASE_URL` and `TEST_REDIS_URL`. CI runs both legs on every pull
request.

---

## Where the server tests live

| File | Tests | Covers |
| --- | --- | --- |
| `oauth.test.ts` | 42 | Discovery, the full flow, PKCE, code replay, rotation, revocation, sign-in and sign-up failures, page hardening, the sweep |
| `mcp.test.ts` | 24 | Anonymous access, the challenge, scopes, isolation, cross-surface |
| `mcp-ui.test.ts` | 22 | Resource shape, fingerprinted URIs, CSP, no tokens in views, inline budget |
| `mcp-bridge.test.ts` | 16 | The shared bridge, in a vm: origin pinning, granted display modes, merged context updates |
| `devices.test.ts` | 15 | Ownership, versions, folding, the cap, auditing |
| `api.test.ts` | 13 | Status codes, error codes, correlation ids, DPoP-only access, `/v1/me` |
| `oauth-clients.test.ts` | 12 | CIMD, SSRF refusals by address range, document caching, DCR strictness, known clients |
| `consent.test.ts` | 11 | Remembered consent, re-authentication, browser binding, CSRF, sessions, `offline_access` |
| `stores.test.ts` | 11 | One contract for memory and Redis stores; sharing and revocation across processes; failing closed (Redis tests need `TEST_REDIS_URL`) |
| `first-party.test.ts` | 8 | The iOS app's PAR flow, bound tokens and refresh, code binding, the app-site association, DPoP at `/mcp` |
| `concurrency.test.ts` | 7 | AC-09 and AC-10 |
| `exchange.test.ts` | 7 | Token exchange: claims, narrowing, adapter separation, lifetimes, caching, revocation, re-exchange |
| `policy.test.ts` | 7 | Policy table completeness, write budgets on MCP and REST, the audit actor chain |
| `dpop.test.ts` | 7 | DPoP proofs: every claim, the nonce, replay, key mismatch, private keys refused |
| `passkeys.test.ts` | 7 | Real WebAuthn ceremonies with a software authenticator: phishing RP IDs and origins, replayed challenges, cloned counters, recent sign-in, CSP |
| `split.test.ts` | 7 | Profile M over real mTLS: introspection, exchange, certificate-bound internal tokens, the allowlist, failing closed |
| `oauth-refresh.test.ts` | 6 | Concurrent refresh, the grace window, theft, single-use codes |
| `kms.test.ts` | 6 | Envelope-encrypted keys, KMS-held signing, refusing to start on a bad key file, rotation |
| `account.test.ts` | 5 | Connected apps, disconnecting, sign out everywhere, password change |
| `chatgpt-challenge.test.ts` | 5 | The tool-level challenge and `securitySchemes` |
| `normalize.test.ts` | 5 | The folds |
| `observability.test.ts` | 5 | No token reaches a log line; refresh and DPoP counters; alerts; Prometheus format |
| `accounts.test.ts` | 4 | Sign-up rules, username folding, password checks |
| `contention.test.ts` | 4 | Fifty concurrent refreshes, code redemptions, switches and creates |
| `device-service.test.ts` | 4 | Internal token verification, `alg: none` and key confusion, no adapter bypass |
| `tokens.test.ts` | 4 | Token format, keyed-hash storage, pepper rotation |
| `hosts.test.ts` | 3 | Each surface answers only on its own origin |
| `mcp-limits.test.ts` | 3 | Limits keyed by address until a token verifies, then by grant |
| `oauth-limits.test.ts` | 3 | Authorization page views, CIMD fetch budget, document cache lifetimes |
| `db-outage.test.ts` | 2 | A database that is down, or drops a connection, is a fast 503 and the pool recovers |
| `password.test.ts` | 2 | Peppered Argon2id; a hash of the bare password never matches |
| `persistence.test.ts` | 1 | Survival across a restart |
| `split-processes.test.ts` | 1 | Profile M as four real processes on PostgreSQL and Redis |

---

## The acceptance report

```bash
npm run acceptance
```

```
32 proven, 12 partial, 3 open   (279 tests ran, 270 passed, 9 skipped)
```

It maps each criterion in requirement §12 to the tests that establish it.
Evidence is matched as a distinctive fragment of a test name, and **each
fragment must match exactly one test** — so renaming a test drops its
criterion loudly rather than quietly. It exits non-zero if evidence goes
missing, becomes ambiguous, or starts failing. A criterion whose evidence
needs PostgreSQL or Redis is reported partial until it has run on them.

**It cannot print all green, and that is the point.** Some criteria need a
host account or a physical device, and the report names what each is missing
rather than letting a green suite imply the product is finished:

| | Missing |
| --- | --- |
| AC-13, AC-14, AC-17 | Claude on iPhone; recorded for Claude and ChatGPT on the web and Android |
| AC-19, AC-20, AC-38 | A real iPhone, and its Secure Enclave; iPad, which nothing exercises |
| AC-23 | That a host *enforces* the policy we declare |
| AC-27 | Whether a host asks again in a new conversation |
| AC-28 | How many rows fit in an inline card on a phone |
| AC-39 | An Apple Developer team, for the universal-link callback |
| AC-45 | A platform passkey on a real device |

The host observations are in [host compatibility](./host-compatibility.md).

---

## Load and failover

Run with `npm run load` against a server on PostgreSQL 17 and Redis 7 in local
containers, with the server and the load generator on the same laptop. The
numbers are for comparison between runs, not capacity planning.

| Run | Result |
| --- | --- |
| Profile S, 100 hosts at 4 requests a second for 60 s | 403 requests/s, no failures. p50 9–15 ms, p95 205–228 ms, p99 under 415 ms. At 25 hosts p95 is 25–36 ms: the tail at 100 is queueing in one Node process that shares the CPU with the load generator. The requirement's target (§11) is p95 under 1 s. Internal-token cache hit rate 98.4% |
| Profile M, the same load against four processes over mTLS | 410 requests/s, no failures, p95 25–40 ms, p99 under 100 ms. Introspection cache hit rate 95%, exchange cache 97.9% |
| Redis stopped for 26 s under 200 requests/s (profile S and M) | Every request during the outage got a 503; none was served. Refusals were fast (p95 16–20 ms) and traffic recovered by itself within 5 s of Redis returning. A revocation still crossed processes in 10 ms afterwards: the subscriber resubscribes |
| PostgreSQL stopped under load | Every request during the outage got a fast 503 (p95 23 ms), with no stalled interval, 26 log lines, and recovery within 5 s |

`LOAD_TIMELINE=<seconds>` prints status counts per interval, which is how the
outage runs were read. The load tool paces itself: the MCP endpoint allows 600
requests a minute per grant, so an unpaced loop measures the rate limiter, not
the service. Rate-limited answers are reported apart from failures. Run the
server with `WRITE_BUDGETS=report`, or the per-device budget refuses most of
the load's switches.

---

## The harnesses

### `npm run client-check`

Connects using the **official MCP SDK client** rather than driving endpoints
directly. Discovery, registration, PKCE, the token exchange and bearer
attachment are all its code, not ours. It stands in for the person only where
a real client opens a browser.

Everything else proves the endpoints behave as intended, but not that a real
client can navigate them. A client validates `structuredContent` against a
tool's declared `outputSchema` whenever present — **including on an error
result** — and only a real client shows what that does to an error.

### `npm run host-check`

Opens a tunnel, starts the server with the tunnel's origin as its public URL,
verifies the discovery chain and the `401` challenge over real HTTPS, and
prints the connector URL with a checklist. Everything capable of failing
without a host has already failed by the time that URL is pasted anywhere.

`BASE_URL` must match the registered connector URL exactly — it becomes the
OAuth issuer, the RFC 8707 resource indicator and the token audience — and
hosts cache discovery documents **globally by URL** for minutes, so a changing
hostname produces stale-cache behaviour that reads like a code bug.
`UI_DIAGNOSTICS=1` adds a panel to the device list showing what the host sent.

### `node tools/mock-host/run.mjs`

A mock MCP Apps host: implements the bridge protocol, proxies tool calls to a
running server, and renders any view in an iframe with a live message log.
It is the way to look at a view and watch its messages, which unit tests of
the bridge cannot show.

---

## What each layer cannot prove

**Unit and integration tests** drive the endpoints directly. They cannot prove
a real client navigates them; that is what `client-check` is for.

**PGlite serialises queries.** On it, the concurrency tests prove the logic is
correct when two callers start from the same observed state. `npm run test:pg`
runs the same tests under genuine row-level contention.

**The mock host is not a host.** It implements the protocol faithfully but
makes its own choices about approval, sizing and display modes. It cannot tell
you how many rows fit in an inline card on a real phone.

**The simulator is not a device.** AC-19 asks for a real iPhone.

---

## Testing conventions

- **A test name is a claim.** `a stale version is a tool error, not a
  transport error` says what must be true. Prefer that to `test control 409`.
- **Comments say why, not what.** Where a test guards against a specific
  failure, the comment describes it and its consequence.
- **Assert on what must *not* happen.** The strongest tests here check that no
  inverse command was sent, that nothing was mutated, that no second code was
  minted.
- **Reproduce before fixing.** A defect is demonstrated against a running
  server, and captured in a test, before a line changes.
