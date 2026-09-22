# Testing and verification

202 automated tests, plus three harnesses for the things tests cannot reach.
This document explains what each layer proves — and, as importantly, what it
does not.

---

## The layers

| | Count | Command | What it establishes |
| --- | --- | --- | --- |
| Server | 155 | `npm test` | Domain rules, HTTP contract, OAuth, MCP protocol, views |
| iOS | 47 | `xcodebuild … test` | View-model state machines, session lifecycle, transport |
| Acceptance | 28 criteria | `npm run acceptance` | Which of §12 the suites actually establish |
| Client conformance | 18 checks | `npm run client-check` | That a compliant MCP client can find its way through |
| Host readiness | 9 checks | `npm run host-check` | That everything failable without a host has already failed |
| Views | manual | `node tools/mock-host/run.mjs` | What a view looks like and does |

---

## Running them

```bash
cd server
npm install
npm test                                   # 155
npm run typecheck
npm run acceptance                         # the criteria map

cd ../ios
xcodebuild -project IoTSwitch.xcodeproj -scheme IoTSwitch \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' test
```

The server suite needs nothing installed — PGlite is real PostgreSQL compiled
to WebAssembly, so there is no database to provision.

---

## Where the server tests live

| File | Tests | Covers |
| --- | --- | --- |
| `oauth.test.ts` | 36 | Discovery, the full flow, PKCE, code replay, rotation, revocation |
| `mcp.test.ts` | 24 | Anonymous access, the challenge, scopes, isolation, cross-surface |
| `mcp-ui.test.ts` | 21 | Resource shape, CSP, no tokens in views, inline budget |
| `api.test.ts` | 17 | Status codes, error codes, correlation ids |
| `devices.test.ts` | 15 | Ownership, versions, folding, the cap, auditing |
| `auth.test.ts` | 13 | Hashing, rotation, reuse detection, revocation |
| `mcp-bridge.test.ts` | 9 | The shared bridge, in a vm |
| `concurrency.test.ts` | 7 | AC-09 and AC-10 |
| `oauth-clients.test.ts` | 6 | CIMD, SSRF refusals, redirect rules |
| `normalize.test.ts` | 5 | The folds |
| `persistence.test.ts` | 1 | Survival across a restart |
| `mcp-limits.test.ts` | 1 | Anonymous traffic is bounded |

---

## The acceptance report

```bash
npm run acceptance
```

```
20 proven, 5 partial, 3 open   (155 tests ran, 155 passed)
```

It maps each criterion in §12 to the tests that establish it. Evidence is
matched as a distinctive fragment of a test name, and **each fragment must
match exactly one test** — so renaming a test drops its criterion loudly
rather than quietly. It exits non-zero if evidence goes missing, becomes
ambiguous, or starts failing.

**It cannot print all green, and that is the point.** Eight criteria need a
host account or a physical device, and the report names what each is missing
rather than letting a green suite imply the product is finished:

| | Missing |
| --- | --- |
| AC-13, AC-14, AC-17 | Whether a host renders the views, and completes the flow |
| AC-19, AC-20 | A real iPhone; iPad, which nothing exercises |
| AC-23 | That a host *enforces* the policy we declare |
| AC-27 | Whether every write is confirmed |
| AC-28 | How many rows survive an inline card |

Those close in [`spike/FINDINGS.md`](../spike/FINDINGS.md).

---

## The three harnesses

### `npm run client-check`

Connects using the **official MCP SDK client** rather than driving endpoints
directly. Discovery, registration, PKCE, the token exchange and bearer
attachment are all its code, not ours. It stands in for the person only where
a real client opens a browser.

This exists because everything else proves the endpoints behave as intended
but not that a real client can navigate them. It immediately found a bug
nothing else did: a client validates `structuredContent` against a tool's
declared `outputSchema` whenever present — **including on an error result** —
so every version conflict reached it as a protocol error rather than as the
conflict.

### `npm run host-check`

Opens a tunnel, starts the server told the origin it is reachable at, verifies
the discovery chain and the `401` challenge over real HTTPS, and prints the
connector URL with a checklist. Everything capable of failing without a host
has already failed by the time that URL is pasted anywhere.

`BASE_URL` must match the registered connector URL exactly — it becomes the
OAuth issuer, the RFC 8707 resource indicator and the token audience — and
hosts cache discovery documents **globally by URL** for minutes, so a changing
hostname produces stale-cache behaviour that reads like a code bug.

### `node tools/mock-host/run.mjs`

A mock MCP Apps host: implements the bridge protocol, proxies tool calls to a
running server, and renders any view in an iframe with a live message log.

It exists because the views cannot otherwise be looked at, and it earned its
place immediately. It found a handler-registry collision in the bridge that
every unit test passed over — "Show all" was granted fullscreen and then
redrew as if still inline, because a view listening for `host-context-changed`
had silently replaced the bridge's own handling of it.

---

## What each layer cannot prove

**Unit and integration tests** drive the endpoints directly. They cannot prove
a real client navigates them. Two interop bugs shipped past a fully green
suite for exactly that reason.

**PGlite serialises queries.** The concurrency tests prove the logic is
correct when two callers start from the same observed state; they do not prove
behaviour under genuine row-level contention. Everything above `src/db` is
written against a `Queryable` interface so that closing this gap is one file.

**The mock host is not a host.** It implements the protocol faithfully but
makes its own choices about approval, sizing and display modes. It cannot tell
you how many rows survive an inline card on a real phone.

**The simulator is not a device.** AC-19 asks for a real iPhone.

---

## Testing conventions

- **A test name is a claim.** `a stale version is a tool error, not a
  transport error` says what must be true. Prefer that to `test control 409`.
- **Comments say why, not what.** Where a test guards a specific past failure,
  the comment records it — several read as short incident reports, which is
  the most useful thing a regression test can carry.
- **Assert on what must *not* happen.** The strongest tests here check that no
  inverse command was sent, that nothing was mutated, that no second code was
  minted.
- **Reproduce before fixing.** Every defect in the history was demonstrated
  against a running server before a line changed.
