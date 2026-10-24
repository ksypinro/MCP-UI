# Contributing

Thanks for looking. This document is short on ceremony and specific about the
few things that matter here.

---

## Getting set up

```bash
cd server
npm install
npm test             # 279 tests, nothing to provision
npm run test:pg      # the same on PostgreSQL 17 and Redis 7
npm run typecheck
```

Node 22+ (25 recommended — it runs TypeScript directly, so there is no build
step). Xcode 16+ only if you are touching the iOS app.

```bash
cd ios
xcodebuild -project IoTSwitch.xcodeproj -scheme IoTSwitch \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' test
```

Start with [Architecture](./docs/architecture.md) and
[Code flow](./docs/code-flow.md). The "Where to change things" table at the
end of the latter is the fastest way to find a file.

---

## Before you open a pull request

```bash
cd server
npm test
npm run typecheck
npm run acceptance     # must stay green
```

`npm run acceptance` maps the acceptance criteria in
[`requirement.md`](./requirement.md) §12 to the tests that establish them. It
fails if a criterion's evidence goes missing, becomes ambiguous, or starts
failing — so **renaming a test can break it**. If you rename one, update
`server/acceptance/criteria.ts` in the same change.

---

## The rules that are load-bearing

Most conventions here are ordinary. These five are not, and breaking one
tends to produce a bug that passes the whole suite.

### 1. Business rules live in `domain/`, once

The REST API and the MCP tools are adapters. They verify a credential,
exchange it for an internal token, call the Device Service, and translate a
result. They do not validate names, check ownership or compare versions.

A rule implemented in an adapter is a rule the other surface does not have.

### 2. Let the database decide races

`UNIQUE (owner_id, normalized_name)` is what prevents a duplicate device.
`UPDATE … WHERE version = $expected` is what prevents a lost update. Neither
is a check in application code, because application code loses races.

Creation uses `ON CONFLICT DO NOTHING` rather than catching a unique
violation — on PostgreSQL a failed statement aborts the transaction and leaves
nothing usable to continue with.

### 3. Never write a side effect inside a transaction that is about to abort

Three places depend on this:

- the audit record of a rejected write, which the rollback carrying the
  rejection would erase;
- refresh-token reuse detection, whose revocation the aborting transaction
  would undo, so a detected theft would revoke nothing;
- a grant and its first tokens, which must be created together or not at all.

If something must survive a refusal, do it **after** the transaction, in its
own.

### 4. Authorization refusals are transport errors; everything else is not

| Failure | Shape |
| --- | --- |
| No token, insufficient scope | HTTP `401` / `403` with `WWW-Authenticate` |
| Conflict, duplicate, not found | `200` with `isError: true` |

A `200` carrying `isError` is an application failure: a host passes the text
to the model and moves on, and no authentication prompt appears. Only a
transport status makes a host authorize.

And error results carry **no** `structuredContent` — a client validates it
against the tool's declared `outputSchema` whenever present, including on
errors. Codes go in `_meta['iot/error']`.

### 5. Migrations are append-only

Add an entry to `MIGRATIONS` in `server/src/db/migrations.ts`. Never edit one
that has been applied anywhere.

---

## Tests

**A test name is a claim.** `a stale version is a tool error, not a transport
error` states what must be true. Prefer that to `test control 409`.

**Assert on what must not happen.** The strongest tests here check that no
inverse command was sent, that nothing was mutated, that no second code was
minted.

**Reproduce before fixing.** Demonstrate a defect against a running server
before changing a line, and give the regression test a comment saying what
goes wrong without it.

**Some things need a harness, not a unit test.** Tests that drive your own
endpoints cannot tell you whether a real client can navigate them:

- `npm run client-check` drives the server with the official MCP SDK client,
  which is what shows whether an error result is readable to a real client.
- `tools/mock-host` renders a view and logs its messages, which is what shows
  whether "Show all" actually goes fullscreen.
- `npm run host-check` puts the server in front of Claude or ChatGPT;
  record what you see in [`docs/host-compatibility.md`](./docs/host-compatibility.md).

If you are changing the bridge, the views, or anything a host consumes, use
them.

---

## Commits and pull requests

Explain **why**, not what — the diff already says what. Where a change fixes a
defect, describe the failure concretely enough that someone can picture it.

Keep a pull request to one coherent change. If you find something unrelated on
the way, note it rather than folding it in.

---

## Documentation

Update it in the same change, not afterwards:

- a new endpoint or tool → [`docs/architecture.md`](./docs/architecture.md)
  and the README's API tables
- anything about tokens, clients or keys →
  [`docs/authentication-architecture.md`](./docs/authentication-architecture.md)
- a new flow → [`docs/sequence-diagrams.md`](./docs/sequence-diagrams.md)
- moving where something happens → the "Where to change things" table in
  [`docs/code-flow.md`](./docs/code-flow.md)

If you discover a limit, record it in Architecture §10. A known gap written
down is worth more than a gap someone rediscovers.

---

## Things deliberately not in scope

Listed in [`requirement.md`](./requirement.md) §2.2: real hardware, additional
device states, schedules, device deletion or renaming, social login, push
notifications, offline queues. A pull request adding one of these needs the
specification changed first.

---

## Reporting a security issue

Please do not open a public issue. Contact the maintainer directly.

The security model is described in
[the authentication architecture](./docs/authentication-architecture.md),
including its threat model and risk-to-control matrix. Findings against the
OAuth server, the MCP authorization gate, token exchange, or the view sandbox
are especially welcome.
