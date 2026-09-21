# Phase 0 — host feasibility spike

> **Mostly superseded.** Phases 3 and 4 replaced this spike's backend with the
> real one in [`../server`](../server). Use the real server for everything it
> now covers, and this spike only for the two questions it cannot answer yet.
> The split is in the table below.

Its job was always to answer the questions in [FINDINGS.md](./FINDINGS.md)
before more was built on assumptions. Those questions are still open — all
fifteen answer rows are blank — and they now gate phase 5's UI design rather
than phase 1. See section 13 of `../requirement.md`.

## Which server answers which question

| Question | Run against |
| --- | --- |
| Q1 — does an app-initiated `tools/call` raise the Connect prompt? | **`../server`**, but see the caveat below |
| Q2 — how much of a device list survives an inline card? | **this spike** |
| Q3 — does `ui/request-display-mode: fullscreen` work? | **this spike** |
| Q4 — what approval does a write require? | **`../server`** |
| Q5 — does the connector reach the phone at all? | **`../server`** |
| Q6 — does OAuth complete from each surface? | **`../server`** |

**Do not use this spike's authorization server for anything.** It was always a
stub: in-memory, so every restart drops the accounts; no refresh grant, so
nothing can be learned here about token renewal; and no SSRF guard on the
client metadata fetch. Phase 3 replaced it with a real one. Any Q6 answer
gathered here would describe code that no longer exists.

**Q1 has a caveat.** It asks whether a tool call made *from inside an MCP App*
raises the host's Connect prompt. The real server has the tools but not yet
the `ui://` resources — those are phase 5, deliberately, because their design
depends on Q2's answer. So against the real server you can only answer the
model-initiated half of Q1. The app-initiated half needs this spike's
`auth.html`, or phase 5.

## Running the real server

```bash
cd ../server && npm install && npm test     # 122 tests
```

Hosts reach connectors from their own infrastructure, so `localhost` is not
reachable. Tunnel it, and tell the server the origin it is reachable at:

```bash
ngrok http 4000
```

```bash
cd ../server && BASE_URL=https://your-tunnel-hostname npm start
```

`BASE_URL` must exactly match the URL you register as the connector. It becomes
the OAuth issuer, the RFC 8707 resource indicator, and the token audience.

It matters more than it looks: hosts cache discovery documents **globally by
URL** for several minutes, so restarting with a new hostname mid-session
produces stale-cache behaviour that reads like a code bug and is not one. A
free ngrok tunnel gets a new hostname every restart. If you can, use one stable
hostname for the whole exercise.

## Running this spike, for Q2 and Q3 only

```bash
npm install && npm start        # port 3000
node smoke.mjs                  # 46 assertions
```

Same tunnel story, on port 3000. The device card renders a diagnostics panel
and a live bridge log; the line to watch is **fits inline?**, which compares
content height against the iframe viewport and reports how many pixels are cut
off. On a phone that number is the answer to Q2, and it is the number phase 5's
`devices.html` should be designed around instead of the published guidance it
currently follows.

## Connecting a host

**Claude.** Settings → Connectors → Add custom connector, with the tunnel's
`/mcp` URL. Do this on web or desktop: a custom connector must be added there
before it appears on mobile. Then open the *same conversation* on an iPhone —
that is the half of the test that matters.

**ChatGPT.** Settings → Connectors → Advanced → Developer mode, then add the
same `/mcp` URL. Web only; this cannot be done in the mobile app.

Then, in a conversation: *"Sign in to IoT Switch"* → *"Show my devices"* →
*"Turn on the bedroom lamp"*.

## Two things that will waste your time if you do not know them

- A synthetic tap with **no duration does not actuate a `UISwitch`**, if you
  are driving a simulator rather than tapping yourself. Use ~0.15s. Every
  other control type responds to an instant tap, which makes the wrong
  explanation look convincing.
- On sign-up, iOS shows its **"Use Strong Password?"** sheet and swallows
  typed characters until dismissed. That is `.textContentType(.newPassword)`
  working as intended, not a bug.

Record everything in FINDINGS.md as you go. Screenshots are worth more than
recollection.
