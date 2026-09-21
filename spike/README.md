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

All six run against [`../server`](../server) now. Phase 5 gave it the `ui://`
views, which were the only reason two of them previously needed this spike.

```bash
cd ../server && npm run host-check
```

**Do not use this spike's authorization server for anything.** It was always a
stub: in-memory, so every restart drops the accounts; no refresh grant, so
nothing can be learned here about token renewal; and no SSRF guard on the
client metadata fetch. Phase 3 replaced it with a real one. Any Q6 answer
gathered here would describe code that no longer exists.

`host-check` handles the tunnel and the origin for you. `BASE_URL` has to match
the URL you register as the connector exactly — it becomes the OAuth issuer,
the RFC 8707 resource indicator and the token audience — and hosts cache
discovery documents **globally by URL** for several minutes, so restarting with
a new hostname mid-session produces stale-cache behaviour that reads like a
code bug and is not one. A free ngrok tunnel gets a new hostname every restart;
use one stable hostname for the whole exercise if you can.

## Is any of this spike still useful?

Only as a record. Its stub backend is gone, its views are superseded by the
real ones, and `tools/mock-host` in the server is the better way to look at a
view without a host.

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
