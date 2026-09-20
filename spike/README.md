# Phase 0 — host feasibility spike

Throwaway. This is not the product and none of it should survive into phase 1.

Its only job is to answer the questions in [FINDINGS.md](./FINDINGS.md) before
the native app is built, because the answers can change the scope of phases
1–6. See section 13 of `../requirement.md`.

## What it is

A single Node process that is, at once:

- an **MCP server** over Streamable HTTP, with three protected device tools and
  three public ones;
- a stub **OAuth 2.1 authorization server** — PKCE S256, RFC 9728 protected
  resource metadata at both well-known paths, RFC 8707 resource indicators
  bound into the token audience, RFC 9207 `iss`, CIMD and DCR;
- two **MCP App** UI resources, one of which reports what the host actually
  tells it.

Everything is in memory. Restarting drops all accounts and devices, which is
fine and intentional: signing up again takes five seconds and seeds twelve
devices.

## Run it

```bash
npm install
npm start
```

Then, in another shell, prove the server is correct before involving any host:

```bash
node smoke.mjs
```

46 assertions covering discovery, anonymous access, the 401 challenge, the
full authorization-code flow, control semantics, cross-account isolation,
audience binding, and scope step-up. If this fails, no host was ever going to
work; fix it here, where the feedback loop is seconds rather than minutes.

## Expose it

Hosts reach connectors from their own infrastructure, so `localhost` is not
reachable. Tunnel it and tell the server its public origin:

```bash
cloudflared tunnel --url http://localhost:3000
```

```bash
BASE_URL=https://your-tunnel-hostname.trycloudflare.com npm start
```

`BASE_URL` must exactly match the URL you register as the connector. It becomes
the OAuth issuer, the RFC 8707 resource indicator, and the token audience. It
also matters more than it looks: hosts cache discovery documents **globally by
URL** for several minutes, so restarting with a new tunnel hostname mid-session
produces stale-cache behaviour that reads like a code bug and is not one. If
you can, use one stable hostname for the whole exercise.

## Connect it

**Claude.** Settings → Connectors → Add custom connector, with the tunnel's
`/mcp` URL. Do this on web or desktop: a custom connector must be added there
before it appears on mobile. Then open the *same conversation* on an iPhone —
that is the half of the test that matters.

**ChatGPT.** Settings → Connectors → Advanced → Developer mode, then add the
same `/mcp` URL. Web only; this cannot be done in the mobile app.

Then, in a conversation: *"Sign in to IoT Switch"* → *"Show my devices"* →
toggle a switch in the card.

## What to watch

The device card renders a diagnostics panel and a live bridge log. The line to
watch is **fits inline?** — it compares content height against the iframe
viewport and reports how many pixels are cut off. On a phone that number is the
answer to whether a device list can be an inline card at all.

Record everything in FINDINGS.md as you go. Screenshots are worth more than
recollection.
