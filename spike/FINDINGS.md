# Phase 0 findings

**Status: not yet run against a host.**

**Run these against `../server`, not against this spike** — phases 3 and 4
replaced the spike's stub backend with the real one. The two exceptions are Q2
and Q3, which need the spike's `ui://` resources because the real server has
none until phase 5. See [README.md](./README.md) for which is which.

Everything below requires a human with a Claude account, a ChatGPT account on a
paid plan, and an iPhone. Nothing here may be filled in from expectation — only from
observation. An unanswered question is a better outcome than a guessed one.

Record for each host: app version, account plan, and test date. Section 12 of
`../requirement.md` requires that provenance, and a finding without it cannot
be acted on six weeks later.

---

## Q1 — Does an app-initiated tool call raise the host's Connect prompt?

The whole authentication design assumes yes: the auth card calls `list_devices`,
the server answers `401`, and the host runs OAuth and retries. The MCP Apps
authorization guidance says the host "handles it transparently", but that text
describes the protocol, not any particular host's UI.

*How:* connect while signed out, ask the assistant to sign in to IoT Switch, and
press **Log In** on the card. Watch the bridge log in the card.

| Host | Connect prompt appeared? | Call retried after auth? | Notes |
| --- | --- | --- | --- |
| Claude web | | | |
| Claude iOS | | | |
| ChatGPT web | | | |

**If no:** section 7.4 needs rewriting. The fallback is that only a
model-initiated call can trigger authentication, which makes the auth card
decorative and the honest entry point a sentence of instruction to the user.

---

## Q2 — How much of a device list survives an inline card?

Twelve devices are seeded deliberately. The card's diagnostics panel reports
content height against viewport height and prints how many pixels are cut off.

| Host | Viewport | Content | Rows reachable | Inline scroll works? |
| --- | --- | --- | --- | --- |
| Claude web | | | | |
| Claude iOS | | | | |
| ChatGPT web | | | | |

On a phone the conversation is expected to own vertical scrolling, so a pan
starting inside the card scrolls the chat instead of the list.

**If rows are unreachable:** section 9.3's requirement stands and `devices.html`
must ship as a bounded summary that escalates to fullscreen. Record the number
of rows that *do* fit — that is the real design budget, and it should be written
into the spec rather than guessed.

---

## Q3 — Does `ui/request-display-mode: fullscreen` work?

Press **Request fullscreen** on the card.

| Host | Granted? | Usable on a phone? | Close returns to conversation? |
| --- | --- | --- | --- |
| Claude web | | | |
| Claude iOS | | | |
| ChatGPT web | | | |

**If refused on mobile:** Q2's fallback disappears with it, and the device list
inside a host becomes a genuinely constrained surface. Say so in the spec rather
than designing around a capability that is not there.

---

## Q4 — What approval does a write require?

Toggle a switch in the card.

| Host | Prompt per write? | Remembered within a conversation? | Across conversations? | Time added |
| --- | --- | --- | --- | --- |
| Claude web | | | | |
| Claude iOS | | | | |
| ChatGPT web | | | | |

ChatGPT documents that write actions require confirmation by default and that
new conversations prompt again.

**If every flip needs a confirmation:** a switch is the wrong control for that
host. Consider an explicit Apply button so one approval covers one intended
change, and record the latency the prompt adds — section 11's 200 ms target
measures our own pending indicator, not the human in the loop.

---

## Q5 — Does the connector reach the phone at all?

| Question | Claude | ChatGPT |
| --- | --- | --- |
| Added on web/desktop, visible on iOS? | | |
| Does the MCP App render on iOS? | | |
| Anything degraded versus web? | | |

Expected: Claude yes, ChatGPT no. If ChatGPT surprises us, section 2 of the spec
and decision 3 in section 14 both change.

---

## Q6 — Does OAuth complete from each surface?

| Host | Registration used | Flow completed | Token audience correct | Notes |
| --- | --- | --- | --- | --- |
| Claude web | CIMD / DCR / pre-reg | | | |
| Claude iOS | | | | |
| ChatGPT web | | | | |

Watch the server log for which `client_id` arrives: an HTTPS URL means CIMD, a
`client_*` value means the host fell back to dynamic registration.

---

## Anything unexpected

Host bugs, confusing copy, surprising ordering, anything that cost time. This
section is usually the most valuable one and is usually left empty.

---

## Decision

Once Q1–Q6 are answered, resolve these before phase 1 starts:

- [ ] Does ChatGPT stay in scope? (spec section 14, decision 3)
- [ ] Does `devices.html` ship inline-summary-plus-fullscreen, or fullscreen only?
- [ ] Does the auth card stay, or does section 7.4 lose it?
- [ ] Do any acceptance criteria in section 12 need rewriting?
