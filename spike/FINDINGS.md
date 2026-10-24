# Host verification findings

**Status: run on 24 October 2026 against Claude web, Claude Android, ChatGPT
web and the ChatGPT Android app. Not yet run on iPhone (Claude iOS).**

**To repeat it:**

```bash
cd ../server && npm run host-check
```

That opens a tunnel, starts the server told the origin it is reachable at,
verifies the whole discovery chain over real HTTPS, and prints the connector
URL. Everything that can fail without a host will have failed before you
involve one. Setting `UI_DIAGNOSTICS=1` adds a panel to the device list
showing the build, a random id for that copy of the view, and the names of the
messages the host sent it: that is how Q3 below was diagnosed rather than
guessed.

The server starts with no devices. Ask the assistant to add six ("Add 6 devices
named Lamp 1 to Lamp 6") so the list has more rows than the inline card shows.

Nothing here may be filled in from expectation, only from observation. An
unanswered question is a better outcome than a guessed one: cells marked
*not recorded* were not observed.

## Provenance

| | |
| --- | --- |
| Date | 24 October 2026 |
| Server | `main` at `b07a722`, then `fix/views-fullscreen-on-claude-web` (PR #18) for the Q3 re-test |
| Tunnel | ngrok, a fixed free domain |
| Claude | An organisation account (the connector was "in your org"); Team or Enterprise *not recorded*. Web, and the Android app; app versions *not recorded* |
| ChatGPT | Plus. Web, and the Android app; app version *not recorded* |
| Phone | Android; version *not recorded* |
| iPhone | Not used |

---

## Q1 — How does signing in start?

The design assumed a host would render our `show_auth` card while signed out,
and that pressing Log In on it would raise the host's Connect prompt.

| Host | Our auth card rendered before connecting? | What started sign-in | Notes |
| --- | --- | --- | --- |
| Claude web | **No** | Claude's own card: "Connectors that could help — IoT Switch — **Connect**". Pressing it opened our hosted page in the browser | While disconnected, Claude does not offer the server's tools at all, public ones included, so `show_auth` cannot be called |
| ChatGPT web | **No** | Connector setup: ChatGPT connects (OAuth) when the connector is added, and opened our hosted page in the browser for Log In | The connector is created without authentication, then authorized on first connection |

**Finding:** neither host uses an in-chat sign-in card of ours before the
first connection. Both route the person to our hosted page through their own
Connect affordance, which is the required path in §7.4 and works. The auth card
is decorative before connection on both hosts. *Whether the card's own Log In
raises a Connect prompt after a connection has lapsed: not recorded.*

---

## Q2 — How much of a device list survives an inline card?

The device list shows four rows inline (`INLINE_ROW_BUDGET`, published
guidance), then "N more devices not shown here" and **Show all**.

| Host | Rows shown inline | Room for more? | Notes |
| --- | --- | --- | --- |
| Claude web | 4 | **Yes**: empty space below the four rows | The budget is cautious on a desktop browser |
| Claude Android | 4 | *not recorded* | |
| ChatGPT web | 4 | *not recorded* | |
| ChatGPT Android | 4 | *not recorded* | |

**Finding:** four is conservative on the web. A phone is where the budget
binds, and no phone measurement was taken, so the budget stays at four until
one is. `UI_DIAGNOSTICS=1` reports window and content height for that.

---

## Q3 — Does fullscreen work?

| Host | Fullscreen granted? | All six devices shown? | Notes |
| --- | --- | --- | --- |
| Claude web | Yes | **No, then yes after the fix** | Fullscreen frame with its own header and close button, but the card still listed four and offered Show all again |
| Claude Android | Yes | Yes | Worked before the fix |
| ChatGPT web | Yes | Yes | Worked before the fix |
| ChatGPT Android | Yes | **No, then yes after the fix** | Same symptom as Claude web |

**Two defects in our view, both fixed (PR #18):**

1. The bridge ignored the host's answer to `ui/request-display-mode`, which
   is the mode actually set, and replaced its whole host context with each
   `host-context-changed`, although that notification carries only the fields
   that changed. So a host that reported fullscreen in the reply, or sent a
   later update without the display mode, left the card thinking it was
   inline. The hosts where it worked happened to send everything at once.
2. Hosts cache view templates by URI, across a disconnect and reconnect. The
   first fix was invisible on Claude web until every view URI carried a hash
   of its content (`ui://iot/devices.e824b396.html`). Any change to a view
   would otherwise never reach a host.

With both fixes, all six devices showed in fullscreen on Claude web and on
the ChatGPT Android app. *Whether closing fullscreen returns to the
conversation: not recorded.*

---

## Q4 — What approval does a write require?

| Host | Before using the server | Switch flipped in the card | Notes |
| --- | --- | --- | --- |
| Claude web | *not recorded* | **No confirmation**: the device changed from Off to On at once | |
| Claude Android | *not recorded* | No confirmation observed; the switch worked | |
| ChatGPT web and Android | **Asked once**, before it first used the MCP server | **No confirmation** for interactions inside the card | ChatGPT documents per-write confirmation for developer mode; that was not what happened for in-card actions |

**Finding:** in practice neither host confirmed individual switch flips from
inside the card. The server's write budgets (`WRITE_BUDGETS`) are therefore
the only per-write ceiling a person did not have to opt into, which is what
they were built for. *Whether ChatGPT asks again in a new conversation, and
whether either host confirms model-initiated writes ("add a device"): not
recorded.*

---

## Q5 — Does the connector reach the phone?

| Question | Claude | ChatGPT |
| --- | --- | --- |
| Added on the web, then usable in the Android app? | Yes | **Yes** |
| Does the device card render on the phone? | Yes | Yes |
| Switches work on the phone? | Yes | Yes |
| Anything degraded versus the web? | No | Show all (Q3), fixed |
| iPhone | Not tested | Not tested |

**Finding:** the spec expected ChatGPT custom connectors to be web-only. Setup
is web-only, but once added the connector worked in the ChatGPT Android app.
§2, §10.3, AC-14 and §14 decision 3 are corrected accordingly.

---

## Q6 — Does OAuth complete, and how does each host register?

Read from the server's database after the session, not from the screen.

| Host | Registration used | client_id | Flow completed | Token audience correct | Notes |
| --- | --- | --- | --- | --- | --- |
| Claude | **CIMD** | `https://claude.ai/oauth/mcp-oauth-client-metadata` | Yes | Yes (`…/mcp`) | Two grants: one used once at 19:26, then a second at 19:33. Probably a second Connect; harmless, and both are listed on the connected-apps page |
| ChatGPT | **CIMD** | `https://chatgpt.com/oauth/client.json` | Yes | Yes (`…/mcp`) | Shown as **Verified** on the consent page |

Both hosts requested and received all three device scopes. Neither fell back to
dynamic registration. One account (`hosttest`) worked across both hosts: six
devices added through Claude, switched from both, and every change audited
with the right client.

Claude appeared as **Unverified** on the consent page, because only ChatGPT's
client_id was on the known list. Claude's is now in the default
`KNOWN_CLIENTS`.

---

## Anything unexpected

- **Stale views.** Hosts kept running an old copy of a view across a
  disconnect and reconnect. Fixed by fingerprinting view URIs (Q3).
- **Each host started sign-in its own way,** and neither the way §7.4
  pictured (Q1).
- **ChatGPT on the phone.** Out of scope on paper, working in practice (Q5).
- **No per-write prompts** for in-card switches on either host (Q4).

---

## Decision

- [x] **Does ChatGPT stay in scope?** Yes. Its connector works on the web and
  in the Android app (spec §14 decision 3, resolved).
- [x] **Does `devices.html` ship inline summary plus fullscreen?** Yes. With
  PR #18, fullscreen showed the whole list on all four surfaces tested.
- [x] **Does the auth card stay?** It stays as the cosmetic entry point §7.4
  already calls it, but neither host renders it before connecting. The
  required path is the host's own Connect, which works on both.
- [x] **Do any acceptance criteria need rewriting?** AC-13 and AC-14, done.
  AC-17, AC-27 and AC-28 now record what was observed and what remains.
- [ ] **Still open:** Claude on iPhone (AC-13, AC-17, AC-19), a phone
  measurement of the inline row budget (AC-28), and whether hosts re-prompt in
  new conversations (AC-27).
