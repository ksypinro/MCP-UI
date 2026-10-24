# Host compatibility

How Claude and ChatGPT behave with IoT Switch, observed against a running
server, not inferred from documentation.

**Verified 24 October 2026** on Claude web, Claude Android, ChatGPT web and the
ChatGPT Android app. **Not yet run on iPhone** (Claude iOS).

Cells marked *not recorded* were not observed. Only observations go in this
document.

## Running the check

```bash
cd server && npm run host-check
```

That opens a tunnel and starts the server with the tunnel's origin as its
public URL. It then verifies the whole discovery chain over real HTTPS and
prints the connector URL. Everything that can fail without a host fails before
a host is involved.

`UI_DIAGNOSTICS=1` adds a panel to the device list. It shows the build, a
random id for that copy of the view, the window and content size, and the
names of the messages the host sent.

The server starts with no devices. Ask the assistant to add six ("Add 6 devices
named Lamp 1 to Lamp 6"), so the list has more rows than the inline card shows.

| | |
| --- | --- |
| Tunnel | ngrok, a fixed domain |
| Claude | An organisation account; web, and the Android app. App versions *not recorded* |
| ChatGPT | Plus; web, and the Android app. App version *not recorded* |
| Phone | Android; version *not recorded* |

---

## Q1: How does signing in start?

| Host | Our auth card rendered before connecting? | What starts sign-in | Notes |
| --- | --- | --- | --- |
| Claude web | **No** | Claude's own card: "Connectors that could help: IoT Switch, **Connect**". Pressing it opens our hosted page in the browser | While disconnected, Claude does not offer the server's tools at all, public ones included, so `show_auth` cannot be called |
| ChatGPT web | **No** | Connector setup. ChatGPT authorizes (OAuth) when the connector is added, and opens our hosted page in the browser for Log In | The connector is created without authentication, then authorized on first connection |

Neither host shows an in-chat sign-in card of ours before the first
connection. Both route the person to our hosted page through their own
Connect, which is the required path in requirement §7.4. The auth card is the
cosmetic entry point §7.4 describes. *Whether the card's own Log In raises a
Connect prompt after a connection has lapsed: not recorded.*

## Q2: How much of a device list fits in an inline card?

The device list shows four rows inline (`INLINE_ROW_BUDGET`, Claude's
published guidance), then "N more devices not shown here" and **Show all**.

| Host | Rows shown inline | Room for more? |
| --- | --- | --- |
| Claude web | 4 | **Yes**: empty space below the four rows |
| Claude Android | 4 | *not recorded* |
| ChatGPT web | 4 | *not recorded* |
| ChatGPT Android | 4 | *not recorded* |

Four is conservative on a desktop browser. A phone is where the budget
binds, and no phone measurement has been taken, so it stays at four. The
diagnostics panel reports window and content height for that measurement.

## Q3: Does fullscreen work?

| Host | Fullscreen granted? | All six devices shown? |
| --- | --- | --- |
| Claude web | Yes | Yes |
| Claude Android | Yes | Yes |
| ChatGPT web | Yes | Yes |
| ChatGPT Android | Yes | Yes |

Hosts differ in how they report the change, and the view relies on two rules
from MCP Apps 2026-01-26:

- **The reply to `ui/request-display-mode` is the mode actually set.** Claude
  web and the ChatGPT Android app report fullscreen in the reply, not only in a
  later notification.
- **`host-context-changed` carries only the fields that changed.** Claude web
  follows the grant with an update that carries only new dimensions. The
  bridge merges updates; replacing the whole context would lose the display
  mode.

**Hosts cache view templates by URI, across a disconnect and reconnect.** Every
view URI therefore carries a hash of its content
(`ui://iot/devices.e824b396.html`). Changed code is a new URI, which every host
fetches.

*Whether closing fullscreen returns to the conversation: not recorded.*

## Q4: What approval does a write require?

| Host | Before using the server | Switch flipped in the card |
| --- | --- | --- |
| Claude web | *not recorded* | **No confirmation**: the device changed from Off to On at once |
| Claude Android | *not recorded* | No confirmation observed |
| ChatGPT web and Android | **Asked once**, before first using the MCP server | **No confirmation** for actions inside the card |

ChatGPT documents per-write confirmation for developer mode. That is not what
happens for actions inside the card. Neither host confirms individual switch
flips, so the server's write budgets (`WRITE_BUDGETS`) are the per-write
ceiling a person does not have to opt into. *Whether ChatGPT asks again in a
new conversation, and whether either host confirms model-initiated writes such
as "add a device": not recorded.*

## Q5: Does the connector reach the phone?

| Question | Claude | ChatGPT |
| --- | --- | --- |
| Added on the web, then usable in the Android app? | Yes | **Yes** |
| Does the device card render on the phone? | Yes | Yes |
| Do switches work on the phone? | Yes | Yes |
| Anything degraded compared with the web? | No | No |
| iPhone | Not tested | Not tested |

Setup is web-only on both hosts. Once added, the connector works in both
Android apps.

## Q6: Does OAuth complete, and how does each host register?

Read from the server's database after the session, not from the screen.

| Host | Registration | client_id | Flow completed | Token audience |
| --- | --- | --- | --- | --- |
| Claude | **CIMD** | `https://claude.ai/oauth/mcp-oauth-client-metadata` | Yes | `…/mcp` |
| ChatGPT | **CIMD** | `https://chatgpt.com/oauth/client.json` | Yes | `…/mcp` |

Both hosts requested and received all three device scopes. Neither fell back to
dynamic registration. One account worked across both hosts: devices added
through Claude were switched from both, and every change was audited with the
right client. Both client_ids are in the default `KNOWN_CLIENTS`, so both are
shown as **Verified** on the consent page.

---

## Open

- Claude on iPhone (AC-13, AC-17, AC-19).
- A phone measurement of the inline row budget (AC-28).
- Whether hosts ask again in a new conversation (AC-27).
