# IoT Switch — iOS app

The native client for spec section 5. iOS 18 and later. It signs in on the
server's hosted page through the system browser, and talks to `../server`
over the four device endpoints with DPoP-bound OAuth tokens.

## Run

```bash
cd ../server && npm start          # backend on :4000
```

```bash
xcodebuild -project IoTSwitch.xcodeproj -scheme IoTSwitch \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' test
```

Open `IoTSwitch.xcodeproj` to run the app. It points at `http://localhost:4000`
by default. Launch arguments aim it elsewhere, which is how it gets pointed at
a tunnel or a logging proxy:

- `-apiBaseURL http://…`: the REST API;
- `-authBaseURL http://…`: the authorization server, if it is on another origin;
- `-authCallbackHost app.iot.example`: use the universal-link callback on that
  host instead of the custom scheme. This needs the associated-domains
  entitlement, which needs a signing team.

No CocoaPods, no SPM dependencies, no generated project — the `.pbxproj` is
checked in and uses synchronized folder groups, so adding a file to
`IoTSwitch/` is enough and there is no project file to merge-conflict over.

## Layout

```
IoTSwitch/
  Auth/          PKCE, DPoP keys and proofs, the browser sheet
  Models/        Device, Account, token responses, APIError
  Networking/    APIClient protocol + HTTP implementation
  Session/       Keychain storage, SessionController
  ViewModels/    the state machines
  Views/         SwiftUI screens
```

The rule worth keeping: **views hold no logic and no network calls.** Every
decision lives in a view model, which is why the switch behaviour in section
5.6 can be tested exhaustively without a simulator UI test.

## Signing in

The app never sees a password. **Log In** and **Sign Up** do the same thing,
with a hint:

1. Make a PKCE pair and a random `state`, and get the DPoP key's thumbprint.
2. `POST /par` with all of it (`prompt=create` for Sign Up). The server keeps
   the request and returns a `request_uri` that works once, for 60 seconds.
3. Open `/authorize?client_id=iot-switch-ios&request_uri=…` in an ephemeral
   `ASWebAuthenticationSession`. The person signs in or signs up there, with
   the browser's own autofill and password manager.
4. On the callback, check `iss` against the expected issuer first, then
   `state`. A mismatch on either is refused.
5. `POST /token` with the code, the verifier and a DPoP proof. The tokens come
   back bound to the key.

**The key.** `DPoPKeyring` keeps one P-256 key, created in the Secure Enclave
and never exportable. The Keychain holds only an opaque handle to it. The
Simulator has no Secure Enclave, so there it falls back to a software key with
the same interface. Every request carries `Authorization: DPoP <token>` and a
fresh proof: method, URL, a hash of the token, and the server's nonce. If the
server asks for a new nonce, the request is retried once with it.

**The tokens.** The access token lives only in memory, for 10 minutes. The
refresh token lives in the Keychain (`AfterFirstUnlockThisDeviceOnly`, not
synchronised) and is useless without the key. Refresh happens before a request
once a quarter of the access token's life is left, and once only, however many
requests want it. The session ends only when the server rejects the refresh
token; a network failure or a rate limit keeps it.

**Log out** revokes the grant, clears the Keychain and throws the key away, so
the next sign-in starts from a new key.

## The switch, which is the whole app

`DeviceControlService` implements section 5.6 once, and both the list and the
detail screen use it — section 5.4 requires them to behave identically, and two
copies of a state machine do not stay identical.

Three outcomes deserve attention:

- **Version conflict.** The device is refetched and the user is told what it
  actually is, not merely that they were too late.
- **Unknown outcome.** A mutation that fails in transit may or may not have
  applied. The client reads the device before offering a retry and **never**
  sends the inverse command — that is how a switch ends up flipping itself
  back. `APIError.unknownOutcome` exists solely to keep this case from being
  mistaken for an ordinary failure.
- **Pending intent is not state.** An unconfirmed change never becomes the
  displayed truth; the row shows "Changing to On…" and the switch for that one
  device is inert until the backend answers.

## Verified against the real backend

Beyond the 60 unit tests, the core flows were driven in the Simulator against
a running server on 18 October 2026: sign-up on the hosted page, the callback,
the DPoP-bound code exchange, the empty state, add device, switching it On
(version 1 → 2), and log out. The server's database showed one `iot-switch-ios`
grant, bound to a key, and revoked on logout.

Notes for anyone repeating that:

- A synthetic tap with no duration does not actuate a `UISwitch`. Use a press
  of ~0.15s or a short swipe, or the toggle appears dead while every other
  control works.
- On the hosted sign-up page, Safari offers its "Use Strong Password?" sheet,
  which swallows typed characters until dismissed. That is the page's
  `autocomplete="new-password"` doing its job.

## Known gaps

- Code signing is ad-hoc (`CODE_SIGN_IDENTITY = "-"`). Without a signed bundle
  the app has no keychain entitlement, `SecItemAdd` fails, and the session
  silently does not survive a relaunch. A real distribution build needs a real
  team and identity.
- The callback is the custom scheme `com.example.iotswitch:/oauth/callback`.
  The universal link on the API host is ready on the server (it publishes the
  app-site association once `APPLE_TEAM_ID` is set), but the app needs the
  associated-domains entitlement, and so a signing team, first.
- The Secure Enclave path runs only on a physical device. The Simulator
  exercises the software fallback.
- iPad renders correctly but the layout is the iPhone one scaled up; section
  5.1's "appropriately sized presentation on iPad" is not implemented.
- No UI tests. The view models are covered; the views are not.
