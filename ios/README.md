# IoT Switch — iOS app (phase 2)

The native client for spec section 5. Talks to the phase 1 backend in
`../server` over the four device endpoints and the auth service.

## Run

```bash
cd ../server && npm start          # backend on :4000
```

```bash
xcodebuild -project IoTSwitch.xcodeproj -scheme IoTSwitch \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' test
```

Open `IoTSwitch.xcodeproj` to run the app. It points at `http://localhost:4000`
by default; pass `-apiBaseURL http://…` as a launch argument to aim it
elsewhere, which is how it gets pointed at a tunnel or a logging proxy.

No CocoaPods, no SPM dependencies, no generated project — the `.pbxproj` is
checked in and uses synchronized folder groups, so adding a file to
`IoTSwitch/` is enough and there is no project file to merge-conflict over.

## Layout

```
IoTSwitch/
  Models/        Device, Account, APIError
  Networking/    APIClient protocol + HTTP implementation
  Session/       Keychain storage, SessionController
  ViewModels/    the state machines
  Views/         SwiftUI screens
```

The rule worth keeping: **views hold no logic and no network calls.** Every
decision lives in a view model, which is why the switch behaviour in section
5.6 can be tested exhaustively without a simulator UI test.

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

Beyond the 44 unit tests, the core flows were driven in the simulator against a
running phase 1 server with a logging proxy in between:
sign-up, empty state, add device, control from both screens, session
persistence across a relaunch, and a genuine 409 conflict being reconciled.

Two notes for anyone repeating that:

- A synthetic tap with no duration does not actuate a `UISwitch`. Use a press
  of ~0.15s or the toggle appears dead while every other control works.
- On sign-up, iOS offers its "Use Strong Password?" sheet, which swallows typed
  characters until dismissed. That is `.textContentType(.newPassword)` doing
  its job — section 5.2 asks for autofill support — not a bug.

## Known gaps

- Code signing is ad-hoc (`CODE_SIGN_IDENTITY = "-"`). Without a signed bundle
  the app has no keychain entitlement, `SecItemAdd` fails, and the session
  silently does not survive a relaunch. A real distribution build needs a real
  team and identity.
- iPad renders correctly but the layout is the iPhone one scaled up; section
  5.1's "appropriately sized presentation on iPad" is not yet done.
- No UI tests. The view models are covered; the views are not.
