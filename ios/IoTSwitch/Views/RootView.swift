import SwiftUI

struct RootView: View {
    let api: APIClient
    @EnvironmentObject private var session: SessionController

    var body: some View {
        Group {
            if session.isSignedIn {
                // The session is handed over as a value rather than read from
                // the environment inside DevicesView: SwiftUI cannot read the
                // environment during init, and the view model needs it there.
                DevicesView(api: api, session: session)
                    // A new identity gets a new screen, not a reused one still
                    // holding the previous account's devices.
                    .id(session.account?.id ?? "signed-in")
            } else {
                AuthView(viewModel: AuthViewModel(session: session))
            }
        }
        .animation(.default, value: session.isSignedIn)
    }
}
