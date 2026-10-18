import SwiftUI

@main
struct IoTSwitchApp: App {
    @StateObject private var session: SessionController
    private let api: APIClient

    init() {
        let auth = Configuration.auth
        // One DPoP key for this install's current sign-in, kept in the Secure
        // Enclave. Every request the app makes is signed with it.
        let keyring = DPoPKeyring(store: KeychainDPoPKeyStore())
        let api = HTTPAPIClient(baseURL: Configuration.apiBaseURL, auth: auth, keyring: keyring)
        self.api = api
        _session = StateObject(wrappedValue: SessionController(
            api: api, storage: KeychainTokenStorage(), auth: auth,
            web: SystemWebAuthenticator(), keyring: keyring
        ))
    }

    var body: some Scene {
        WindowGroup {
            RootView(api: api)
                .environmentObject(session)
        }
    }
}
