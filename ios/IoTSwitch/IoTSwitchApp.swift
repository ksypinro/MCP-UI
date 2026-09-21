import SwiftUI

@main
struct IoTSwitchApp: App {
    @StateObject private var session: SessionController
    private let api: APIClient

    init() {
        let api = HTTPAPIClient(baseURL: Configuration.apiBaseURL)
        self.api = api
        _session = StateObject(
            wrappedValue: SessionController(api: api, storage: KeychainTokenStorage())
        )
    }

    var body: some Scene {
        WindowGroup {
            RootView(api: api)
                .environmentObject(session)
        }
    }
}
