import Foundation

enum Configuration {
    /// Where the backend lives.
    ///
    /// Overridable at launch (`-apiBaseURL http://…`) so the same build can be
    /// pointed at a local server from the simulator without a rebuild.
    static var apiBaseURL: URL {
        if let override = UserDefaults.standard.string(forKey: "apiBaseURL"),
           let url = URL(string: override) {
            return url
        }
        return URL(string: "http://localhost:4000")!
    }
}
