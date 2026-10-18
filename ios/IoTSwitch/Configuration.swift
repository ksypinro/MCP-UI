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

    /// How the app signs in. `-authBaseURL` points at a separate authorization
    /// server; `-authCallbackHost` switches to a universal-link callback once
    /// the app has the associated-domains entitlement for that host.
    static var auth: AuthConfiguration {
        let defaults = UserDefaults.standard
        let authBase = defaults.string(forKey: "authBaseURL").flatMap(URL.init(string:)) ?? apiBaseURL
        let callback: AuthCallback = defaults.string(forKey: "authCallbackHost")
            .map { .https(host: $0, path: "/oauth/callback") }
            ?? .customScheme(AuthConfiguration.developmentScheme)
        return AuthConfiguration(authBaseURL: authBase, callback: callback)
    }
}

/// Everything the app needs to know about its authorization server.
struct AuthConfiguration: Sendable, Equatable {
    /// Lower case: URL schemes are case-insensitive and arrive lower-cased,
    /// and the server compares redirect URIs exactly.
    static let developmentScheme = "com.example.iotswitch"
    static let clientID = "iot-switch-ios"

    let authBaseURL: URL
    let callback: AuthCallback

    /// The issuer the server names in every response (RFC 9207): its base URL
    /// with no trailing slash.
    var issuer: String {
        var value = authBaseURL.absoluteString
        while value.hasSuffix("/") { value.removeLast() }
        return value
    }

    var redirectURI: String {
        switch callback {
        case .customScheme(let scheme): return "\(scheme):/oauth/callback"
        case .https(let host, let path): return "https://\(host)\(path)"
        }
    }

    static func development(_ baseURL: URL) -> AuthConfiguration {
        AuthConfiguration(authBaseURL: baseURL, callback: .customScheme(developmentScheme))
    }
}
