import AuthenticationServices
import UIKit

/// How the browser comes back to the app.
enum AuthCallback: Sendable, Equatable {
    /// A reverse-DNS private-use scheme. Works without an Apple team, so it is
    /// the development default. Another app could register the same scheme,
    /// but an intercepted code is useless without this app's PKCE verifier
    /// and DPoP key.
    case customScheme(String)
    /// A universal link on our own domain, which no other app can claim. Needs
    /// the associated-domains entitlement and an Apple team.
    case https(host: String, path: String)
}

enum AuthError: Error, Equatable {
    /// The person closed the sign-in sheet. Not an error worth showing.
    case cancelled
    case couldNotStart
    /// The browser came back with a different `state`: not this sign-in.
    case stateMismatch
    /// The response names another issuer (RFC 9207): a mix-up attempt.
    case issuerMismatch
    case denied(String)
    case missingCode

    var userMessage: String {
        switch self {
        case .cancelled: return "Sign-in was cancelled."
        case .couldNotStart: return "Could not open the sign-in page."
        case .stateMismatch, .issuerMismatch, .missingCode:
            return "The sign-in response could not be trusted, so it was ignored. Try again."
        case .denied(let reason): return reason
        }
    }
}

/// Shows the authorization server's page and returns the URL it redirects
/// to. A protocol so tests can script the browser.
@MainActor
protocol WebAuthenticator: AnyObject {
    func authenticate(url: URL, callback: AuthCallback) async throws -> URL
}

/// The system browser sheet (RFC 8252: an external user agent). The app
/// cannot see or script the page, the person sees the real address, and
/// passwords and passkeys come from their own keychain.
///
/// Ephemeral: no cookies are shared with Safari, so signing out of the app
/// really signs out, and nothing from this sign-in lingers in the browser.
@MainActor
final class SystemWebAuthenticator: NSObject, WebAuthenticator, ASWebAuthenticationPresentationContextProviding {
    private var session: ASWebAuthenticationSession?

    func authenticate(url: URL, callback: AuthCallback) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            let systemCallback: ASWebAuthenticationSession.Callback
            switch callback {
            case .customScheme(let scheme): systemCallback = .customScheme(scheme)
            case .https(let host, let path): systemCallback = .https(host: host, path: path)
            }
            let session = ASWebAuthenticationSession(url: url, callback: systemCallback) { [weak self] url, error in
                self?.session = nil
                if let url {
                    continuation.resume(returning: url)
                } else if let error = error as? ASWebAuthenticationSessionError, error.code == .canceledLogin {
                    continuation.resume(throwing: AuthError.cancelled)
                } else {
                    continuation.resume(throwing: error ?? AuthError.cancelled)
                }
            }
            session.prefersEphemeralWebBrowserSession = true
            session.presentationContextProvider = self
            self.session = session
            if !session.start() {
                self.session = nil
                continuation.resume(throwing: AuthError.couldNotStart)
            }
        }
    }

    nonisolated func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        MainActor.assumeIsolated {
            UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .flatMap(\.windows)
                .first(where: \.isKeyWindow) ?? ASPresentationAnchor()
        }
    }
}
