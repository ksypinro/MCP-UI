import Foundation

/// The sign-in screen. Spec section 5.2, as revised for browser sign-in.
///
/// There are no credential fields here any more. Log In and Sign Up both open
/// the authorization server's page in the system browser sheet, where the
/// person types their password (or uses a passkey) on the real site, with
/// autofill, and where this app cannot read or script anything.
@MainActor
final class AuthViewModel: ObservableObject {
    enum Mode: String, CaseIterable, Equatable {
        case logIn = "Log In"
        case signUp = "Sign Up"
    }

    /// The button that started the sign-in in progress, so only it spins.
    @Published private(set) var activeMode: Mode?
    var isWorking: Bool { activeMode != nil }
    @Published private(set) var errorMessage: String?

    private let session: SessionController

    init(session: SessionController) {
        self.session = session
    }

    func start(_ mode: Mode) async {
        guard !isWorking else { return } // section 5.2: no repeat submissions
        errorMessage = nil
        activeMode = mode
        defer { activeMode = nil }

        do {
            try await session.signIn(signUp: mode == .signUp)
        } catch AuthError.cancelled {
            // Closing the sheet is a choice, not a failure.
        } catch let error as AuthError {
            errorMessage = error.userMessage
        } catch let error as APIError {
            errorMessage = error.userMessage
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
