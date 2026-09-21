import Foundation

/// Spec section 5.2. Exactly two credential fields, no email, no confirmation.
@MainActor
final class AuthViewModel: ObservableObject {
    enum Mode: String, CaseIterable, Equatable {
        case logIn = "Log In"
        case signUp = "Sign Up"
    }

    @Published var mode: Mode = .logIn
    @Published var username = ""
    @Published var password = ""
    @Published var isPasswordVisible = false

    @Published private(set) var usernameError: String?
    @Published private(set) var passwordError: String?
    @Published private(set) var formError: String?
    @Published private(set) var isSubmitting = false

    private let session: SessionController

    init(session: SessionController) {
        self.session = session
    }

    var canSubmit: Bool {
        !isSubmitting && !username.trimmingCharacters(in: .whitespaces).isEmpty && !password.isEmpty
    }

    func switchTo(_ mode: Mode) {
        guard mode != self.mode else { return }
        self.mode = mode
        // Field errors describe the previous attempt in the previous mode.
        usernameError = nil
        passwordError = nil
        formError = nil
    }

    func submit() async {
        guard !isSubmitting else { return } // section 5.2: no repeat submissions
        usernameError = nil
        passwordError = nil
        formError = nil

        let trimmedUsername = username.trimmingCharacters(in: .whitespaces)
        // The password is deliberately not trimmed: spaces are legitimate
        // characters in a generated password and removing them silently makes
        // a password that cannot be typed back in.
        guard !trimmedUsername.isEmpty else {
            usernameError = "Enter your username."
            return
        }
        guard !password.isEmpty else {
            passwordError = "Enter your password."
            return
        }

        isSubmitting = true
        defer { isSubmitting = false }

        do {
            switch mode {
            case .logIn:
                try await session.logIn(username: trimmedUsername, password: password)
            case .signUp:
                try await session.signUp(username: trimmedUsername, password: password)
            }
            // Only on success: holding a password in memory after we are done
            // with it serves no purpose.
            password = ""
        } catch let error as APIError {
            present(error)
        } catch {
            formError = error.localizedDescription
        }
    }

    private func present(_ error: APIError) {
        // A field-scoped error belongs next to its field; everything else is a
        // form-level message. Section 5.2.
        switch error.field {
        case "username": usernameError = error.userMessage
        case "password": passwordError = error.userMessage
        default: formError = error.userMessage
        }
    }
}
