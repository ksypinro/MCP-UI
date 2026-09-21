import Foundation

/// The closed error set the backend returns, plus the transport outcomes the
/// client has to tell apart. Spec sections 6.3 and 5.6.
enum APIError: Error, Equatable {
    /// The credential is missing, expired or revoked.
    case unauthenticated
    /// A structured error from the backend.
    case api(code: String, message: String, field: String?, status: Int)
    /// A read failed and can simply be tried again.
    case network(message: String)
    /// A *mutation* whose outcome is unknown: the request may or may not have
    /// been applied. Spec section 5.6 step 8 forbids inferring either way, so
    /// this is a distinct case rather than a flavour of `network`.
    case unknownOutcome
    case decoding(message: String)

    var code: String? {
        if case let .api(code, _, _, _) = self { return code }
        return nil
    }

    var field: String? {
        if case let .api(_, _, field, _) = self { return field }
        return nil
    }

    /// Text safe to show a person. Backend messages are already written for
    /// humans; transport failures are not, so they get replacements here.
    var userMessage: String {
        switch self {
        case .unauthenticated:
            return "Your session has ended. Sign in again."
        case let .api(_, message, _, _):
            return message
        case let .network(message):
            return message
        case .unknownOutcome:
            return "The network dropped before we heard back, so we do not know whether that applied."
        case .decoding:
            return "The server sent something this app could not read."
        }
    }

    var isVersionConflict: Bool { code == "DEVICE_VERSION_CONFLICT" }
    var isNameConflict: Bool { code == "DEVICE_NAME_CONFLICT" }
    var isNotFound: Bool { code == "DEVICE_NOT_FOUND" }
}
