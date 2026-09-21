import Foundation

/// The shape every backend error arrives in. Spec section 6.3.
struct ErrorEnvelope: Codable, Sendable {
    struct Payload: Codable, Sendable {
        let code: String
        let message: String
        let field: String?
        let requestId: String
    }
    let error: Payload
}
