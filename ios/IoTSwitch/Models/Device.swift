import Foundation

/// Exactly two persisted states. Spec section 4.2.
///
/// Loading, updating and error are presentation states and deliberately do not
/// appear here: a device is on or off, and nothing the UI is doing changes that.
enum DeviceState: String, Codable, Sendable, Equatable {
    case on
    case off

    var displayName: String { self == .on ? "On" : "Off" }
    var isOn: Bool { self == .on }

    var opposite: DeviceState { self == .on ? .off : .on }

    static func from(isOn: Bool) -> DeviceState { isOn ? .on : .off }
}

struct Device: Codable, Sendable, Equatable, Identifiable {
    let id: String
    let name: String
    let state: DeviceState
    /// Required by every control request. Spec section 6.1.
    let version: Int
    let createdAt: Date
    let updatedAt: Date
}

struct Account: Codable, Sendable, Equatable {
    let id: String
    let username: String
}

struct DeviceListResponse: Codable, Sendable { let devices: [Device] }
struct DeviceResponse: Codable, Sendable { let device: Device }
struct AccountResponse: Codable, Sendable { let account: Account }

/// A token endpoint response (RFC 6749 section 5.1).
struct TokenResponse: Decodable, Sendable, Equatable {
    let accessToken: String
    /// "DPoP" for this app: every token is bound to its key.
    let tokenType: String
    let expiresIn: Int
    let refreshToken: String?
    let scope: String?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case refreshToken = "refresh_token"
        case scope
    }
}

/// A pushed authorization response (RFC 9126).
struct PushedAuthorizationResponse: Decodable, Sendable {
    let requestURI: String
    let expiresIn: Int

    enum CodingKeys: String, CodingKey {
        case requestURI = "request_uri"
        case expiresIn = "expires_in"
    }
}

/// An OAuth error body (RFC 6749 section 5.2).
struct OAuthErrorResponse: Decodable, Sendable {
    let error: String
    let errorDescription: String?

    enum CodingKeys: String, CodingKey {
        case error
        case errorDescription = "error_description"
    }
}

/// What the app pushes to start a sign-in.
struct AuthorizationRequest: Sendable, Equatable {
    let codeChallenge: String
    let state: String
    let redirectURI: String
    /// The thumbprint of the DPoP key the code will be bound to.
    let dpopThumbprint: String
    /// Open the hosted page on its sign-up form.
    let signUp: Bool
}
