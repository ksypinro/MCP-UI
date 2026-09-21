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

struct SessionResponse: Codable, Sendable {
    let account: Account
    let accessToken: String
    let refreshToken: String
    let expiresIn: Int
}

struct RefreshResponse: Codable, Sendable {
    let accessToken: String
    let refreshToken: String
    let expiresIn: Int
}
