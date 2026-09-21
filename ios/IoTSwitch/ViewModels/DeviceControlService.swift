import Foundation

/// The switch behaviour from spec section 5.6, in one place.
///
/// The list and the detail screen share this rather than each implementing the
/// sequence, because section 5.4 requires the detail screen to behave exactly
/// like the list and two copies of a state machine do not stay identical.
@MainActor
final class DeviceControlService {
    enum Outcome: Equatable {
        /// The backend confirmed the change; this is the authoritative device.
        case updated(Device)
        /// Someone else changed it first. Carries the refetched device when we
        /// managed to read it, so the UI can show what is actually true.
        case conflict(Device?)
        /// The backend refused for a reason the user should see.
        case rejected(APIError)
        /// The device is gone, or was never ours.
        case notFound
        /// The write's outcome is unknown. `reconciled` is what a follow-up
        /// read found, or nil if that read failed too. Section 5.6 step 8:
        /// never infer success, and never send the inverse command.
        case unknown(reconciled: Device?)
        /// The session ended; the app should be showing sign-in.
        case signedOut
    }

    private let api: APIClient
    private let session: SessionController

    init(api: APIClient, session: SessionController) {
        self.api = api
        self.session = session
    }

    func control(_ device: Device, to desired: DeviceState) async -> Outcome {
        // Step 2: capture the identity, the intent and the version we saw.
        // Everything below uses this snapshot, never a re-read of UI state.
        let deviceId = device.id
        let expectedVersion = device.version

        do {
            let updated = try await session.authorized { token in
                try await api.controlDevice(
                    id: deviceId, state: desired, expectedVersion: expectedVersion, accessToken: token
                )
            }
            return .updated(updated)
        } catch let error as APIError {
            switch error {
            case .unauthenticated:
                return .signedOut

            case .unknownOutcome:
                // Read before offering a retry. The request may well have
                // applied; assuming it did not and re-sending the opposite is
                // how a switch ends up flipping itself back.
                return .unknown(reconciled: try? await read(deviceId))

            case .api where error.isVersionConflict:
                // Refetch so the user is told what it actually is, not merely
                // that they were too late.
                return .conflict(try? await read(deviceId))

            case .api where error.isNotFound:
                return .notFound

            default:
                return .rejected(error)
            }
        } catch {
            return .rejected(.network(message: error.localizedDescription))
        }
    }

    func read(_ deviceId: String) async throws -> Device {
        try await session.authorized { token in
            try await api.getDevice(id: deviceId, accessToken: token)
        }
    }

    func list() async throws -> [Device] {
        try await session.authorized { token in
            try await api.listDevices(accessToken: token)
        }
    }
}
