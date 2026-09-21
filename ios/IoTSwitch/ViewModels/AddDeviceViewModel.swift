import Foundation

/// Spec section 5.5. One field, and the entered name survives every failure.
@MainActor
final class AddDeviceViewModel: ObservableObject {
    @Published var name = ""
    @Published private(set) var nameError: String?
    @Published private(set) var formError: String?
    @Published private(set) var isSubmitting = false

    private let api: APIClient
    private let session: SessionController

    /// Stable across retries of the same submission, so a retry after a lost
    /// response returns the original device rather than creating a second.
    /// Spec section 6.2.
    private var idempotencyKey = UUID().uuidString
    /// The name the current key was issued for. The backend refuses a key
    /// replayed with different arguments, so editing the name must mint a new
    /// one rather than fail confusingly.
    private var keyedName: String?

    init(api: APIClient, session: SessionController) {
        self.api = api
        self.session = session
    }

    var trimmedName: String { name.trimmingCharacters(in: .whitespacesAndNewlines) }
    var canSubmit: Bool { !isSubmitting && !trimmedName.isEmpty }

    /// Returns the created device, or nil if the attempt did not succeed. The
    /// view dismisses only on a device.
    func submit() async -> Device? {
        guard !isSubmitting else { return nil }
        nameError = nil
        formError = nil

        let candidate = trimmedName
        guard !candidate.isEmpty else {
            nameError = "Enter a name for this device."
            return nil
        }
        guard candidate.count <= 64 else {
            nameError = "Device names can be at most 64 characters."
            return nil
        }

        if keyedName != candidate {
            idempotencyKey = UUID().uuidString
            keyedName = candidate
        }

        isSubmitting = true
        defer { isSubmitting = false }

        do {
            let key = idempotencyKey
            let device = try await session.authorized { token in
                try await api.addDevice(name: candidate, idempotencyKey: key, accessToken: token)
            }
            return device
        } catch let error as APIError {
            switch error {
            case .unauthenticated:
                return nil // the root view takes over
            case _ where error.isNameConflict:
                nameError = "A device with this name already exists."
            case .unknownOutcome:
                // Retrying is safe: the same key either creates it once or
                // returns what was already created. Never silently resubmit
                // on the user's behalf, though — section 5.2.
                formError = "We lost the connection before hearing back. "
                    + "Tap Add Device again to finish safely, or check your list."
            default:
                if let field = error.field, field == "name" {
                    nameError = error.userMessage
                } else {
                    formError = error.userMessage
                }
            }
            return nil
        } catch {
            formError = error.localizedDescription
            return nil
        }
    }
}
