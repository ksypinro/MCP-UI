import Foundation

/// Spec section 5.4. Fetches the latest device on open and controls it with
/// exactly the behaviour the list uses.
@MainActor
final class DeviceDetailViewModel: ObservableObject {
    enum Phase: Equatable {
        case loading
        case loaded(Device)
        case unavailable(String)
    }

    @Published private(set) var phase: Phase = .loading
    @Published private(set) var pendingIntent: DeviceState?
    @Published var notice: Notice?

    private let control: DeviceControlService
    let deviceID: String

    /// Called with every authoritative device this screen learns about.
    ///
    /// Without it the list keeps whatever version it last read, so changing a
    /// device here and then using its row switch sends a stale version and the
    /// user is told their own change was made "somewhere else".
    var onDeviceChanged: ((Device) -> Void)?

    init(control: DeviceControlService, device: Device) {
        self.control = control
        self.deviceID = device.id
        self.phase = .loaded(device)
    }

    private func adopt(_ device: Device) {
        phase = .loaded(device)
        onDeviceChanged?(device)
    }

    var device: Device? {
        if case let .loaded(device) = phase { return device }
        return nil
    }

    var displayedState: DeviceState? {
        guard let device else { return nil }
        return pendingIntent ?? device.state
    }

    /// Section 5.4: fetch the latest device when the screen opens, because the
    /// row that navigated here may have been read minutes ago.
    func load() async {
        do {
            adopt(try await control.read(deviceID))
        } catch APIError.unauthenticated {
            phase = .loading
        } catch let error as APIError where error.isNotFound {
            phase = .unavailable("This device is no longer available on this account.")
        } catch let error as APIError {
            if device == nil { phase = .unavailable(error.userMessage) } else { notice = Notice(title: "Could not refresh", message: error.userMessage) }
        } catch {
            if device == nil { phase = .unavailable(error.localizedDescription) }
        }
    }

    func setState(to desired: DeviceState) async {
        guard let device, pendingIntent == nil, desired != device.state else { return }

        pendingIntent = desired
        defer { pendingIntent = nil }

        switch await control.control(device, to: desired) {
        case let .updated(updated):
            adopt(updated)

        case let .conflict(refetched):
            if let refetched { adopt(refetched) }
            notice = Notice(
                title: "That device changed",
                message: "\(device.name) was changed somewhere else, so your change was not applied."
            )

        case .notFound:
            phase = .unavailable("This device is no longer available on this account.")

        case let .unknown(reconciled):
            if let reconciled {
                adopt(reconciled)
                notice = Notice(
                    title: "Connection interrupted",
                    message: "We lost the connection before hearing back. It is currently "
                        + "\(reconciled.state.displayName)."
                )
            } else {
                notice = Notice(
                    title: "Connection interrupted",
                    message: "We do not know whether that applied, and could not check."
                )
            }

        case let .rejected(error):
            notice = Notice(title: "Could not change \(device.name)", message: error.userMessage)

        case .signedOut:
            break
        }
    }
}
