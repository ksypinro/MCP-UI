import Foundation

struct Notice: Identifiable, Equatable {
    let id = UUID()
    let title: String
    let message: String
}

/// The Devices screen. Spec sections 5.3 and 5.6.
@MainActor
final class DevicesViewModel: ObservableObject {
    /// The states section 5.3 requires, as one value rather than a handful of
    /// booleans that can contradict each other.
    enum Phase: Equatable {
        case loading
        case loaded
        case failed(String)
    }

    @Published private(set) var phase: Phase = .loading
    @Published private(set) var devices: [Device] = []
    /// Device id to the state the user asked for but the backend has not yet
    /// confirmed. Its presence is what disables that one switch.
    @Published private(set) var pendingIntents: [String: DeviceState] = [:]
    @Published private(set) var isRefreshing = false
    /// True when the visible list is from an earlier fetch that we have since
    /// failed to renew. Section 5.3 forbids implying it is fresh.
    @Published private(set) var isShowingStaleData = false
    @Published var notice: Notice?
    @Published private(set) var recentlyAddedDeviceID: String?

    private var loadSequence = 0

    private let control: DeviceControlService
    private let session: SessionController

    init(control: DeviceControlService, session: SessionController) {
        self.control = control
        self.session = session
    }

    var isEmpty: Bool { phase == .loaded && devices.isEmpty }

    func isPending(_ device: Device) -> Bool { pendingIntents[device.id] != nil }

    /// What the switch should show: the pending intent if there is one, else
    /// the confirmed state. Optimistic motion is allowed, but the row also
    /// renders a pending label so intent is never mistaken for fact.
    func displayedState(for device: Device) -> DeviceState {
        pendingIntents[device.id] ?? device.state
    }

    // MARK: - Loading

    func loadIfNeeded() async {
        // Only the first time. A failed load waits for the Retry button rather
        // than re-firing every time the view reappears.
        guard devices.isEmpty else { return }
        if case .failed = phase { return }
        await load(initial: true)
    }

    func retry() async { await load(initial: true) }

    func refresh() async { await load(initial: false) }

    private func load(initial: Bool) async {
        loadSequence += 1
        let sequence = loadSequence
        let startingIDs = Set(devices.map(\.id))
        if initial {
            phase = .loading
        } else {
            // Section 5.3: the visible list stays put while refreshing.
            isRefreshing = true
        }
        defer { if sequence == loadSequence { isRefreshing = false } }

        do {
            let fetched = try await control.list()
            guard sequence == loadSequence else { return }
            let current = Dictionary(uniqueKeysWithValues: devices.map { ($0.id, $0) })
            let fetchedIDs = Set(fetched.map(\.id))
            // Keep newer confirmations and additions made while this read ran.
            devices = fetched.map { incoming in
                guard let known = current[incoming.id], known.version > incoming.version else { return incoming }
                return known
            } + devices.filter { !startingIDs.contains($0.id) && !fetchedIDs.contains($0.id) }
            devices.sort { $0.createdAt == $1.createdAt ? $0.id < $1.id : $0.createdAt < $1.createdAt }
            phase = .loaded
            isShowingStaleData = false
        } catch APIError.unauthenticated {
            guard sequence == loadSequence else { return }
            // The root view is already switching to sign-in; showing an error
            // here would flash a message at a screen that is going away.
            devices = []
            phase = .loading
        } catch let error as APIError {
            guard sequence == loadSequence else { return }
            if devices.isEmpty {
                phase = .failed(error.userMessage)
            } else {
                // We still have something real to show, so keep showing it —
                // labelled as old, not as current.
                isShowingStaleData = true
                notice = Notice(title: "Could not refresh", message: error.userMessage)
            }
        } catch {
            guard sequence == loadSequence else { return }
            phase = .failed(error.localizedDescription)
        }
    }

    // MARK: - Control

    func setState(_ device: Device, to desired: DeviceState) async {
        guard pendingIntents[device.id] == nil else { return } // step 3: no double-taps
        guard desired != device.state else { return }

        pendingIntents[device.id] = desired
        defer { pendingIntents[device.id] = nil }

        switch await control.control(device, to: desired) {
        case let .updated(updated):
            replace(updated)

        case let .conflict(refetched):
            if let refetched { replace(refetched) }
            notice = Notice(
                title: "That device changed",
                message: "\(device.name) was changed somewhere else, so your change was not applied. "
                    + "It is now \(( refetched?.state ?? device.state).displayName)."
            )

        case .notFound:
            devices.removeAll { $0.id == device.id }
            notice = Notice(
                title: "Device unavailable",
                message: "\(device.name) is no longer available on this account."
            )

        case let .unknown(reconciled):
            if let reconciled {
                replace(reconciled)
                notice = Notice(
                    title: "Connection interrupted",
                    message: "We lost the connection before hearing back. \(reconciled.name) is "
                        + "currently \(reconciled.state.displayName)."
                )
            } else {
                notice = Notice(
                    title: "Connection interrupted",
                    message: "We do not know whether that applied, and could not check. "
                        + "Pull to refresh when you are back online."
                )
            }

        case let .rejected(error):
            notice = Notice(title: "Could not change \(device.name)", message: error.userMessage)

        case .signedOut:
            break // the root view takes over
        }
    }

    // MARK: - Additions

    /// Adopts a device that another screen has just confirmed, so the list
    /// never holds a version it already knows to be stale.
    func deviceChangedElsewhere(_ device: Device) {
        replace(device)
    }

    func deviceWasAdded(_ device: Device) {
        replace(device, insertingIfMissing: true)
        recentlyAddedDeviceID = device.id
        Task {
            await refresh()
            // The highlight marks "this is the one you just added". Left
            // permanently it becomes a meaningless coloured row.
            try? await Task.sleep(for: .seconds(3))
            if recentlyAddedDeviceID == device.id { recentlyAddedDeviceID = nil }
        }
    }

    private func replace(_ device: Device, insertingIfMissing: Bool = false) {
        if let index = devices.firstIndex(where: { $0.id == device.id }) {
            guard device.version >= devices[index].version else { return }
            devices[index] = device
        } else if insertingIfMissing {
            devices.append(device)
            // Section 4.3's ordering is a server contract, but a locally
            // inserted device has to land in the right place until the
            // refetch lands.
            devices.sort {
                $0.createdAt == $1.createdAt ? $0.id < $1.id : $0.createdAt < $1.createdAt
            }
        }
    }
}
