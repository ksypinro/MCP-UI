import SwiftUI

struct DevicesView: View {
    let api: APIClient
    private let session: SessionController
    private let control: DeviceControlService
    @StateObject private var viewModel: DevicesViewModel
    @State private var isAddingDevice = false
    @State private var hasLoaded = false

    @Environment(\.scenePhase) private var scenePhase

    init(api: APIClient, session: SessionController) {
        self.api = api
        self.session = session
        let control = DeviceControlService(api: api, session: session)
        self.control = control
        _viewModel = StateObject(
            wrappedValue: DevicesViewModel(control: control, session: session)
        )
    }

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("Devices")
                .toolbar { toolbar }
                .refreshable { await viewModel.refresh() }
                .sheet(isPresented: $isAddingDevice) {
                    AddDeviceView(
                        viewModel: AddDeviceViewModel(api: api, session: session),
                        onAdded: { device in viewModel.deviceWasAdded(device) }
                    )
                }
                .alert(item: $viewModel.notice) { notice in
                    Alert(title: Text(notice.title), message: Text(notice.message),
                          dismissButton: .default(Text("OK")))
                }
        }
        .task {
            await viewModel.loadIfNeeded()
            hasLoaded = true
        }
        .onChange(of: scenePhase) { previous, phase in
            // Section 5.3: returning to the foreground fetches fresh data.
            //
            // Guarded on both sides. The scene settles from .inactive to
            // .active during launch, which fired this while the initial load
            // was already running and sent every launch two identical
            // requests; and a refresh before the first load has finished would
            // race it.
            guard hasLoaded, previous != .active, phase == .active else { return }
            Task { await viewModel.refresh() }
        }
    }

    @ViewBuilder
    private var content: some View {
        switch viewModel.phase {
        case .loading:
            ProgressView("Loading your devices…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)

        case let .failed(message):
            ContentUnavailableView {
                Label("Could not load devices", systemImage: "wifi.exclamationmark")
            } description: {
                Text(message)
            } actions: {
                Button("Retry") { Task { await viewModel.retry() } }
                    .buttonStyle(.borderedProminent)
                    .frame(minHeight: 44)
            }

        case .loaded:
            if viewModel.devices.isEmpty {
                ContentUnavailableView {
                    Label("No devices yet", systemImage: "powerplug.portrait")
                } description: {
                    Text("Add a device to start controlling it.")
                } actions: {
                    Button("Add Device") { isAddingDevice = true }
                        .buttonStyle(.borderedProminent)
                        .frame(minHeight: 44)
                }
            } else {
                deviceList
            }
        }
    }

    private var deviceList: some View {
        List {
            if viewModel.isShowingStaleData {
                Section {
                    Label(
                        "Showing devices from an earlier update. Pull down to try again.",
                        systemImage: "clock.arrow.circlepath"
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }
            }
            Section {
                ForEach(viewModel.devices) { device in
                    NavigationLink {
                        DeviceDetailView(
                            viewModel: detailViewModel(for: device)
                        )
                    } label: {
                        DeviceRowView(
                            device: device,
                            displayedState: viewModel.displayedState(for: device),
                            isPending: viewModel.isPending(device),
                            onChange: { desired in
                                Task { await viewModel.setState(device, to: desired) }
                            }
                        )
                    }
                    .listRowBackground(
                        device.id == viewModel.recentlyAddedDeviceID
                            ? Color.accentColor.opacity(0.12) : Color(.secondarySystemGroupedBackground)
                    )
                }
            }
        }
        .listStyle(.insetGrouped)
    }

    private func detailViewModel(for device: Device) -> DeviceDetailViewModel {
        let detail = DeviceDetailViewModel(control: control, device: device)
        // Changes made on the detail screen flow straight back into the list,
        // so returning to it never leaves a stale version behind.
        detail.onDeviceChanged = { [viewModel] updated in
            viewModel.deviceChangedElsewhere(updated)
        }
        return detail
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .topBarTrailing) {
            Button {
                isAddingDevice = true
            } label: {
                Label("Add Device", systemImage: "plus")
                    .frame(minWidth: 44, minHeight: 44)
            }
        }
        ToolbarItem(placement: .topBarLeading) {
            Menu {
                if let username = session.account?.username {
                    Text("Signed in as \(username)")
                }
                Button("Log Out", role: .destructive) {
                    Task { await session.logOut() }
                }
            } label: {
                Label("Account", systemImage: "person.crop.circle")
                    .frame(minWidth: 44, minHeight: 44)
            }
        }
    }
}
