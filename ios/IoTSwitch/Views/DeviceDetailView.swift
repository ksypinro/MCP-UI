import SwiftUI

/// Spec section 5.4.
struct DeviceDetailView: View {
    @StateObject var viewModel: DeviceDetailViewModel

    init(viewModel: DeviceDetailViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    var body: some View {
        Group {
            switch viewModel.phase {
            case .loading:
                ProgressView("Loading…").frame(maxWidth: .infinity, maxHeight: .infinity)

            case let .unavailable(message):
                ContentUnavailableView {
                    Label("Device unavailable", systemImage: "questionmark.circle")
                } description: {
                    Text(message)
                }

            case let .loaded(device):
                form(for: device)
            }
        }
        .navigationTitle(viewModel.device?.name ?? "Device")
        .navigationBarTitleDisplayMode(.inline)
        .task { await viewModel.load() }
        .alert(item: $viewModel.notice) { notice in
            Alert(title: Text(notice.title), message: Text(notice.message),
                  dismissButton: .default(Text("OK")))
        }
    }

    private func form(for device: Device) -> some View {
        let displayed = viewModel.displayedState ?? device.state
        let isPending = viewModel.pendingIntent != nil

        return Form {
            Section {
                HStack {
                    Text(device.name).font(.headline)
                    Spacer(minLength: 8)
                }
                Toggle(isOn: Binding(
                    get: { displayed.isOn },
                    set: { desired in
                        Task { await viewModel.setState(to: DeviceState.from(isOn: desired)) }
                    }
                )) {
                    HStack(spacing: 6) {
                        if isPending { ProgressView().controlSize(.mini) }
                        // Text as well as switch position: colour alone must
                        // not communicate state. Section 5.1.
                        Text(isPending ? "Changing to \(displayed.displayName)…" : displayed.displayName)
                    }
                }
                .disabled(isPending)
                .frame(minHeight: 44)
                .accessibilityLabel(device.name)
                .accessibilityValue(isPending ? "Changing to \(displayed.displayName)" : displayed.displayName)
            }

            Section("Details") {
                LabeledContent("Device ID") {
                    Text(device.id).font(.footnote.monospaced()).textSelection(.enabled)
                }
                LabeledContent("Last updated") {
                    Text(device.updatedAt.formatted(date: .abbreviated, time: .shortened))
                }
                LabeledContent("Version") { Text("\(device.version)") }
            }
        }
    }
}
