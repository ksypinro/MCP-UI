import SwiftUI

/// Spec section 5.5. One field, and the entered name survives every failure.
struct AddDeviceView: View {
    @StateObject var viewModel: AddDeviceViewModel
    let onAdded: (Device) -> Void

    @Environment(\.dismiss) private var dismiss
    @FocusState private var isNameFocused: Bool

    init(viewModel: AddDeviceViewModel, onAdded: @escaping (Device) -> Void) {
        _viewModel = StateObject(wrappedValue: viewModel)
        self.onAdded = onAdded
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Device Name", text: $viewModel.name)
                        .textInputAutocapitalization(.words)
                        .submitLabel(.done)
                        .focused($isNameFocused)
                        .onSubmit { submit() }
                        .frame(minHeight: 44)
                    if let error = viewModel.nameError {
                        Text(error).font(.footnote).foregroundStyle(.red)
                            .accessibilityLabel("Error: \(error)")
                    }
                } header: {
                    Text("Device Name")
                } footer: {
                    Text("New devices start Off. You can switch it on once it has been added.")
                }

                if let formError = viewModel.formError {
                    Section {
                        Label(formError, systemImage: "exclamationmark.triangle.fill")
                            .font(.callout)
                            .foregroundStyle(.red)
                            .accessibilityLabel("Error: \(formError)")
                    }
                }
            }
            .navigationTitle("Add Device")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.frame(minHeight: 44)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(action: submit) {
                        if viewModel.isSubmitting { ProgressView() } else { Text("Add Device") }
                    }
                    .disabled(!viewModel.canSubmit)
                    .frame(minHeight: 44)
                }
            }
            .onAppear { isNameFocused = true }
        }
    }

    private func submit() {
        Task {
            // The sheet closes only on a real device. Every failure path keeps
            // the form and the typed name. Section 5.5.
            if let device = await viewModel.submit() {
                onAdded(device)
                dismiss()
            }
        }
    }
}
