import SwiftUI

struct AuthView: View {
    @StateObject var viewModel: AuthViewModel

    init(viewModel: AuthViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header
                if let message = viewModel.errorMessage {
                    Label(message, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(.red)
                        .accessibilityLabel("Error: \(message)")
                }
                buttons
                Text("You'll sign in on IoT Switch's secure page. This app never sees your password.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            .padding(20)
            .frame(maxWidth: 480)
            .frame(maxWidth: .infinity)
        }
        .background(Color(.systemGroupedBackground))
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("IoT Switch").font(.largeTitle.bold())
            Text("Sign in to see and control your devices.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }

    private var buttons: some View {
        VStack(spacing: 12) {
            Button {
                Task { await viewModel.start(.logIn) }
            } label: {
                label(for: .logIn, tint: .white)
            }
            .buttonStyle(.borderedProminent)

            Button {
                Task { await viewModel.start(.signUp) }
            } label: {
                label(for: .signUp, tint: nil)
            }
            .buttonStyle(.bordered)
        }
        .disabled(viewModel.isWorking)
    }

    private func label(for mode: AuthViewModel.Mode, tint: Color?) -> some View {
        HStack {
            if viewModel.activeMode == mode { ProgressView().tint(tint) }
            Text(mode.rawValue)
        }
        .frame(maxWidth: .infinity, minHeight: 44)
    }
}
