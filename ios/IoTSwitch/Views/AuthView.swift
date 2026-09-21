import SwiftUI

struct AuthView: View {
    @StateObject var viewModel: AuthViewModel
    @FocusState private var focused: Field?

    private enum Field { case username, password }

    init(viewModel: AuthViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                modePicker
                usernameField
                passwordField
                if let formError = viewModel.formError {
                    Label(formError, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(.red)
                        .accessibilityLabel("Error: \(formError)")
                }
                submitButton
            }
            .padding(20)
            .frame(maxWidth: 480)
            .frame(maxWidth: .infinity)
        }
        .background(Color(.systemGroupedBackground))
        .scrollDismissesKeyboard(.interactively)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("IoT Switch").font(.largeTitle.bold())
            Text(viewModel.mode == .logIn
                 ? "Log in to see and control your devices."
                 : "Create an account to start adding devices.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }

    private var modePicker: some View {
        Picker("Mode", selection: Binding(
            get: { viewModel.mode },
            set: { viewModel.switchTo($0) }
        )) {
            ForEach(AuthViewModel.Mode.allCases, id: \.self) { mode in
                Text(mode.rawValue).tag(mode)
            }
        }
        .pickerStyle(.segmented)
    }

    private var usernameField: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Username").font(.subheadline.weight(.semibold))
            TextField("Username", text: $viewModel.username)
                .textContentType(.username)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.next)
                .focused($focused, equals: .username)
                .onSubmit { focused = .password }
                .textFieldStyle(.roundedBorder)
            if let error = viewModel.usernameError {
                fieldError(error)
            }
        }
    }

    private var passwordField: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Password").font(.subheadline.weight(.semibold))
            HStack(spacing: 8) {
                Group {
                    if viewModel.isPasswordVisible {
                        TextField("Password", text: $viewModel.password)
                    } else {
                        SecureField("Password", text: $viewModel.password)
                    }
                }
                // New password for sign-up so the OS offers to generate and
                // save one; current password for log-in so it offers to fill.
                .textContentType(viewModel.mode == .signUp ? .newPassword : .password)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.go)
                .focused($focused, equals: .password)
                .onSubmit { Task { await viewModel.submit() } }
                .textFieldStyle(.roundedBorder)

                Button {
                    viewModel.isPasswordVisible.toggle()
                } label: {
                    Image(systemName: viewModel.isPasswordVisible ? "eye.slash" : "eye")
                        .frame(width: 44, height: 44)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(viewModel.isPasswordVisible ? "Hide password" : "Show password")
            }
            if let error = viewModel.passwordError {
                fieldError(error)
            }
        }
    }

    private func fieldError(_ message: String) -> some View {
        Text(message)
            .font(.footnote)
            .foregroundStyle(.red)
            .accessibilityLabel("Error: \(message)")
    }

    private var submitButton: some View {
        Button {
            focused = nil
            Task { await viewModel.submit() }
        } label: {
            HStack {
                if viewModel.isSubmitting { ProgressView().tint(.white) }
                Text(viewModel.mode.rawValue)
            }
            .frame(maxWidth: .infinity, minHeight: 44)
        }
        .buttonStyle(.borderedProminent)
        .disabled(!viewModel.canSubmit)
    }
}
