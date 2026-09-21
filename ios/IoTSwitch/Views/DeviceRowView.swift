import SwiftUI

/// One device in the list. Spec section 5.1: icon, name, an explicit On/Off
/// label, and a switch — the label matters because colour alone must not carry
/// the state.
struct DeviceRowView: View {
    let device: Device
    let displayedState: DeviceState
    let isPending: Bool
    let onChange: (DeviceState) -> Void

    @ScaledMetric(relativeTo: .body) private var iconSize: CGFloat = 28

    var body: some View {
        // At accessibility text sizes a row cannot hold a name and a switch
        // side by side, so it stacks rather than truncating either away.
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 12) { icon; labels; Spacer(minLength: 8); toggle }
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 12) { icon; labels }
                toggle.frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .combine)
        .accessibilityValue(isPending ? "Changing to \(displayedState.displayName)" : displayedState.displayName)
    }

    private var icon: some View {
        Image(systemName: "powerplug.portrait")
            .font(.system(size: iconSize * 0.55))
            .frame(width: iconSize, height: iconSize)
            .foregroundStyle(.secondary)
            .accessibilityHidden(true)
    }

    private var labels: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(device.name)
                .font(.body)
                .lineLimit(2)
            HStack(spacing: 5) {
                if isPending {
                    ProgressView().controlSize(.mini)
                }
                Text(isPending ? "Changing to \(displayedState.displayName)…" : displayedState.displayName)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var toggle: some View {
        Toggle("", isOn: Binding(
            get: { displayedState.isOn },
            set: { onChange(DeviceState.from(isOn: $0)) }
        ))
        .labelsHidden()
        // Section 5.6 step 3: while a change is in flight this one switch is
        // inert, so a second tap cannot queue a contradictory write.
        .disabled(isPending)
        .accessibilityLabel(device.name)
    }
}
