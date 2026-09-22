import XCTest
@testable import IoTSwitch

/// Spec section 5.4, and the propagation the list depends on.
@MainActor
final class DeviceDetailViewModelTests: XCTestCase {

    func testDelayedReadCannotOverwriteConfirmedControl() async {
        let api = StubAPIClient()
        api.controlResults = [.success(.fixture(state: .on, version: 2))]
        api.getResults = [.success(.fixture(state: .off, version: 1))]
        let viewModel = makeViewModel(api)
        var reported: [Int] = []
        viewModel.onDeviceChanged = { reported.append($0.version) }
        let gate = AsyncGate()
        api.readGate = { await gate.wait() }
        let read = Task { await viewModel.load() }
        while !(await gate.hasWaiter()) { await Task.yield() }
        await viewModel.setState(to: .on)
        await gate.open()
        await read.value
        XCTAssertEqual(viewModel.device?.version, 2)
        XCTAssertEqual(viewModel.device?.state, .on)
        XCTAssertEqual(reported, [2])
    }

    private func makeViewModel(
        _ api: StubAPIClient, device: Device = .fixture()
    ) -> DeviceDetailViewModel {
        let session = makeSignedInSession(api)
        return DeviceDetailViewModel(
            control: DeviceControlService(api: api, session: session), device: device
        )
    }

    func testOpeningTheScreenFetchesTheLatestDevice() async {
        let api = StubAPIClient()
        api.getResults = [.success(.fixture(state: .on, version: 5))]
        let viewModel = makeViewModel(api)

        await viewModel.load()

        // Section 5.4: the row that navigated here may have been read minutes
        // ago, so the screen does not trust it.
        XCTAssertEqual(viewModel.device?.version, 5)
        XCTAssertEqual(api.calls, [.get("dev_01")])
    }

    func testAMissingDeviceBecomesAnUnavailableScreen() async {
        let api = StubAPIClient()
        api.getResults = [.failure(APIError.api(
            code: "DEVICE_NOT_FOUND", message: "That device does not exist.", field: nil, status: 404
        ))]
        let viewModel = makeViewModel(api)

        await viewModel.load()

        guard case .unavailable = viewModel.phase else {
            return XCTFail("expected an unavailable screen, got \(viewModel.phase)")
        }
    }

    func testEveryAuthoritativeDeviceIsReportedOutwards() async {
        let api = StubAPIClient()
        api.getResults = [.success(.fixture(version: 5))]
        api.controlResults = [.success(.fixture(state: .on, version: 6))]
        let viewModel = makeViewModel(api)

        var reported: [Device] = []
        viewModel.onDeviceChanged = { reported.append($0) }

        await viewModel.load()
        await viewModel.setState(to: .on)

        XCTAssertEqual(reported.map(\.version), [5, 6],
                       "both the fetch and the change are handed back to the list")
    }

    /// The bug this guards against: change a device here, go back, flip its row
    /// switch, and be told your own change was made "somewhere else".
    func testAChangeHereLeavesTheListHoldingTheNewVersion() async {
        let api = StubAPIClient()
        api.listResults = [.success([.fixture(version: 1)])]
        api.controlResults = [
            .success(.fixture(state: .on, version: 2)),   // from the detail screen
            .success(.fixture(state: .off, version: 3))   // from the row switch
        ]
        let session = makeSignedInSession(api)
        let control = DeviceControlService(api: api, session: session)
        let list = DevicesViewModel(control: control, session: session)
        await list.loadIfNeeded()

        let detail = DeviceDetailViewModel(control: control, device: list.devices[0])
        detail.onDeviceChanged = { list.deviceChangedElsewhere($0) }
        await detail.setState(to: .on)

        XCTAssertEqual(list.devices.first?.version, 2, "the list adopted the change")

        await list.setState(list.devices[0], to: .off)

        XCTAssertEqual(
            api.calls.last, .control(id: "dev_01", state: .off, expectedVersion: 2),
            "the row switch sends the version the detail screen established, not the stale one"
        )
        XCTAssertNil(list.notice, "no spurious conflict is reported to the user")
    }
}
