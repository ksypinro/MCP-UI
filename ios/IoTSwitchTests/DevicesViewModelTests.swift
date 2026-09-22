import XCTest
@testable import IoTSwitch

/// The switch behaviour in spec section 5.6 and the list states in 5.3.
@MainActor
final class DevicesViewModelTests: XCTestCase {

    func testDelayedReadCannotOverwriteConfirmedControl() async {
        let api = StubAPIClient()
        api.controlResults = [.success(.fixture(state: .on, version: 2))]
        api.listResults = [.success([.fixture()]), .success([.fixture()])]
        let (viewModel, _) = makeViewModel(api)
        await viewModel.loadIfNeeded()
        let gate = AsyncGate()
        api.readGate = { await gate.wait() }
        let read = Task { await viewModel.refresh() }
        while !(await gate.hasWaiter()) { await Task.yield() }
        await viewModel.setState(viewModel.devices[0], to: .on)
        await gate.open()
        await read.value
        XCTAssertEqual(viewModel.devices.first?.version, 2)
        XCTAssertEqual(viewModel.devices.first?.state, .on)
    }

    private func makeViewModel(_ api: StubAPIClient) -> (DevicesViewModel, SessionController) {
        let session = makeSignedInSession(api)
        let control = DeviceControlService(api: api, session: session)
        return (DevicesViewModel(control: control, session: session), session)
    }

    // MARK: - Loading

    func testLoadedListShowsDevices() async {
        let api = StubAPIClient()
        api.listResults = [.success([.fixture()])]
        let (viewModel, _) = makeViewModel(api)

        await viewModel.loadIfNeeded()

        XCTAssertEqual(viewModel.phase, .loaded)
        XCTAssertEqual(viewModel.devices.count, 1)
        XCTAssertFalse(viewModel.isShowingStaleData)
    }

    func testEmptyAccountReportsEmptyRatherThanFailure() async {
        let api = StubAPIClient()
        api.listResults = [.success([])]
        let (viewModel, _) = makeViewModel(api)

        await viewModel.loadIfNeeded()

        XCTAssertTrue(viewModel.isEmpty)
        XCTAssertEqual(viewModel.phase, .loaded)
    }

    func testInitialLoadFailureOffersRetryWithoutInventingDevices() async {
        let api = StubAPIClient()
        api.listResults = [.failure(APIError.network(message: "You appear to be offline."))]
        let (viewModel, _) = makeViewModel(api)

        await viewModel.loadIfNeeded()

        XCTAssertEqual(viewModel.phase, .failed("You appear to be offline."))
        XCTAssertTrue(viewModel.devices.isEmpty, "a failed load must not fabricate devices")
    }

    func testFailedRefreshKeepsTheListAndLabelsItStale() async {
        let api = StubAPIClient()
        api.listResults = [
            .success([.fixture()]),
            .failure(APIError.network(message: "You appear to be offline."))
        ]
        let (viewModel, _) = makeViewModel(api)

        await viewModel.loadIfNeeded()
        await viewModel.refresh()

        // Section 5.3: keep showing what we have, but never imply it is fresh.
        XCTAssertEqual(viewModel.devices.count, 1)
        XCTAssertTrue(viewModel.isShowingStaleData)
        XCTAssertEqual(viewModel.phase, .loaded)
    }

    // MARK: - Control

    func testSuccessfulChangeAdoptsTheServerResponse() async {
        let api = StubAPIClient()
        let device = Device.fixture()
        api.listResults = [.success([device])]
        api.controlResults = [.success(.fixture(state: .on, version: 2))]
        let (viewModel, _) = makeViewModel(api)
        await viewModel.loadIfNeeded()

        await viewModel.setState(device, to: .on)

        XCTAssertEqual(viewModel.devices.first?.state, .on)
        XCTAssertEqual(viewModel.devices.first?.version, 2, "the version comes from the server, not arithmetic")
        XCTAssertNil(viewModel.pendingIntents[device.id])
    }

    func testControlSendsTheVersionThatWasOnScreen() async {
        let api = StubAPIClient()
        let device = Device.fixture(version: 7)
        api.listResults = [.success([device])]
        api.controlResults = [.success(.fixture(state: .on, version: 8))]
        let (viewModel, _) = makeViewModel(api)
        await viewModel.loadIfNeeded()

        await viewModel.setState(device, to: .on)

        XCTAssertEqual(api.calls.last, .control(id: "dev_01", state: .on, expectedVersion: 7))
    }

    func testRejectionRestoresTheConfirmedStateAndExplains() async {
        let api = StubAPIClient()
        let device = Device.fixture()
        api.listResults = [.success([device])]
        api.controlResults = [.failure(APIError.api(
            code: "RATE_LIMITED", message: "Too many requests. Try again shortly.",
            field: nil, status: 429
        ))]
        let (viewModel, _) = makeViewModel(api)
        await viewModel.loadIfNeeded()

        await viewModel.setState(device, to: .on)

        XCTAssertEqual(viewModel.devices.first?.state, .off, "the confirmed state is restored")
        XCTAssertNil(viewModel.pendingIntents[device.id])
        XCTAssertEqual(viewModel.notice?.message, "Too many requests. Try again shortly.")
    }

    func testVersionConflictRefetchesAndSaysItChangedElsewhere() async {
        let api = StubAPIClient()
        let device = Device.fixture()
        api.listResults = [.success([device])]
        api.controlResults = [.failure(APIError.api(
            code: "DEVICE_VERSION_CONFLICT", message: "This device changed.", field: nil, status: 409
        ))]
        api.getResults = [.success(.fixture(state: .on, version: 2))]
        let (viewModel, _) = makeViewModel(api)
        await viewModel.loadIfNeeded()

        await viewModel.setState(device, to: .on)

        XCTAssertEqual(viewModel.devices.first?.version, 2, "the refetched device replaces the stale one")
        XCTAssertEqual(viewModel.notice?.title, "That device changed")
        XCTAssertEqual(api.callCount { if case .get = $0 { return true }; return false }, 1)
    }

    /// Spec section 5.6 step 8, the important one.
    func testUnknownOutcomeReadsAndNeverSendsTheInverse() async {
        let api = StubAPIClient()
        let device = Device.fixture()
        api.listResults = [.success([device])]
        api.controlResults = [.failure(APIError.unknownOutcome)]
        // The write actually landed; the response was what got lost.
        api.getResults = [.success(.fixture(state: .on, version: 2))]
        let (viewModel, _) = makeViewModel(api)
        await viewModel.loadIfNeeded()

        await viewModel.setState(device, to: .on)

        XCTAssertEqual(
            api.callCount { if case .control = $0 { return true }; return false }, 1,
            "exactly one control was sent: no retry, and above all no inverse command"
        )
        XCTAssertEqual(viewModel.devices.first?.state, .on, "the truth comes from the read")
        XCTAssertEqual(viewModel.notice?.title, "Connection interrupted")
    }

    func testUnknownOutcomeWhoseReadAlsoFailsAdmitsItDoesNotKnow() async {
        let api = StubAPIClient()
        let device = Device.fixture()
        api.listResults = [.success([device])]
        api.controlResults = [.failure(APIError.unknownOutcome)]
        api.getResults = [.failure(APIError.network(message: "offline"))]
        let (viewModel, _) = makeViewModel(api)
        await viewModel.loadIfNeeded()

        await viewModel.setState(device, to: .on)

        XCTAssertEqual(viewModel.devices.first?.state, .off, "unconfirmed intent never becomes state")
        XCTAssertTrue(viewModel.notice?.message.contains("do not know") == true)
    }

    func testSecondTapWhileInFlightIsIgnored() async {
        let api = StubAPIClient()
        let device = Device.fixture()
        api.listResults = [.success([device])]
        api.controlResults = [.success(.fixture(state: .on, version: 2))]
        let (viewModel, _) = makeViewModel(api)
        await viewModel.loadIfNeeded()

        // Hold the first control open so the second tap lands while it is
        // genuinely in flight rather than merely soon after.
        let started = expectation(description: "first control reached the client")
        let gate = AsyncGate()
        api.gate = { started.fulfill(); await gate.wait() }

        let first = Task { await viewModel.setState(device, to: .on) }
        await fulfillment(of: [started], timeout: 2)

        // Section 5.6 step 3: this one switch is inert until the first settles.
        await viewModel.setState(device, to: .off)
        await gate.open()
        await first.value

        XCTAssertEqual(
            api.callCount { if case .control = $0 { return true }; return false }, 1,
            "a second tap must not queue a contradictory write"
        )
        XCTAssertEqual(viewModel.devices.first?.state, .on)
    }

    func testNotFoundRemovesTheDevice() async {
        let api = StubAPIClient()
        let device = Device.fixture()
        api.listResults = [.success([device])]
        api.controlResults = [.failure(APIError.api(
            code: "DEVICE_NOT_FOUND", message: "That device does not exist.", field: nil, status: 404
        ))]
        let (viewModel, _) = makeViewModel(api)
        await viewModel.loadIfNeeded()

        await viewModel.setState(device, to: .on)

        XCTAssertTrue(viewModel.devices.isEmpty)
        XCTAssertEqual(viewModel.notice?.title, "Device unavailable")
    }

    func testDisplayedStateShowsIntentWhilePendingAndFactOtherwise() async {
        let api = StubAPIClient()
        let device = Device.fixture()
        api.listResults = [.success([device])]
        let (viewModel, _) = makeViewModel(api)
        await viewModel.loadIfNeeded()

        XCTAssertEqual(viewModel.displayedState(for: device), .off)
        XCTAssertFalse(viewModel.isPending(device))
    }
}
