import XCTest
@testable import IoTSwitch

/// Spec sections 5.5 and 6.2.
@MainActor
final class AddDeviceViewModelTests: XCTestCase {

    private func makeViewModel(_ api: StubAPIClient) -> AddDeviceViewModel {
        AddDeviceViewModel(api: api, session: makeSignedInSession(api))
    }

    func testASuccessfulAddReturnsTheDevice() async {
        let api = StubAPIClient()
        api.addResults = [.success(.fixture(name: "Bedroom Lamp"))]
        let viewModel = makeViewModel(api)
        viewModel.name = "  Bedroom Lamp  "

        let device = await viewModel.submit()

        XCTAssertEqual(device?.name, "Bedroom Lamp")
        XCTAssertEqual(api.calls.last, .add(name: "Bedroom Lamp", key: api.lastAddKey ?? ""))
    }

    func testANameConflictKeepsWhatWasTyped() async {
        let api = StubAPIClient()
        api.addResults = [.failure(APIError.api(
            code: "DEVICE_NAME_CONFLICT", message: "A device with this name already exists.",
            field: nil, status: 409
        ))]
        let viewModel = makeViewModel(api)
        viewModel.name = "Bedroom Lamp"

        let device = await viewModel.submit()

        XCTAssertNil(device, "the sheet must stay open")
        XCTAssertEqual(viewModel.nameError, "A device with this name already exists.")
        XCTAssertEqual(viewModel.name, "Bedroom Lamp", "the typed name survives the failure")
    }

    func testAnEmptyNameIsCaughtBeforeAnyRequest() async {
        let api = StubAPIClient()
        let viewModel = makeViewModel(api)
        viewModel.name = "   "

        let device = await viewModel.submit()

        XCTAssertNil(device)
        XCTAssertNotNil(viewModel.nameError)
        XCTAssertTrue(api.calls.isEmpty, "nothing is sent for a name that cannot be valid")
    }

    /// Section 6.2: a retry after a lost response must not create a second
    /// device, which is what reusing the key buys.
    func testRetryingTheSameNameReusesTheIdempotencyKey() async {
        let api = StubAPIClient()
        api.addResults = [
            .failure(APIError.unknownOutcome),
            .success(.fixture(name: "Bedroom Lamp"))
        ]
        let viewModel = makeViewModel(api)
        viewModel.name = "Bedroom Lamp"

        _ = await viewModel.submit()
        XCTAssertNotNil(viewModel.formError, "the user is told the outcome is unknown")
        _ = await viewModel.submit()

        let keys = api.addKeys
        XCTAssertEqual(keys.count, 2)
        XCTAssertEqual(keys[0], keys[1], "the same submission keeps its key")
    }

    /// The backend refuses a key replayed with different arguments, so editing
    /// the name has to mint a new one or the retry fails confusingly.
    func testEditingTheNameMintsANewIdempotencyKey() async {
        let api = StubAPIClient()
        api.addResults = [
            .failure(APIError.unknownOutcome),
            .success(.fixture(name: "Desk Fan"))
        ]
        let viewModel = makeViewModel(api)
        viewModel.name = "Bedroom Lamp"
        _ = await viewModel.submit()

        viewModel.name = "Desk Fan"
        _ = await viewModel.submit()

        let keys = api.addKeys
        XCTAssertEqual(keys.count, 2)
        XCTAssertNotEqual(keys[0], keys[1], "a different request needs a different key")
    }

    func testAnOverLongNameIsRejectedLocally() async {
        let api = StubAPIClient()
        let viewModel = makeViewModel(api)
        viewModel.name = String(repeating: "x", count: 65)

        let device = await viewModel.submit()

        XCTAssertNil(device)
        XCTAssertNotNil(viewModel.nameError)
        XCTAssertTrue(api.calls.isEmpty)
    }
}

extension StubAPIClient {
    var addKeys: [String] {
        calls.compactMap { if case let .add(_, key) = $0 { return key }; return nil }
    }
    var lastAddKey: String? { addKeys.last }
}
