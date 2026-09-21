import XCTest
@testable import IoTSwitch

/// Spec section 5.2.
@MainActor
final class AuthViewModelTests: XCTestCase {

    private func makeViewModel(_ api: StubAPIClient) -> AuthViewModel {
        AuthViewModel(session: SessionController(api: api, storage: InMemoryTokenStorage()))
    }

    func testLogInSignsTheUserIn() async {
        let api = StubAPIClient()
        api.sessionResults = [.success(.fixture())]
        let viewModel = makeViewModel(api)
        viewModel.username = "  sam  "
        viewModel.password = "correct horse battery staple"

        await viewModel.submit()

        XCTAssertEqual(api.calls.first, .logIn("sam"), "the username is trimmed")
        XCTAssertNil(viewModel.formError)
    }

    func testThePasswordIsNotTrimmed() async {
        let api = StubAPIClient()
        api.sessionResults = [.success(.fixture())]
        let viewModel = makeViewModel(api)
        viewModel.username = "sam"
        viewModel.password = "  spaces matter  "

        await viewModel.submit()

        // Trimming here would silently change the password and make a
        // generated one impossible to use.
        XCTAssertNil(viewModel.passwordError)
        XCTAssertNil(viewModel.formError)
    }

    func testAFieldScopedErrorLandsOnItsField() async {
        let api = StubAPIClient()
        api.sessionResults = [.failure(APIError.api(
            code: "USERNAME_TAKEN", message: "That username is already taken.",
            field: "username", status: 409
        ))]
        let viewModel = makeViewModel(api)
        viewModel.mode = .signUp
        viewModel.username = "sam"
        viewModel.password = "correct horse battery staple"

        await viewModel.submit()

        XCTAssertEqual(viewModel.usernameError, "That username is already taken.")
        XCTAssertNil(viewModel.formError, "a field error is not also shown at form level")
    }

    func testAFailedLogInIsAReadableFormError() async {
        let api = StubAPIClient()
        api.sessionResults = [.failure(APIError.unauthenticated)]
        let viewModel = makeViewModel(api)
        viewModel.username = "sam"
        viewModel.password = "wrong-password"

        await viewModel.submit()

        XCTAssertNotNil(viewModel.formError)
        XCTAssertNil(viewModel.usernameError, "never hint which half was wrong")
        XCTAssertNil(viewModel.passwordError)
    }

    func testEmptyFieldsAreCaughtBeforeAnyRequest() async {
        let api = StubAPIClient()
        let viewModel = makeViewModel(api)
        viewModel.username = "   "
        viewModel.password = "something"

        await viewModel.submit()

        XCTAssertNotNil(viewModel.usernameError)
        XCTAssertTrue(api.calls.isEmpty)
    }

    func testSwitchingModeClearsErrorsFromThePreviousAttempt() async {
        let api = StubAPIClient()
        api.sessionResults = [.failure(APIError.unauthenticated)]
        let viewModel = makeViewModel(api)
        viewModel.username = "sam"
        viewModel.password = "wrong-password"
        await viewModel.submit()
        XCTAssertNotNil(viewModel.formError)

        viewModel.switchTo(.signUp)

        XCTAssertNil(viewModel.formError, "the message described the other mode's attempt")
    }

    func testCannotSubmitWithoutBothFields() {
        let api = StubAPIClient()
        let viewModel = makeViewModel(api)

        XCTAssertFalse(viewModel.canSubmit)
        viewModel.username = "sam"
        XCTAssertFalse(viewModel.canSubmit)
        viewModel.password = "correct horse battery staple"
        XCTAssertTrue(viewModel.canSubmit)
    }
}
