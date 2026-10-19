import XCTest
@testable import IoTSwitch

/// Spec section 5.2 as revised: no credential fields in the app; Log In and
/// Sign Up open the authorization server's page in the system browser.
@MainActor
final class AuthViewModelTests: XCTestCase {

    private func make(_ api: StubAPIClient, _ web: StubWebAuthenticator) -> (AuthViewModel, SessionController) {
        let session = SessionController(
            api: api, storage: InMemoryTokenStorage(),
            auth: .development(URL(string: "http://localhost:4000")!),
            web: web, keyring: DPoPKeyring(store: InMemoryDPoPKeyStore())
        )
        return (AuthViewModel(session: session), session)
    }

    func testSignUpOpensTheBrowserOnTheSignUpForm() async {
        let api = StubAPIClient()
        let web = StubWebAuthenticator()
        api.pushResults = [.success(URL(string: "http://localhost:4000/authorize?request_uri=x")!)]
        let (viewModel, _) = make(api, web)

        await viewModel.start(.signUp)

        guard case let .push(request)? = api.calls.first else { return XCTFail("nothing was pushed") }
        XCTAssertTrue(request.signUp)
        XCTAssertEqual(web.opened.count, 1)
    }

    func testOnlyTheTappedButtonShowsProgress() async {
        let api = StubAPIClient()
        let web = StubWebAuthenticator()
        api.pushResults = [.success(URL(string: "http://localhost:4000/authorize")!)]
        let (viewModel, _) = make(api, web)
        var modeWhileOpen: AuthViewModel.Mode?
        web.respond = { _ in
            modeWhileOpen = viewModel.activeMode
            throw AuthError.cancelled
        }

        await viewModel.start(.signUp)

        XCTAssertEqual(modeWhileOpen, .signUp)
        XCTAssertNil(viewModel.activeMode)
    }

    func testClosingTheSheetShowsNoError() async {
        let api = StubAPIClient()
        let web = StubWebAuthenticator()
        api.pushResults = [.success(URL(string: "http://localhost:4000/authorize")!)]
        web.respond = { _ in throw AuthError.cancelled }
        let (viewModel, session) = make(api, web)

        await viewModel.start(.logIn)

        XCTAssertNil(viewModel.errorMessage, "closing the sheet is a choice, not a failure")
        XCTAssertFalse(viewModel.isWorking)
        XCTAssertFalse(session.isSignedIn)
    }

    func testAnUntrustworthyResponseIsExplained() async {
        let api = StubAPIClient()
        let web = StubWebAuthenticator()
        api.pushResults = [.success(URL(string: "http://localhost:4000/authorize")!)]
        web.respond = { _ in URL(string: "com.example.iotswitch:/oauth/callback?code=c&state=wrong&iss=http://localhost:4000")! }
        let (viewModel, _) = make(api, web)

        await viewModel.start(.logIn)

        XCTAssertEqual(viewModel.errorMessage, AuthError.stateMismatch.userMessage)
    }

    func testAnUnreachableServerIsAReadableError() async {
        let api = StubAPIClient()
        let web = StubWebAuthenticator()
        api.pushResults = [.failure(APIError.network(message: "Could not reach the server."))]
        let (viewModel, _) = make(api, web)

        await viewModel.start(.logIn)

        XCTAssertEqual(viewModel.errorMessage, "Could not reach the server.")
        XCTAssertTrue(web.opened.isEmpty, "the browser is not opened for a request the server never accepted")
    }
}
