import XCTest
@testable import IoTSwitch

/// Transport behaviour: status mapping, and the distinction section 5.6
/// depends on between a failed read and a mutation of unknown outcome.
final class APIClientTests: XCTestCase {

    private func makeClient() -> HTTPAPIClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        return HTTPAPIClient(
            baseURL: URL(string: "http://localhost:4000")!,
            session: URLSession(configuration: configuration)
        )
    }

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    func testDecodesADeviceList() async throws {
        StubURLProtocol.handler = { _ in
            (200, Data("""
            {"devices":[{"id":"dev_01","name":"Bedroom Lamp","state":"off","version":1,
            "createdAt":"2026-09-21T10:00:00Z","updatedAt":"2026-09-21T10:00:00Z"}]}
            """.utf8))
        }

        let devices = try await makeClient().listDevices(accessToken: "t")

        XCTAssertEqual(devices.count, 1)
        XCTAssertEqual(devices.first?.state, .off)
        XCTAssertEqual(devices.first?.version, 1)
    }

    func testA401BecomesUnauthenticatedRatherThanAGenericError() async {
        StubURLProtocol.handler = { _ in (401, Data("""
        {"error":{"code":"UNAUTHENTICATED","message":"Sign in to continue.","requestId":"req_1"}}
        """.utf8)) }

        do {
            _ = try await makeClient().listDevices(accessToken: "t")
            XCTFail("expected a failure")
        } catch {
            // The session layer keys its refresh-once behaviour on this exact
            // case, so it must not be folded into `.api`.
            XCTAssertEqual(error as? APIError, .unauthenticated)
        }
    }

    func testAStructuredErrorKeepsItsCodeAndField() async {
        StubURLProtocol.handler = { _ in (409, Data("""
        {"error":{"code":"DEVICE_VERSION_CONFLICT","message":"This device changed.",
        "requestId":"req_1"}}
        """.utf8)) }

        do {
            _ = try await makeClient().controlDevice(
                id: "dev_01", state: .on, expectedVersion: 1, accessToken: "t")
            XCTFail("expected a failure")
        } catch let error as APIError {
            XCTAssertTrue(error.isVersionConflict)
            XCTAssertEqual(error.userMessage, "This device changed.")
        } catch {
            XCTFail("wrong error type")
        }
    }

    func testAFailedReadIsRetryable() async {
        StubURLProtocol.handler = { _ in throw URLError(.timedOut) }

        do {
            _ = try await makeClient().listDevices(accessToken: "t")
            XCTFail("expected a failure")
        } catch let error as APIError {
            guard case .network = error else {
                return XCTFail("a read that times out is an ordinary network failure, got \(error)")
            }
        } catch {
            XCTFail("wrong error type")
        }
    }

    /// The distinction the whole of section 5.6 step 8 rests on.
    func testAMutationThatFailsInTransitHasAnUnknownOutcome() async {
        StubURLProtocol.handler = { _ in throw URLError(.networkConnectionLost) }

        do {
            _ = try await makeClient().controlDevice(
                id: "dev_01", state: .on, expectedVersion: 1, accessToken: "t")
            XCTFail("expected a failure")
        } catch let error as APIError {
            XCTAssertEqual(error, .unknownOutcome,
                           "the write may have applied; treating it as a plain failure invites an inverse retry")
        } catch {
            XCTFail("wrong error type")
        }
    }

    func testCreateSendsTheIdempotencyKeyAsAHeader() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Idempotency-Key"), "key-1")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer t")
            return (201, Data("""
            {"device":{"id":"dev_01","name":"Bedroom Lamp","state":"off","version":1,
            "createdAt":"2026-09-21T10:00:00Z","updatedAt":"2026-09-21T10:00:00Z"}}
            """.utf8))
        }

        let device = try await makeClient().addDevice(
            name: "Bedroom Lamp", idempotencyKey: "key-1", accessToken: "t")

        XCTAssertEqual(device.state, .off, "new devices start Off")
    }
}

/// Serves canned responses so the client can be exercised without a server.
final class StubURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var handler: ((URLRequest) throws -> (Int, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }
        do {
            // Body streams are not readable from httpBody once URLSession has
            // taken the request, so header assertions happen on the original.
            let (status, data) = try handler(request)
            let response = HTTPURLResponse(
                url: request.url!, statusCode: status,
                httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"]
            )!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
