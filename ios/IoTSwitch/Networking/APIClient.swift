import Foundation

/// Everything the app can ask the backend for. A protocol so the view models
/// can be driven by a stub in tests without a running server.
protocol APIClient: Sendable {
    func signUp(username: String, password: String) async throws -> SessionResponse
    func logIn(username: String, password: String) async throws -> SessionResponse
    func refresh(refreshToken: String) async throws -> RefreshResponse
    func logOut(accessToken: String) async throws

    func listDevices(accessToken: String) async throws -> [Device]
    func getDevice(id: String, accessToken: String) async throws -> Device
    func controlDevice(
        id: String, state: DeviceState, expectedVersion: Int, accessToken: String
    ) async throws -> Device
    func addDevice(name: String, idempotencyKey: String, accessToken: String) async throws -> Device
}

struct HTTPAPIClient: APIClient {
    let baseURL: URL
    let session: URLSession

    init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
    }

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    // MARK: - Authentication

    func signUp(username: String, password: String) async throws -> SessionResponse {
        try await send("POST", "/v1/auth/signup", body: ["username": username, "password": password])
    }

    func logIn(username: String, password: String) async throws -> SessionResponse {
        try await send("POST", "/v1/auth/login", body: ["username": username, "password": password])
    }

    func refresh(refreshToken: String) async throws -> RefreshResponse {
        try await send("POST", "/v1/auth/refresh", body: ["refreshToken": refreshToken])
    }

    func logOut(accessToken: String) async throws {
        _ = try await sendExpectingNoContent("POST", "/v1/auth/logout", token: accessToken)
    }

    // MARK: - Devices

    func listDevices(accessToken: String) async throws -> [Device] {
        let response: DeviceListResponse = try await send("GET", "/v1/devices", token: accessToken)
        return response.devices
    }

    func getDevice(id: String, accessToken: String) async throws -> Device {
        let response: DeviceResponse = try await send(
            "GET", "/v1/devices/\(pathEscaped(id))", token: accessToken
        )
        return response.device
    }

    func controlDevice(
        id: String, state: DeviceState, expectedVersion: Int, accessToken: String
    ) async throws -> Device {
        let response: DeviceResponse = try await send(
            "PUT", "/v1/devices/\(pathEscaped(id))/state",
            body: ["state": state.rawValue, "expectedVersion": expectedVersion],
            token: accessToken,
            isMutation: true
        )
        return response.device
    }

    func addDevice(name: String, idempotencyKey: String, accessToken: String) async throws -> Device {
        let response: DeviceResponse = try await send(
            "POST", "/v1/devices",
            body: ["name": name],
            token: accessToken,
            headers: ["Idempotency-Key": idempotencyKey],
            isMutation: true
        )
        return response.device
    }

    // MARK: - Transport

    private func pathEscaped(_ component: String) -> String {
        component.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? component
    }

    private func request(
        _ method: String, _ path: String, body: [String: any Sendable]?,
        token: String?, headers: [String: String]
    ) throws -> URLRequest {
        guard let url = URL(string: path, relativeTo: baseURL) else {
            throw APIError.network(message: "Could not build a request URL.")
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let token {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        }
        return request
    }

    private func send<T: Decodable>(
        _ method: String, _ path: String, body: [String: any Sendable]? = nil,
        token: String? = nil, headers: [String: String] = [:], isMutation: Bool = false
    ) async throws -> T {
        let data = try await perform(method, path, body: body, token: token, headers: headers, isMutation: isMutation)
        do {
            return try Self.decoder.decode(T.self, from: data)
        } catch {
            throw APIError.decoding(message: String(describing: error))
        }
    }

    private func sendExpectingNoContent(
        _ method: String, _ path: String, token: String? = nil
    ) async throws -> Data {
        try await perform(method, path, body: nil, token: token, headers: [:], isMutation: true)
    }

    private func perform(
        _ method: String, _ path: String, body: [String: any Sendable]?,
        token: String?, headers: [String: String], isMutation: Bool
    ) async throws -> Data {
        let request = try request(method, path, body: body, token: token, headers: headers)

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch let error as URLError {
            // A mutation that failed in transit may or may not have been
            // applied. Spec section 5.6 forbids guessing, so the two are
            // surfaced as different errors and only reads are freely retried.
            throw isMutation ? APIError.unknownOutcome : APIError.network(message: Self.describe(error))
        } catch {
            throw isMutation ? APIError.unknownOutcome : APIError.network(message: error.localizedDescription)
        }

        guard let http = response as? HTTPURLResponse else {
            throw APIError.network(message: "The server sent an unexpected response.")
        }

        if (200..<300).contains(http.statusCode) { return data }
        if http.statusCode == 401 { throw APIError.unauthenticated }

        if let envelope = try? Self.decoder.decode(ErrorEnvelope.self, from: data) {
            throw APIError.api(
                code: envelope.error.code,
                message: envelope.error.message,
                field: envelope.error.field,
                status: http.statusCode
            )
        }
        throw APIError.api(
            code: "UNKNOWN", message: "The server returned an error (\(http.statusCode)).",
            field: nil, status: http.statusCode
        )
    }

    private static func describe(_ error: URLError) -> String {
        switch error.code {
        case .notConnectedToInternet: return "You appear to be offline."
        case .timedOut: return "The server took too long to respond."
        case .cannotConnectToHost, .cannotFindHost: return "Could not reach the server."
        default: return error.localizedDescription
        }
    }
}
