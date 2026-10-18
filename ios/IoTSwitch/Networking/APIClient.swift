import Foundation

/// Everything the app can ask the backend for. A protocol so the view models
/// can be driven by a stub in tests without a running server.
protocol APIClient: Sendable {
    // MARK: The authorization server (OAuth 2.1 with PAR, PKCE and DPoP)

    /// Pushes the authorization request (RFC 9126) and returns the URL to open
    /// in the browser, which carries only the client id and a request_uri.
    func pushAuthorization(_ request: AuthorizationRequest) async throws -> URL
    func exchangeCode(code: String, verifier: String, redirectURI: String) async throws -> TokenResponse
    /// A rejected refresh token surfaces as `APIError.unauthenticated`.
    func refresh(refreshToken: String) async throws -> TokenResponse
    func revoke(refreshToken: String) async throws
    func me(accessToken: String) async throws -> Account

    // MARK: Devices

    func listDevices(accessToken: String) async throws -> [Device]
    func getDevice(id: String, accessToken: String) async throws -> Device
    func controlDevice(
        id: String, state: DeviceState, expectedVersion: Int, accessToken: String
    ) async throws -> Device
    func addDevice(name: String, idempotencyKey: String, accessToken: String) async throws -> Device
}

struct HTTPAPIClient: APIClient {
    let baseURL: URL
    let auth: AuthConfiguration
    let session: URLSession
    /// Signs a DPoP proof for every request when present. Without it (tests,
    /// previews) tokens are sent as plain bearer tokens.
    let keyring: DPoPKeyring?
    private let nonces = DPoPNonceCache()

    init(baseURL: URL, auth: AuthConfiguration? = nil, session: URLSession = .shared, keyring: DPoPKeyring? = nil) {
        self.baseURL = baseURL
        self.auth = auth ?? .development(baseURL)
        self.session = session
        self.keyring = keyring
    }

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    // MARK: - Authorization server

    func pushAuthorization(_ request: AuthorizationRequest) async throws -> URL {
        var fields = [
            "client_id": AuthConfiguration.clientID,
            "redirect_uri": request.redirectURI,
            "response_type": "code",
            "code_challenge": request.codeChallenge,
            "code_challenge_method": "S256",
            "state": request.state,
            "scope": "devices:read devices:control devices:create offline_access",
            "dpop_jkt": request.dpopThumbprint
        ]
        if request.signUp { fields["prompt"] = "create" }
        let data = try await perform(.oauth("POST", "/par", fields), token: nil, isMutation: false)
        let pushed = try decode(PushedAuthorizationResponse.self, data)

        var components = URLComponents(url: auth.authBaseURL.appendingPathComponent("authorize"), resolvingAgainstBaseURL: false)
        components?.queryItems = [
            URLQueryItem(name: "client_id", value: AuthConfiguration.clientID),
            URLQueryItem(name: "request_uri", value: pushed.requestURI)
        ]
        guard let url = components?.url else { throw APIError.network(message: "Could not build the sign-in URL.") }
        return url
    }

    func exchangeCode(code: String, verifier: String, redirectURI: String) async throws -> TokenResponse {
        let data = try await perform(.oauth("POST", "/token", [
            "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
            "redirect_uri": redirectURI, "client_id": AuthConfiguration.clientID
        ]), token: nil, isMutation: false)
        return try decode(TokenResponse.self, data)
    }

    func refresh(refreshToken: String) async throws -> TokenResponse {
        do {
            let data = try await perform(.oauth("POST", "/token", [
                "grant_type": "refresh_token", "refresh_token": refreshToken, "client_id": AuthConfiguration.clientID
            ]), token: nil, isMutation: false)
            return try decode(TokenResponse.self, data)
        } catch let error as APIError where error.isRejectedCredential {
            // The authorization server says this session is over. Distinct
            // from a transport failure, after which the session survives.
            throw APIError.unauthenticated
        }
    }

    func revoke(refreshToken: String) async throws {
        _ = try await perform(.oauth("POST", "/revoke", [
            "token": refreshToken, "token_type_hint": "refresh_token", "client_id": AuthConfiguration.clientID
        ]), token: nil, isMutation: true)
    }

    func me(accessToken: String) async throws -> Account {
        let data = try await perform(.api("GET", "/v1/auth/me", nil, [:]), token: accessToken, isMutation: false)
        return try decode(AccountResponse.self, data).account
    }

    // MARK: - Devices

    func listDevices(accessToken: String) async throws -> [Device] {
        let data = try await perform(.api("GET", "/v1/devices", nil, [:]), token: accessToken, isMutation: false)
        return try decode(DeviceListResponse.self, data).devices
    }

    func getDevice(id: String, accessToken: String) async throws -> Device {
        let data = try await perform(.api("GET", "/v1/devices/\(pathEscaped(id))", nil, [:]),
                                     token: accessToken, isMutation: false)
        return try decode(DeviceResponse.self, data).device
    }

    func controlDevice(
        id: String, state: DeviceState, expectedVersion: Int, accessToken: String
    ) async throws -> Device {
        let data = try await perform(.api(
            "PUT", "/v1/devices/\(pathEscaped(id))/state",
            ["state": state.rawValue, "expectedVersion": expectedVersion], [:]
        ), token: accessToken, isMutation: true)
        return try decode(DeviceResponse.self, data).device
    }

    func addDevice(name: String, idempotencyKey: String, accessToken: String) async throws -> Device {
        let data = try await perform(.api(
            "POST", "/v1/devices", ["name": name], ["Idempotency-Key": idempotencyKey]
        ), token: accessToken, isMutation: true)
        return try decode(DeviceResponse.self, data).device
    }

    // MARK: - Transport

    private enum Endpoint {
        /// A form-encoded request to the authorization server.
        case oauth(String, String, [String: String])
        /// A JSON request to the REST API.
        case api(String, String, [String: any Sendable]?, [String: String])
    }

    private func pathEscaped(_ component: String) -> String {
        component.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? component
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do {
            return try Self.decoder.decode(T.self, from: data)
        } catch {
            throw APIError.decoding(message: String(describing: error))
        }
    }

    private func request(_ endpoint: Endpoint, token: String?) throws -> URLRequest {
        let method: String
        let url: URL
        var request: URLRequest
        switch endpoint {
        case let .oauth(verb, path, fields):
            method = verb
            url = auth.authBaseURL.appendingPathComponent(String(path.dropFirst()))
            request = URLRequest(url: url)
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            var form = URLComponents()
            form.queryItems = fields.sorted { $0.key < $1.key }.map { URLQueryItem(name: $0.key, value: $0.value) }
            // `+` is a space in form encoding, and URLComponents leaves it alone.
            request.httpBody = Data((form.percentEncodedQuery ?? "").replacingOccurrences(of: "+", with: "%2B").utf8)
        case let .api(verb, path, body, headers):
            method = verb
            guard let resolved = URL(string: path, relativeTo: baseURL)?.absoluteURL else {
                throw APIError.network(message: "Could not build a request URL.")
            }
            url = resolved
            request = URLRequest(url: url)
            for (key, value) in headers { request.setValue(value, forHTTPHeaderField: key) }
            if let body {
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
                request.httpBody = try JSONSerialization.data(withJSONObject: body)
            }
        }
        request.httpMethod = method
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        // DPoP: a fresh proof for this method and URL, hashing the access
        // token when one is sent, echoing the server's latest nonce.
        if let keyring {
            let key = try keyring.key()
            request.setValue(try key.proof(method: method, url: url, accessToken: token, nonce: nonces.current),
                             forHTTPHeaderField: "DPoP")
            if let token { request.setValue("DPoP \(token)", forHTTPHeaderField: "Authorization") }
        } else if let token {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        return request
    }

    private func perform(_ endpoint: Endpoint, token: String?, isMutation: Bool, retried: Bool = false) async throws -> Data {
        let request = try request(endpoint, token: token)

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
        nonces.update(http.value(forHTTPHeaderField: "DPoP-Nonce"))

        // The server wants a fresh nonce. The request was refused before it
        // did anything, so it is safe to send again — once.
        if !retried, keyring != nil, Self.asksForNonce(http, data) {
            return try await perform(endpoint, token: token, isMutation: isMutation, retried: true)
        }

        if (200..<300).contains(http.statusCode) { return data }
        if http.statusCode == 401 { throw APIError.unauthenticated }

        if let envelope = try? Self.decoder.decode(ErrorEnvelope.self, from: data) {
            throw APIError.api(code: envelope.error.code, message: envelope.error.message,
                               field: envelope.error.field, status: http.statusCode)
        }
        if let oauth = try? Self.decoder.decode(OAuthErrorResponse.self, from: data) {
            throw APIError.api(code: oauth.error, message: oauth.errorDescription ?? oauth.error,
                               field: nil, status: http.statusCode)
        }
        throw APIError.api(
            code: "UNKNOWN", message: "The server returned an error (\(http.statusCode)).",
            field: nil, status: http.statusCode
        )
    }

    private static func asksForNonce(_ http: HTTPURLResponse, _ data: Data) -> Bool {
        if http.statusCode == 401,
           http.value(forHTTPHeaderField: "WWW-Authenticate")?.contains("use_dpop_nonce") == true {
            return true
        }
        if http.statusCode == 400, let oauth = try? decoder.decode(OAuthErrorResponse.self, from: data) {
            return oauth.error == "use_dpop_nonce"
        }
        return false
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
