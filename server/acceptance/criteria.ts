/**
 * The acceptance criteria from spec section 12, each tied to the tests that
 * establish it.
 *
 * The point is not ceremony. It is to make the gap visible: a handful of these
 * cannot be closed from a terminal at all, and without writing that down it is
 * easy to mistake a green suite for a finished product. Anything marked `gap`
 * needs a person with a host account or a physical device.
 *
 * Evidence is matched as a distinctive fragment of a test name, and each
 * fragment must match exactly one test. A renamed or deleted test therefore
 * fails the report rather than silently dropping coverage.
 */

export interface Criterion {
  id: string;
  scenario: string;
  /** Fragments of server-suite test names. Each must match exactly one. */
  evidence: string[];
  /** Swift tests under ios/. Listed, not run here — see the note in report.mjs. */
  ios?: string[];
  /** What this criterion still needs that no test can supply. */
  gap?: string;
  /**
   * Backends the evidence must have run on. Without them the criterion is
   * reported partial: the tests pass on PGlite and in-memory stores, but what
   * they claim is only shown on the real thing.
   */
  requires?: Array<'postgres' | 'redis'>;
}

export const CRITERIA: Criterion[] = [
  {
    id: 'AC-01', scenario: 'New registration',
    evidence: [
      'sign-up creates one account and rejects a duplicate under folding',
      'sign-up returns an account and a session'
    ],
    ios: ['SessionControllerTests.testSigningInPushesTheRequestAndKeepsOnlyTheRefreshToken']
  },
  {
    id: 'AC-02', scenario: 'Invalid or duplicate registration',
    evidence: [
      'usernames and passwords are validated at the boundary',
      'a duplicate username is a 409 naming the field',
      'a weak password is a 422 naming the field'
    ]
    // Since phase 3 these errors are shown on the hosted page, not in the app.
  },
  {
    id: 'AC-03', scenario: 'Login and logout',
    evidence: [
      'login succeeds, and failure is generic',
      'credential verification is case-insensitive on the username only',
      'logout invalidates access tokens that were already issued'
    ],
    ios: ['SessionControllerTests.testLogOutClearsLocalStateEvenIfRevocationFails']
  },
  {
    id: 'AC-04', scenario: 'Add a device',
    evidence: [
      'a new device starts off, at version 1',
      'creating a device returns 201 and an off device at version 1',
      'MCP and the REST API are the same devices, and the channel is recorded'
    ]
  },
  {
    id: 'AC-05', scenario: 'Fetch all devices',
    evidence: ['the list returns only this account, oldest first', 'devices are listed oldest first']
  },
  {
    id: 'AC-06', scenario: 'Fetch one device',
    evidence: [
      'a 404, exactly like one that does not exist',
      'indistinguishable from one that does not exist'
    ]
  },
  {
    id: 'AC-07', scenario: 'Control, and persistence across restart',
    evidence: [
      'a switch changes state and consumes exactly one version',
      'accounts, devices and state survive a full restart',
      'the four device operations work over MCP'
    ],
    ios: ['DevicesViewModelTests.testSuccessfulChangeAdoptsTheServerResponse']
  },
  {
    id: 'AC-08', scenario: 'Exactly two states',
    evidence: [
      'an invalid state is refused',
      'control requires expectedVersion, rejects invalid states, and detects staleness',
      'invalid arguments are rejected before the service sees them'
    ]
  },
  {
    id: 'AC-09', scenario: 'Duplicate creation under concurrency',
    evidence: [
      'AC-09: concurrent creates of the same name produce exactly one device',
      'AC-09: concurrent creates differing only by case still produce one device',
      'AC-09: a replayed idempotency key never creates a second device'
    ]
  },
  {
    id: 'AC-10', scenario: 'Concurrent control',
    evidence: [
      'AC-10: two writers holding the same version, exactly one wins',
      'AC-10: many writers on one version consume exactly one version',
      'AC-10: a no-op racing a real change never invents a version'
    ]
  },
  {
    id: 'AC-11', scenario: 'Ambiguous network outcome',
    evidence: [
      'replaying a successful control conflicts rather than inverting',
      'an idempotency key makes a replayed create return the original device',
      'an idempotency key reused for a different device is refused'
    ],
    ios: [
      'DevicesViewModelTests.testUnknownOutcomeReadsAndNeverSendsTheInverse',
      'APIClientTests.testAMutationThatFailsInTransitHasAnUnknownOutcome'
    ]
  },
  {
    id: 'AC-12', scenario: 'Anonymous MCP connection',
    evidence: [
      'a host can initialize without a token',
      'tool discovery works without a token and exposes no private data',
      'the public status tool reports signed out rather than failing',
      'a view can be read anonymously, before anyone has signed in'
    ]
  },
  {
    id: 'AC-13', scenario: 'MCP authentication entry',
    evidence: [
      'the presentation tools are public and link their views',
      'the auth view contains no credential fields'
    ],
    gap: 'Whether a host renders show_auth at all, and whether an app-initiated '
      + 'tool call raises its Connect prompt. FINDINGS Q1.'
  },
  {
    id: 'AC-14', scenario: 'External authorization',
    evidence: [
      'a full authorization issues a token bound to this resource',
      'authorization server metadata advertises what hosts gate on'
    ],
    gap: 'Claude and ChatGPT completing the flow against this server, with the '
      + 'client, version, plan and capabilities recorded. FINDINGS Q6.'
  },
  {
    id: 'AC-15', scenario: 'Credential isolation',
    evidence: [
      'a password is stored hashed and never trimmed',
      'tokens are stored hashed, not in the clear',
      'no view can hold a token, and none renders user data as markup',
      'sign-up returns an account and a session, and echoes no secrets',
      'logging a request with an Authorization header writes no token'
    ]
  },
  {
    id: 'AC-16', scenario: 'Expired or cancelled authorization',
    evidence: [
      'revoking a refresh token kills the access token with it',
      'cancelling returns access_denied and mints no code',
      'an absent or unknown token is refused'
    ]
  },
  {
    id: 'AC-17', scenario: 'MCP device UI',
    evidence: [
      'the four views are discoverable without a token',
      'every view declares the exact MCP Apps content type',
      'a version conflict explains itself with what the device actually is'
    ],
    gap: 'Whether a host actually renders them, and how they behave on a phone.'
  },
  {
    id: 'AC-18', scenario: 'Text fallback',
    evidence: ['the four device operations work over MCP', 'control_device tells a caller to read before writing']
  },
  {
    id: 'AC-19', scenario: 'iOS usability',
    evidence: [],
    ios: ['the whole IoTSwitchTests suite'],
    gap: 'Core flows on a real iPhone, and Claude on iOS rendering the views. '
      + 'The simulator run in phase 2 is not a device.'
  },
  {
    id: 'AC-20', scenario: 'iPad layout',
    evidence: [],
    gap: 'Nothing here exercises iPad. Section 5.1 asks for a presentation sized '
      + 'for it, and the app currently scales the iPhone layout up.'
  },
  {
    id: 'AC-21', scenario: 'User isolation',
    evidence: [
      "one account cannot see or touch another account",
      'another account cannot control a device it does not own',
      'two accounts writing concurrently do not interfere',
      'the same name is free for a different account'
    ]
  },
  {
    id: 'AC-22', scenario: 'Cross-client consistency',
    evidence: ['MCP and the REST API are the same devices, and the channel is recorded']
  },
  {
    id: 'AC-23', scenario: 'Sandbox and content policy',
    evidence: [
      'no view reaches for an external origin, and none is declared',
      'no view asks for a device permission it does not need',
      'the templates are identical for everyone',
      'the bridge only accepts messages from the host',
      'only the handshake is posted to any origin',
      'after the handshake, messages from another origin are ignored'
    ],
    gap: 'That a host enforces the policy we declare. We can only prove we ask '
      + 'for nothing and reach for nothing.'
  },
  {
    id: 'AC-24', scenario: 'Authentication challenge',
    evidence: [
      'an unauthenticated protected call is a transport 401, not a tool error',
      'the challenge carries everything a host needs to authorize',
      'the metadata the challenge points at is actually served',
      'protected resource metadata is served at both well-known paths'
    ]
  },
  {
    id: 'AC-25', scenario: 'Scope sufficiency and step-up',
    evidence: [
      'a read-only token gets 403 insufficient_scope naming every scope',
      'a narrower scope request is honoured exactly',
      'a batch cannot smuggle a call the token is not scoped for'
    ]
  },
  {
    id: 'AC-26', scenario: 'Device cap',
    evidence: ['the device cap is enforced']
  },
  {
    id: 'AC-27', scenario: 'Host write approval',
    evidence: [],
    gap: 'Whether a host confirms every write, and whether it remembers. '
      + 'ChatGPT documents per-write confirmation. FINDINGS Q4.'
  },
  {
    id: 'AC-28', scenario: 'Inline presentation',
    evidence: ['the device list bounds what it renders inline and can ask for more'],
    gap: 'How many rows actually survive an inline card on a phone. The budget '
      + 'is currently published guidance, not a measurement. FINDINGS Q2.'
  },

  // Beyond section 12: criteria added by Authentication Architecture v2
  // (docs/authentication-architecture/implementation-plan.md, section 9.3).
  {
    id: 'AC-29', scenario: 'Authorization pages cannot be framed',
    evidence: [
      'authorization pages cannot be framed',
      'the login form may redirect to the client it was issued for',
      'the page styles itself only through its nonced stylesheet'
    ]
  },
  {
    id: 'AC-30', scenario: 'Single-use codes and race-safe refresh rotation',
    evidence: [
      'concurrent refreshes with one token all succeed with the identical response',
      'a duplicate refresh inside the grace window gets the same tokens',
      'a replay after the grace window revokes the grant',
      'a replay after the successor was used revokes the grant',
      'concurrent redemptions of one code yield exactly one token'
    ],
    requires: ['postgres']
  },
  {
    id: 'AC-31', scenario: 'Tokens are stored only as keyed hashes',
    evidence: [
      'tokens are stored only as keyed hashes',
      'a token names its kind and carries a checksum',
      'tokens issued under a retired pepper keep working until they expire',
      'a stored hash cannot be checked without the pepper',
      'the key file holds only ciphertext and KMS key ids',
      'rotating the pepper keeps tokens from before it working'
    ]
  },
  {
    id: 'AC-32', scenario: 'Consent names who is asking and is never remembered for unverified registration',
    evidence: [
      'DCR consent names the selected callback rather than the first registered host',
      'a dynamically registered client is asked every time',
      'asking for more than was approved asks again',
      'a changed metadata document asks again',
      'approving write access needs a recent sign-in',
      'a pending authorization cannot be completed in another browser',
      'a form posted without its CSRF token is refused'
    ]
  },
  {
    id: 'AC-33', scenario: 'Client metadata fetches cannot reach private networks',
    evidence: [
      'only ordinary public unicast addresses may be fetched',
      'a metadata document on a private address is refused',
      'a document that does not name itself, or is too large, is refused',
      'client metadata fetches are budgeted per host'
    ]
  },
  {
    id: 'AC-34', scenario: 'No adapter reaches the device rules without an exchanged internal token',
    evidence: [
      'no adapter reaches the device rules except through the Device Service',
      'a valid internal token reaches the device rules as its subject',
      'an inherited property name is an unknown tool, and unknown tools never run anonymously'
    ]
  },
  {
    id: 'AC-35', scenario: 'Internal tokens are audience-, scope- and workload-bound',
    evidence: [
      'an internal token names who, through what, for which one scope',
      'every malformed or misdirected internal token is refused',
      'alg none and HMAC key confusion never verify',
      'an exchange can narrow scope but never widen it',
      'each adapter may present only its own kind of credential',
      'an internal token never outlives the credential it came from',
      'a revoked grant cannot be exchanged, and its cached internal tokens are dropped'
    ]
  },
  {
    id: 'AC-36', scenario: 'Write budgets bound automated writes per grant and device',
    evidence: [
      'switching one device more than six times a minute is refused when enforced',
      'more than twenty changes a minute across devices is refused when enforced',
      'budgets are per grant: another client of the same person keeps its own',
      'the REST API refuses an over-budget change with 429 and Retry-After'
    ],
    gap: 'Report-only by default (WRITE_BUDGETS=report) until a week of real use '
      + 'shows the limits do not bite people. Enforcement is a configuration change.'
  },
  {
    id: 'AC-37', scenario: 'Every change names the user, client, grant and adapter behind it',
    evidence: ['every change is audited with the client, grant and adapter behind it']
  },
  {
    id: 'AC-38', scenario: 'A DPoP-bound token is useless without its key',
    evidence: [
      'a bound token is useless without its key',
      'a proof from another key is refused for a bound token',
      'a proof is refused unless every claim matches this request',
      'a proof cannot be replayed',
      'a proof carrying its private key is refused',
      'a host that offers DPoP gets bound tokens at the MCP endpoint too'
    ],
    ios: [
      'DPoPTests.testAProofNamesTheRequestAndVerifiesWithItsOwnKey',
      'APIClientTests.testEveryRequestCarriesAProofAndTheDPoPScheme',
      'APIClientTests.testAServerNonceIsPickedUpAndTheRequestRetriedOnce'
    ],
    gap: 'The Secure Enclave key is exercised only on a physical device; the '
      + 'Simulator falls back to a software key with the same interface.'
  },
  {
    id: 'AC-39', scenario: 'The native app never handles a password',
    evidence: [
      'the app signs in through PAR and gets DPoP-bound tokens for the API',
      'the universal-link association is published only with an Apple team'
    ],
    ios: [
      'AuthViewModelTests.testSignUpOpensTheBrowserOnTheSignUpForm',
      'SessionControllerTests.testAResponseFromAnotherIssuerIsRefused',
      'SessionControllerTests.testAResponseToAnotherRequestIsRefused'
    ],
    gap: 'The callback is the custom scheme until an Apple team is chosen (G3); '
      + 'then the universal link replaces it.'
  },
  {
    id: 'AC-40', scenario: 'The app keeps its session through flaky networks, and only with its key',
    evidence: ['refreshing needs the same key'],
    ios: [
      'SessionControllerTests.testATokenNearExpiryIsRefreshedBeforeItIsUsed',
      'SessionControllerTests.testConcurrentFailuresRefreshExactlyOnce',
      'SessionControllerTests.testANetworkFailureDuringRefreshKeepsTheSession'
    ]
  },
  {
    id: 'AC-41', scenario: 'The first-party app must push its authorization request',
    evidence: [
      'the app must push its request, bind a key, and ask only for the API',
      'a pushed request is used once, and the browser cannot change it',
      'a code bound to one key cannot be redeemed with another, and nothing is spent by trying'
    ]
  },
  {
    id: 'AC-42', scenario: 'The legacy password endpoints can be retired',
    evidence: [
      'legacy sign-in is marked deprecated, and can be retired',
      'the API can be told to accept only DPoP-bound tokens'
    ],
    gap: 'Deprecated, not yet off: the legacy endpoints answer with Deprecation '
      + 'and Sunset headers until the browser sign-in build has shipped. Then '
      + 'LEGACY_FIRST_PARTY_AUTH=off and DPOP_REQUIRED_FOR_API=on.'
  },
  {
    id: 'AC-43', scenario: 'Concurrency guarantees hold on real Postgres under contention',
    evidence: [
      'fifty concurrent refreshes of one token rotate it once',
      'fifty concurrent redemptions of one code issue tokens at most once',
      'fifty concurrent switches from one version',
      'fifty concurrent creates of one name make one device'
    ],
    requires: ['postgres']
  },
  {
    id: 'AC-44', scenario: 'Revocation propagates across processes before the next request',
    evidence: [
      'redis: a revocation in one process reaches every other',
      'redis: revoking a grant in one process empties the cache in another',
      "a revocation empties the edge's introspection cache at once",
      'an MCP host signs a person in and controls a device through four processes'
    ],
    requires: ['postgres', 'redis']
  },
  {
    id: 'AC-45', scenario: 'Passkey login is phishing-resistant (RP ID bound)',
    evidence: [
      'a passkey made for another site, or answered at another origin, is refused',
      'a passkey can be added from the account page, then used to sign in',
      'a passkey completes an authorization in flight',
      'a challenge answers once',
      'an authenticator whose counter stops advancing is refused'
    ],
    gap: 'Run with a software authenticator that signs real WebAuthn responses. '
      + 'A platform passkey in Safari and Chrome, on a device, is the exit review.'
  },
  {
    id: 'AC-46', scenario: 'Users can see and revoke every connected app',
    evidence: [
      'every connected app is listed with what it can do',
      'disconnecting an app makes its token fail on the next call',
      "another person's app cannot be disconnected",
      'sign out everywhere ends the hosts, the iPhone app',
      'changing the password signs out everything else'
    ]
  },
  {
    id: 'AC-47', scenario: 'Store outages fail closed',
    evidence: [
      'redis: an unreachable store refuses with 503 rather than letting requests through',
      'an unreachable authorization server is a 503 at the edge, never a pass',
      'start-up fails closed on a tampered file, another KMS, or a missing key'
    ],
    requires: ['redis'],
    gap: 'The failover drill — Redis stopped under load — is the phase 4 exit review.'
  }
];
