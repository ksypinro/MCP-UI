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
}

export const CRITERIA: Criterion[] = [
  {
    id: 'AC-01', scenario: 'New registration',
    evidence: [
      'sign-up creates one account and rejects a duplicate under folding',
      'sign-up returns an account and a session'
    ],
    ios: ['SessionControllerTests.testSignUpStoresTheSessionForNextLaunch']
  },
  {
    id: 'AC-02', scenario: 'Invalid or duplicate registration',
    evidence: [
      'usernames and passwords are validated at the boundary',
      'a duplicate username is a 409 naming the field',
      'a weak password is a 422 naming the field'
    ],
    ios: ['AuthViewModelTests.testAFieldScopedErrorLandsOnItsField']
  },
  {
    id: 'AC-03', scenario: 'Login and logout',
    evidence: [
      'login succeeds, and failure is generic',
      'credential verification is case-insensitive on the username only',
      'logout invalidates access tokens that were already issued'
    ],
    ios: ['SessionControllerTests.testLogOutClearsLocalStateEvenIfTheServerCallFails']
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
      'sign-up returns an account and a session, and echoes no secrets'
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
      'the bridge only accepts messages from the host'
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
  }
];
