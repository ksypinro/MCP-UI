/**
 * Compile-time checks, run by `npm run typecheck`, not by the test runner.
 * Each `@ts-expect-error` fails the typecheck if the line beneath it ever
 * starts compiling — that is, if an anonymous caller could be used where a
 * verified one is required.
 */

import type { AnonymousCaller, Caller, VerifiedCaller } from '../../src/domain/types.ts';

declare function needsVerified(caller: VerifiedCaller): void;
declare const anonymous: AnonymousCaller;
declare const either: Caller;

// @ts-expect-error an anonymous caller is not a verified one
needsVerified(anonymous);

// @ts-expect-error a caller of unknown kind must be narrowed first
needsVerified(either);

if (either.kind === 'verified') needsVerified(either);
