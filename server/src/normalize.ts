/**
 * The normalization folds from spec sections 4.1 and 4.2.
 *
 * This module exists once and is imported by everything that touches a name:
 * the HTTP layer, the device service, and later the MCP adapter. If this logic
 * ever forks between callers, two devices whose names differ only by case can
 * both be created, and acceptance criterion AC-09 fails in a way that is
 * genuinely unpleasant to trace back to its cause.
 */

/** Trim, NFKC, lowercase. Used for the unique account lookup. */
export function normalizeUsername(raw: string): string {
  return raw.trim().normalize('NFKC').toLowerCase();
}

/**
 * Trim, collapse internal whitespace runs, NFKC, lowercase.
 *
 * Lowercasing is not full Unicode case folding, and JavaScript has no built-in
 * that is. The difference is real but narrow: "Straße" and "STRASSE" fold
 * apart, so a German user can hold both as separate devices. Usernames avoid
 * this because validation restricts them to ASCII first; device names are not
 * restricted, so this is a known limitation rather than an oversight. If it
 * ever matters, the fix is a case-folding table here, and nowhere else.
 */
export function normalizeDeviceName(raw: string): string {
  return collapseWhitespace(raw).normalize('NFKC').toLowerCase();
}

/**
 * The display form of a device name: trimmed, with internal whitespace runs
 * collapsed to single spaces. What the user typed, tidied — never folded.
 */
export function displayDeviceName(raw: string): string {
  return collapseWhitespace(raw);
}

function collapseWhitespace(raw: string): string {
  return raw.trim().replace(/\s+/g, ' ');
}
