import test from 'node:test';
import assert from 'node:assert/strict';
import { displayDeviceName, normalizeDeviceName, normalizeUsername } from '../src/normalize.ts';

test('device names fold case, trim, and collapse internal whitespace', () => {
  const canonical = normalizeDeviceName('Bedroom Lamp');
  assert.equal(normalizeDeviceName('  bedroom lamp  '), canonical);
  assert.equal(normalizeDeviceName('BEDROOM LAMP'), canonical);
  assert.equal(normalizeDeviceName('Bedroom   Lamp'), canonical);
  assert.equal(normalizeDeviceName('Bedroom\tLamp'), canonical);
});

test('device names fold compatibility-equivalent Unicode', () => {
  // Fullwidth characters normalise to ASCII under NFKC. Without this, a name
  // that is visually identical creates a second device.
  assert.equal(normalizeDeviceName('Ｌａｍｐ'), normalizeDeviceName('lamp'));
});

test('distinct device names stay distinct', () => {
  assert.notEqual(normalizeDeviceName('Lamp 1'), normalizeDeviceName('Lamp 2'));
  assert.notEqual(normalizeDeviceName('a.b'), normalizeDeviceName('a-b'));
});

test('the display form preserves what the user typed, minus tidying', () => {
  assert.equal(displayDeviceName('  Bedroom   Lamp '), 'Bedroom Lamp');
  assert.equal(displayDeviceName('BEDROOM lamp'), 'BEDROOM lamp');
});

test('usernames fold case and NFKC but keep internal punctuation', () => {
  assert.equal(normalizeUsername(' Sam.Smith '), normalizeUsername('sam.smith'));
  assert.notEqual(normalizeUsername('sam.smith'), normalizeUsername('sam_smith'));
});
