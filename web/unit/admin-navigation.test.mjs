import assert from 'node:assert/strict';
import test from 'node:test';
import { assertSafeAdminNavigation } from '../live/admin-navigation.mjs';

const EXPECTED = 'https://c.example.com/admin';

test('accepts a direct exact HTTPS Admin navigation', () => {
  assert.doesNotThrow(() =>
    assertSafeAdminNavigation(EXPECTED, EXPECTED, [EXPECTED]),
  );
});

for (const [name, unsafe] of [
  ['cross-origin', 'https://attacker.example/admin'],
  ['HTTPS downgrade', 'http://c.example.com/admin'],
  ['alternate path', 'https://c.example.com/redirect'],
  ['query injection', 'https://c.example.com/admin?next=1'],
  ['fragment injection', 'https://c.example.com/admin#token'],
]) {
  test(`rejects a ${name} redirect hop even when it returns to the expected URL`, () => {
    assert.throws(() =>
      assertSafeAdminNavigation(EXPECTED, EXPECTED, [
        EXPECTED,
        unsafe,
        EXPECTED,
      ]),
    );
  });
}
