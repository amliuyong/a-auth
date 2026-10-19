import assert from 'node:assert/strict';
import test from 'node:test';
import { formatMinorUnits } from '../src/paymentAmount.ts';

test('payment amount formats minor units with the currency exponent', () => {
  assert.equal(formatMinorUnits('1999', 2), '19.99');
  assert.equal(formatMinorUnits('5', 2), '0.05');
  assert.equal(formatMinorUnits('10', 2), '0.10');
  assert.equal(formatMinorUnits('100', 2), '1.00');
  assert.equal(formatMinorUnits('120000', 0), '120000');
  assert.equal(formatMinorUnits('1000', 3), '1.000');
  assert.equal(formatMinorUnits('7', 4), '0.0007');
});

test('payment amount keeps every digit of the largest canonical amount', () => {
  assert.equal(formatMinorUnits('999999999999999999', 2), '9999999999999999.99');
  assert.equal(formatMinorUnits('123456789012345678', 4), '12345678901234.5678');
});

test('payment amount rejects a non-canonical amount', () => {
  for (const bad of [
    '',
    '0',
    '01999',
    '-1999',
    '+1999',
    '19.99',
    '1e3',
    ' 1999',
    '1999 ',
    '1_999',
    '１９９９',
    '1000000000000000000',
  ]) {
    assert.equal(formatMinorUnits(bad, 2), null, JSON.stringify(bad));
  }
  assert.equal(formatMinorUnits(1999 as unknown as string, 2), null);
});

test('payment amount rejects an exponent outside 0 to 4', () => {
  for (const bad of [-1, 5, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.equal(formatMinorUnits('1999', bad), null, String(bad));
  }
  assert.equal(formatMinorUnits('1999', '2' as unknown as number), null);
});
