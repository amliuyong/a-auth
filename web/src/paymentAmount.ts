// Canonical `amount_minor` (same rule as the payment domain's `parse_amount_minor`):
// a positive decimal integer without leading zeros, at most 18 digits (fits u64).
const AMOUNT_MINOR = /^[1-9][0-9]{0,17}$/;
const MAX_CURRENCY_EXPONENT = 4;

/**
 * Format a payment amount given in minor units as a major-unit decimal string,
 * e.g. ("1999", 2) → "19.99", ("5", 2) → "0.05", ("120000", 0) → "120000".
 *
 * Pure string manipulation: the amount is never converted to a JS number, so
 * no value is rounded or loses precision. Returns `null` (never throws) when
 * `amountMinor` is not canonical or `exponent` is not an integer in 0–4, so the
 * caller can fail closed instead of displaying a guessed amount.
 */
export function formatMinorUnits(amountMinor: string, exponent: number): string | null {
  if (typeof amountMinor !== 'string' || !AMOUNT_MINOR.test(amountMinor)) return null;
  if (!Number.isInteger(exponent) || exponent < 0 || exponent > MAX_CURRENCY_EXPONENT) {
    return null;
  }
  if (exponent === 0) return amountMinor;
  const digits = amountMinor.padStart(exponent + 1, '0');
  return `${digits.slice(0, -exponent)}.${digits.slice(-exponent)}`;
}
