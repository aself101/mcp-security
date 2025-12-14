/**
 * Input validation utilities
 */

// ISO 4217 currency codes (common subset)
export const VALID_CURRENCY_CODES = new Set([
  'USD', 'EUR', 'GBP', 'JPY', 'AUD', 'CAD', 'CHF', 'CNY', 'HKD', 'NZD',
  'SEK', 'KRW', 'SGD', 'NOK', 'MXN', 'INR', 'RUB', 'ZAR', 'TRY', 'BRL',
  'TWD', 'DKK', 'PLN', 'THB', 'IDR', 'HUF', 'CZK', 'ILS', 'CLP', 'PHP',
  'AED', 'COP', 'SAR', 'MYR', 'RON', 'BGN', 'ISK', 'HRK', 'PKR', 'VND'
]);

export function isValidCurrencyCode(code: string): boolean {
  return VALID_CURRENCY_CODES.has(code.toUpperCase());
}

export function sanitizeString(input: string, maxLength: number = 100): string {
  return input
    .slice(0, maxLength)
    .replace(/[<>]/g, '') // Remove potential XSS characters
    .trim();
}

export function isValidLatitude(lat: number): boolean {
  return lat >= -90 && lat <= 90;
}

export function isValidLongitude(lon: number): boolean {
  return lon >= -180 && lon <= 180;
}
