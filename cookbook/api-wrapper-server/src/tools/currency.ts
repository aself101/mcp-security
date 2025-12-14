/**
 * Currency Conversion Tool
 * Wraps Frankfurter API (free, no key required)
 * https://www.frankfurter.app/
 */

import { z } from 'zod';
import { fetchJson, isValidCurrencyCode, VALID_CURRENCY_CODES } from '../utils/index.js';

const CURRENCY_API_BASE = 'https://api.frankfurter.app';

export const currencyConvertSchema = z.object({
  from: z.string()
    .length(3)
    .transform(s => s.toUpperCase())
    .describe('Source currency code (ISO 4217, e.g., "USD", "EUR")'),
  to: z.string()
    .length(3)
    .transform(s => s.toUpperCase())
    .describe('Target currency code (ISO 4217, e.g., "GBP", "JPY")'),
  amount: z.number()
    .positive()
    .max(1000000000) // 1 billion max
    .describe('Amount to convert'),
});

export type CurrencyConvertArgs = z.infer<typeof currencyConvertSchema>;

interface FrankfurterResponse {
  amount: number;
  base: string;
  date: string;
  rates: Record<string, number>;
}

export async function currencyConvert(args: CurrencyConvertArgs) {
  const from = args.from.toUpperCase();
  const to = args.to.toUpperCase();

  // Validate currency codes
  if (!isValidCurrencyCode(from)) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          error: 'Invalid currency code',
          message: `"${from}" is not a valid ISO 4217 currency code`,
          validCodes: Array.from(VALID_CURRENCY_CODES).slice(0, 20).join(', ') + '...',
        }, null, 2),
      }],
    };
  }

  if (!isValidCurrencyCode(to)) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          error: 'Invalid currency code',
          message: `"${to}" is not a valid ISO 4217 currency code`,
          validCodes: Array.from(VALID_CURRENCY_CODES).slice(0, 20).join(', ') + '...',
        }, null, 2),
      }],
    };
  }

  if (from === to) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          from,
          to,
          amount: args.amount,
          result: args.amount,
          rate: 1,
          message: 'Same currency - no conversion needed',
        }, null, 2),
      }],
    };
  }

  const url = `${CURRENCY_API_BASE}/latest?` + new URLSearchParams({
    from,
    to,
    amount: args.amount.toString(),
  });

  const data = await fetchJson<FrankfurterResponse>(url, {
    timeout: 10000,
    maxResponseSize: 10 * 1024, // 10KB limit
  });

  const convertedAmount = data.rates[to];
  const rate = convertedAmount / args.amount;

  const result = {
    from,
    to,
    amount: args.amount,
    result: Math.round(convertedAmount * 100) / 100,
    rate: Math.round(rate * 1000000) / 1000000,
    date: data.date,
    formatted: {
      input: `${args.amount.toLocaleString()} ${from}`,
      output: `${convertedAmount.toLocaleString(undefined, {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
      })} ${to}`,
    },
  };

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify(result, null, 2),
    }],
  };
}
