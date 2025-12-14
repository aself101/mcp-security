/**
 * Zod Error Formatting Utilities
 *
 * Provides user-friendly error messages for Zod validation failures.
 */

import { ZodError, type ZodIssue } from 'zod';

export interface FormattedError {
  error: string;
  message: string;
  field?: string;
  details?: string[];
}

/**
 * Format a single Zod issue into a readable message
 */
function formatIssue(issue: ZodIssue): string {
  const path = issue.path.join('.');
  const prefix = path ? `${path}: ` : '';

  switch (issue.code) {
    case 'invalid_type':
      return `${prefix}Expected ${issue.expected}, received ${issue.received}`;
    case 'too_small':
      if (issue.type === 'string') {
        return `${prefix}Must be at least ${issue.minimum} character(s)`;
      }
      if (issue.type === 'number') {
        return `${prefix}Must be at least ${issue.minimum}`;
      }
      if (issue.type === 'array') {
        return `${prefix}Must have at least ${issue.minimum} item(s)`;
      }
      return `${prefix}Value is too small`;
    case 'too_big':
      if (issue.type === 'string') {
        return `${prefix}Must be at most ${issue.maximum} character(s)`;
      }
      if (issue.type === 'number') {
        return `${prefix}Must be at most ${issue.maximum}`;
      }
      if (issue.type === 'array') {
        return `${prefix}Must have at most ${issue.maximum} item(s)`;
      }
      return `${prefix}Value is too large`;
    case 'invalid_enum_value':
      return `${prefix}Invalid value. Expected one of: ${issue.options.join(', ')}`;
    case 'invalid_string':
      if (issue.validation === 'email') {
        return `${prefix}Invalid email format`;
      }
      if (issue.validation === 'regex') {
        return `${prefix}Invalid format`;
      }
      return `${prefix}Invalid string`;
    default:
      return `${prefix}${issue.message}`;
  }
}

/**
 * Format a ZodError into a user-friendly response
 */
export function formatZodError(error: ZodError): FormattedError {
  const issues = error.issues;
  const firstIssue = issues[0];
  const field = firstIssue?.path.join('.') || undefined;

  return {
    error: 'Validation failed',
    message: formatIssue(firstIssue),
    field,
    details: issues.length > 1 ? issues.map(formatIssue) : undefined,
  };
}

/**
 * Wrap an async handler to catch and format Zod errors
 */
export function withZodErrorHandling<T, R>(
  handler: (args: T) => Promise<R>
): (args: T) => Promise<R | { content: Array<{ type: 'text'; text: string }> }> {
  return async (args: T) => {
    try {
      return await handler(args);
    } catch (error) {
      if (error instanceof ZodError) {
        const formatted = formatZodError(error);
        return {
          content: [{ type: 'text', text: JSON.stringify(formatted, null, 2) }],
        };
      }
      throw error;
    }
  };
}
