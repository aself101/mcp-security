/**
 * HTTP utilities for safe API calls
 */

export interface FetchOptions {
  timeout?: number;
  maxResponseSize?: number;
}

const DEFAULT_TIMEOUT = 10000; // 10 seconds
const DEFAULT_MAX_RESPONSE_SIZE = 50 * 1024; // 50KB

export async function safeFetch(
  url: string,
  options: FetchOptions = {}
): Promise<Response> {
  const { timeout = DEFAULT_TIMEOUT } = options;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'mcp-api-wrapper/1.0.0',
        'Accept': 'application/json',
      },
    });
    return response;
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function fetchJson<T>(
  url: string,
  options: FetchOptions = {}
): Promise<T> {
  const { maxResponseSize = DEFAULT_MAX_RESPONSE_SIZE } = options;

  const response = await safeFetch(url, options);

  if (!response.ok) {
    throw new Error(`API request failed: ${response.status} ${response.statusText}`);
  }

  const contentLength = response.headers.get('content-length');
  if (contentLength && parseInt(contentLength, 10) > maxResponseSize) {
    throw new Error(`Response too large: ${contentLength} bytes exceeds ${maxResponseSize} byte limit`);
  }

  const text = await response.text();

  if (text.length > maxResponseSize) {
    throw new Error(`Response too large: ${text.length} bytes exceeds ${maxResponseSize} byte limit`);
  }

  return JSON.parse(text) as T;
}
