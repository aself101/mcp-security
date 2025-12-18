# Security Demonstration

This document shows attack attempts that are blocked by the mcp-secure-server framework.

## Attack 1: SSRF to AWS Metadata

**Attempt:** Try to access AWS instance metadata through the API.

Since URLs are not user-controllable in this server, SSRF is prevented by design. The only domains that can be accessed are:
- `api.open-meteo.com`
- `api.frankfurter.app`
- `hn.algolia.com`

**Result:** Not possible - no user-controlled URL parameter exists.

## Attack 2: Rate Limit Exhaustion

**Attempt:** Rapidly call news-headlines to exhaust the rate limit.

```bash
# Simulate rapid requests
for i in 1 2 3 4 5; do
  echo "Request $i:"
  # Call news-headlines
done
```

**Result:**
- Requests 1-3: Success
- Requests 4+: Blocked by Layer 4 with error:
  ```json
  {
    "error": "Rate limit exceeded",
    "message": "Tool 'news-headlines' quota exceeded. Max 3 requests per 60 seconds.",
    "retryAfter": 45
  }
  ```

## Attack 3: XSS Injection in City Name

**Attempt:** Inject JavaScript through the city parameter.

```json
{
  "tool": "weather-forecast",
  "arguments": {
    "city": "<script>document.cookie</script>",
    "units": "metric"
  }
}
```

**Result:** The `sanitizeString` function removes `<` and `>` characters:
```json
{
  "error": "City not found",
  "message": "City \"scriptdocument.cookie/script\" is not in our database..."
}
```

## Attack 4: SQL Injection in Currency Code

**Attempt:** Inject SQL through the currency parameter.

```json
{
  "tool": "currency-convert",
  "arguments": {
    "from": "'; DROP TABLE users;--",
    "to": "EUR",
    "amount": 100
  }
}
```

**Result:** Blocked by ISO 4217 validation:
```json
{
  "error": "Invalid currency code",
  "message": "\"'; DROP TABLE USERS;--\" is not a valid ISO 4217 currency code"
}
```

## Attack 5: Large Amount Overflow

**Attempt:** Use an extremely large number to cause overflow.

```json
{
  "tool": "currency-convert",
  "arguments": {
    "from": "USD",
    "to": "EUR",
    "amount": 999999999999999
  }
}
```

**Result:** Blocked by Zod schema validation (max: 1 billion):
```json
{
  "error": "Validation error",
  "message": "amount: Number must be less than or equal to 1000000000"
}
```

## Attack 6: Command Injection in Search Query

**Attempt:** Inject shell commands through the news query.

```json
{
  "tool": "news-headlines",
  "arguments": {
    "category": "front_page",
    "query": "; rm -rf /; echo",
    "limit": 5
  }
}
```

**Result:** The query is URL-encoded and sent to the Hacker News API as a search term. No shell execution occurs. The API simply searches for stories containing those characters.

## Attack 7: Prototype Pollution

**Attempt:** Use __proto__ in arguments.

```json
{
  "tool": "weather-forecast",
  "arguments": {
    "city": "London",
    "__proto__": { "admin": true }
  }
}
```

**Result:** Blocked by Zod schema validation:
```json
{
  "error": "Validation error",
  "message": "Unrecognized key(s) in object: '__proto__'"
}
```

## Attack 8: Oversized Response

**Attempt:** Request data that would return a very large response.

The server enforces a 50KB response limit via `maxResponseSize` in the `fetchJson` utility. If an API returns more than 50KB:

```json
{
  "error": "Response too large",
  "message": "Response too large: 75000 bytes exceeds 51200 byte limit"
}
```

## Attack 9: Path Traversal in City Name

**Attempt:** Use path traversal to access files.

```json
{
  "tool": "weather-forecast",
  "arguments": {
    "city": "../../../etc/passwd",
    "units": "metric"
  }
}
```

**Result:** The city is looked up in a hardcoded map, not the filesystem:
```json
{
  "error": "City not found",
  "message": "City \"../../../etc/passwd\" is not in our database..."
}
```

## Attack 10: NoSQL Injection

**Attempt:** Inject MongoDB operators.

```json
{
  "tool": "currency-convert",
  "arguments": {
    "from": { "$gt": "" },
    "to": "EUR",
    "amount": 100
  }
}
```

**Result:** Blocked by Zod schema (expects string, not object):
```json
{
  "error": "Validation error",
  "message": "from: Expected string, received object"
}
```

## Summary

| Attack | Vector | Prevention |
|--------|--------|------------|
| SSRF | URL manipulation | Design (no user URLs) |
| Rate abuse | Rapid requests | Layer 4 quotas |
| XSS | City name | String sanitization |
| SQL injection | Currency code | Input validation |
| Integer overflow | Amount | Zod max limit |
| Command injection | Search query | URL encoding, no shell |
| Prototype pollution | __proto__ | Zod strict parsing |
| Large response | API response | Size limit enforcement |
| Path traversal | City name | Lookup map, not filesystem |
| NoSQL injection | Object in string | Zod type checking |
