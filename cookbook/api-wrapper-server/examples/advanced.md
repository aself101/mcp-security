# Advanced Usage Examples

## Chaining Tool Calls

### Travel Planning: Weather + Currency

Get weather for a destination and convert your budget:

**Step 1: Check weather at destination**
```json
{
  "tool": "weather-forecast",
  "arguments": {
    "city": "Tokyo",
    "units": "metric"
  }
}
```

**Step 2: Convert travel budget**
```json
{
  "tool": "currency-convert",
  "arguments": {
    "from": "USD",
    "to": "JPY",
    "amount": 2000
  }
}
```

### Research Workflow: News + Follow-up

**Step 1: Find trending topics**
```json
{
  "tool": "news-headlines",
  "arguments": {
    "category": "front_page",
    "limit": 5
  }
}
```

**Step 2: Deep dive on specific topic**
```json
{
  "tool": "news-headlines",
  "arguments": {
    "category": "front_page",
    "query": "interesting topic from step 1",
    "limit": 10
  }
}
```

## Multi-City Weather Comparison

Compare weather across cities (make separate calls):

```json
// Call 1
{ "tool": "weather-forecast", "arguments": { "city": "London", "units": "metric" } }

// Call 2
{ "tool": "weather-forecast", "arguments": { "city": "Paris", "units": "metric" } }

// Call 3
{ "tool": "weather-forecast", "arguments": { "city": "Berlin", "units": "metric" } }
```

## Currency Arbitrage Check

Check multiple currency pairs:

```json
// USD -> EUR
{ "tool": "currency-convert", "arguments": { "from": "USD", "to": "EUR", "amount": 1000 } }

// EUR -> GBP
{ "tool": "currency-convert", "arguments": { "from": "EUR", "to": "GBP", "amount": 918.5 } }

// GBP -> USD
{ "tool": "currency-convert", "arguments": { "from": "GBP", "to": "USD", "amount": 785.3 } }
```

## Rate Limit Considerations

### Optimizing News Queries

Instead of making multiple calls, use the query parameter:

**Inefficient (3 calls):**
```json
{ "category": "front_page", "limit": 10 }
{ "category": "ask_hn", "limit": 10 }
{ "category": "show_hn", "limit": 10 }
```

**Better (1 call per category, respect limits):**
```json
{ "category": "front_page", "query": "specific topic", "limit": 10 }
```

### Working Within Limits

| Tool | Limit | Strategy |
|------|-------|----------|
| weather-forecast | 10/min | Cache results for repeated city queries |
| currency-convert | 5/min | Batch conversions with different amounts |
| news-headlines | 3/min | Use search query to get targeted results |

## Error Handling Examples

### Unknown City Graceful Handling

```json
{
  "tool": "weather-forecast",
  "arguments": {
    "city": "SmallTownUSA",
    "units": "metric"
  }
}
```

**Response:**
```json
{
  "error": "City not found",
  "message": "City \"SmallTownUSA\" is not in our database. Supported cities: new york, london, paris...",
  "hint": "For other cities, please use latitude/longitude coordinates directly."
}
```

### Invalid Currency Code

```json
{
  "tool": "currency-convert",
  "arguments": {
    "from": "FAKE",
    "to": "EUR",
    "amount": 100
  }
}
```

**Response:**
```json
{
  "error": "Invalid currency code",
  "message": "\"FAKE\" is not a valid ISO 4217 currency code",
  "validCodes": "USD, EUR, GBP, JPY, AUD, CAD, CHF, CNY, HKD, NZD..."
}
```

## Custom Integration Patterns

### Caching Layer (Application Code)

```typescript
const weatherCache = new Map<string, { data: any; expiry: number }>();

async function getCachedWeather(city: string) {
  const cached = weatherCache.get(city);
  if (cached && cached.expiry > Date.now()) {
    return cached.data;
  }

  // Make MCP tool call
  const result = await callTool('weather-forecast', { city, units: 'metric' });

  // Cache for 10 minutes
  weatherCache.set(city, {
    data: result,
    expiry: Date.now() + 10 * 60 * 1000,
  });

  return result;
}
```

### Retry Logic

```typescript
async function fetchWithRetry(toolName: string, args: any, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await callTool(toolName, args);
    } catch (error) {
      if (attempt === maxRetries) throw error;
      // Wait before retry (exponential backoff)
      await new Promise(r => setTimeout(r, 1000 * attempt));
    }
  }
}
```
