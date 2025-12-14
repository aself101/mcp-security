# Advanced Configuration

This document covers advanced configuration options for the KenPom MCP server.

## Custom Rate Limits

Adjust rate limits based on your KenPom subscription:

```typescript
const server = new SecureMcpServer({
  name: 'kenpom-server',
  version: '1.0.0',
}, {
  maxRequestsPerMinute: 30,  // Increase for heavy usage
  maxRequestsPerHour: 500,   // Adjust based on needs
  toolRegistry: [
    {
      name: 'get-ratings',
      sideEffects: 'network',
      quotaPerMinute: 10,     // Per-tool limits
    },
  ],
});
```

## Tool-Specific Quotas

Different tools may have different usage patterns:

```typescript
toolRegistry: [
  // Frequently used - higher quota
  { name: 'get-ratings', sideEffects: 'network', quotaPerMinute: 15 },
  { name: 'get-fan-match', sideEffects: 'network', quotaPerMinute: 10 },

  // Heavy API calls - lower quota
  { name: 'get-scouting-report', sideEffects: 'network', quotaPerMinute: 5 },
  { name: 'get-player-stats', sideEffects: 'network', quotaPerMinute: 5 },
]
```

## Caching Configuration

The underlying kenpom-api supports caching. Configure via environment:

```bash
# Cache responses for 5 minutes (300 seconds)
KENPOM_CACHE_TTL=300

# Disable caching for real-time data
KENPOM_CACHE_ENABLED=false
```

## Response Size Management

Control response sizes to manage token usage:

```typescript
// In tool implementation
export async function getRatings(args: GetRatingsArgs) {
  const api = await getApi();
  const ratings = await api.getPomeroyRatings(args.season);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        count: ratings.length,
        ratings: ratings.slice(0, args.limit || 50)  // Configurable limit
      }, null, 2)
    }]
  };
}
```

## Multiple Season Queries

For historical analysis across seasons:

```typescript
// Query multiple seasons (careful with rate limits)
const seasons = [2023, 2024, 2025];
for (const season of seasons) {
  await delay(3000);  // Respect rate limits
  const ratings = await getRatings({ season });
  // Process ratings...
}
```

## Conference Abbreviations Reference

| Full Name | Abbreviation |
|-----------|--------------|
| Atlantic 10 | A10 |
| ACC | ACC |
| America East | AE |
| American Athletic | Amer |
| Atlantic Sun | ASun |
| Big Ten | B10 |
| Big 12 | B12 |
| Big East | BE |
| Big Sky | BSky |
| Big South | BSth |
| Big West | BW |
| CAA | CAA |
| Conference USA | CUSA |
| Horizon | Horz |
| Ivy League | Ivy |
| MAAC | MAAC |
| MAC | MAC |
| MEAC | MEast |
| Missouri Valley | MVC |
| Mountain West | MWC |
| NEC | NEC |
| OVC | OVC |
| Pac-12 | Pac |
| Patriot | Pat |
| SoCon | SC |
| SEC | SEC |
| Southland | Slnd |
| Summit | Sum |
| SWAC | SWAC |
| WAC | WAC |
| WCC | WCC |

## Error Handling

The server provides structured error responses:

```json
{
  "error": "Rate limit exceeded",
  "message": "Too many requests. Try again in 60 seconds.",
  "retryAfter": 60
}
```

```json
{
  "error": "Invalid conference",
  "message": "Conference 'Big Ten' not found. Use 'B10' instead.",
  "validConferences": ["A10", "ACC", "B10", "..."]
}
```
