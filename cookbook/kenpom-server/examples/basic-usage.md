# Basic Usage Examples

This document shows common usage patterns for the KenPom MCP server.

## Getting Team Ratings

### Current season ratings

```
Tool: get-ratings
Arguments: {}
```

Response:
```json
{
  "success": true,
  "season": "current",
  "count": 50,
  "ratings": [
    { "rank": 1, "team": "Michigan", "conference": "B10", "record": "10-0", "adjEM": 34.52 },
    { "rank": 2, "team": "Iowa St.", "conference": "B12", "record": "9-0", "adjEM": 32.15 }
  ]
}
```

### Historical season ratings

```
Tool: get-ratings
Arguments: { "season": 2024 }
```

## Efficiency Stats

### Get team efficiency rankings

```
Tool: get-efficiency
Arguments: { "season": 2025 }
```

Response includes AdjO (offensive efficiency), AdjD (defensive efficiency), and AdjT (tempo).

### Get four factors

```
Tool: get-four-factors
Arguments: {}
```

Response includes eFG%, TO%, OR%, and FTRate for offense and defense.

## Team Information

### Get a team's schedule

```
Tool: get-schedule
Arguments: { "team": "Duke" }
```

Response:
```json
{
  "success": true,
  "team": "Duke",
  "season": "current",
  "games": [
    { "date": "2024-11-04", "opponent": "Maine", "result": "W", "score": "96-62" }
  ]
}
```

### Get team statistics

```
Tool: get-team-stats
Arguments: { "defense": true }
```

Returns 20+ defensive statistics for all teams.

## Player Statistics

### Top players by offensive rating

```
Tool: get-player-stats
Arguments: { "metric": "ORtg" }
```

### Players in a specific conference

```
Tool: get-player-stats
Arguments: { "metric": "eFG", "conference": "ACC" }
```

## Conference Data

### Conference standings

```
Tool: get-conference-standings
Arguments: { "conference": "B10" }
```

Note: Use conference abbreviations (B10, SEC, ACC, B12, etc.)

### Today's games with predictions

```
Tool: get-fan-match
Arguments: {}
```

Response:
```json
{
  "success": true,
  "date": "today",
  "games": [
    {
      "home": "Duke",
      "away": "North Carolina",
      "prediction": { "winner": "Duke", "spread": -5.5 }
    }
  ]
}
```

## Workflow Example: Scouting a Team

1. Get overall ratings to identify the team's strength:
```
Tool: get-ratings
Arguments: {}
```

2. Get detailed scouting report:
```
Tool: get-scouting-report
Arguments: { "team": "Duke" }
```

3. Check their schedule and recent results:
```
Tool: get-schedule
Arguments: { "team": "Duke" }
```

4. Find their best players:
```
Tool: get-player-stats
Arguments: { "metric": "ORtg", "conference": "ACC" }
```
