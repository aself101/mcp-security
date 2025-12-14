# Basic Usage Examples

## Weather Forecast

### Get weather for London in Celsius

```json
{
  "tool": "weather-forecast",
  "arguments": {
    "city": "London",
    "units": "metric"
  }
}
```

**Response:**
```json
{
  "city": "London",
  "coordinates": { "latitude": 51.5074, "longitude": -0.1278 },
  "timezone": "Europe/London",
  "current": {
    "time": "2024-01-15T14:00",
    "temperature": "12°C",
    "humidity": "78%",
    "conditions": "Overcast",
    "windSpeed": "15 km/h"
  },
  "forecast": [
    { "date": "2024-01-15", "high": "13°C", "low": "7°C", "conditions": "Overcast" },
    { "date": "2024-01-16", "high": "11°C", "low": "5°C", "conditions": "Slight rain" },
    { "date": "2024-01-17", "high": "10°C", "low": "4°C", "conditions": "Partly cloudy" }
  ]
}
```

### Get weather for New York in Fahrenheit

```json
{
  "tool": "weather-forecast",
  "arguments": {
    "city": "New York",
    "units": "imperial"
  }
}
```

## Currency Conversion

### Convert USD to EUR

```json
{
  "tool": "currency-convert",
  "arguments": {
    "from": "USD",
    "to": "EUR",
    "amount": 100
  }
}
```

**Response:**
```json
{
  "from": "USD",
  "to": "EUR",
  "amount": 100,
  "result": 91.85,
  "rate": 0.9185,
  "date": "2024-01-15",
  "formatted": {
    "input": "100 USD",
    "output": "91.85 EUR"
  }
}
```

### Convert large amounts

```json
{
  "tool": "currency-convert",
  "arguments": {
    "from": "GBP",
    "to": "JPY",
    "amount": 50000
  }
}
```

## News Headlines

### Get front page stories

```json
{
  "tool": "news-headlines",
  "arguments": {
    "category": "front_page",
    "limit": 5
  }
}
```

**Response:**
```json
{
  "category": "front_page",
  "query": null,
  "count": 5,
  "totalAvailable": 1000,
  "articles": [
    {
      "id": "12345678",
      "title": "Show HN: I built a new programming language",
      "url": "https://example.com/my-language",
      "author": "developer123",
      "points": 342,
      "comments": 89,
      "published": "2024-01-15T08:30:00.000Z"
    }
  ]
}
```

### Search for specific topics

```json
{
  "tool": "news-headlines",
  "arguments": {
    "category": "front_page",
    "query": "rust programming",
    "limit": 3
  }
}
```

### Get Show HN posts

```json
{
  "tool": "news-headlines",
  "arguments": {
    "category": "show_hn",
    "limit": 10
  }
}
```

### Get job listings

```json
{
  "tool": "news-headlines",
  "arguments": {
    "category": "jobs",
    "limit": 5
  }
}
```
