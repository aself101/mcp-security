/**
 * Weather Forecast Tool
 * Wraps Open-Meteo API (free, no key required)
 * https://open-meteo.com/
 */

import { z } from 'zod';
import { fetchJson, isValidLatitude, isValidLongitude, sanitizeString } from '../utils/index.js';

const WEATHER_API_BASE = 'https://api.open-meteo.com/v1';

// Well-known city coordinates for city name lookup
const CITY_COORDINATES: Record<string, { lat: number; lon: number }> = {
  'new york': { lat: 40.7128, lon: -74.0060 },
  'london': { lat: 51.5074, lon: -0.1278 },
  'paris': { lat: 48.8566, lon: 2.3522 },
  'tokyo': { lat: 35.6762, lon: 139.6503 },
  'sydney': { lat: -33.8688, lon: 151.2093 },
  'los angeles': { lat: 34.0522, lon: -118.2437 },
  'chicago': { lat: 41.8781, lon: -87.6298 },
  'berlin': { lat: 52.5200, lon: 13.4050 },
  'madrid': { lat: 40.4168, lon: -3.7038 },
  'rome': { lat: 41.9028, lon: 12.4964 },
  'beijing': { lat: 39.9042, lon: 116.4074 },
  'mumbai': { lat: 19.0760, lon: 72.8777 },
  'dubai': { lat: 25.2048, lon: 55.2708 },
  'singapore': { lat: 1.3521, lon: 103.8198 },
  'toronto': { lat: 43.6532, lon: -79.3832 },
  'san francisco': { lat: 37.7749, lon: -122.4194 },
  'seattle': { lat: 47.6062, lon: -122.3321 },
  'miami': { lat: 25.7617, lon: -80.1918 },
  'boston': { lat: 42.3601, lon: -71.0589 },
  'denver': { lat: 39.7392, lon: -104.9903 },
};

export const weatherForecastSchema = z.object({
  city: z.string()
    .min(1)
    .max(100)
    .describe('City name (e.g., "London", "New York", "Tokyo")'),
  units: z.enum(['metric', 'imperial'])
    .default('metric')
    .describe('Temperature units: metric (Celsius) or imperial (Fahrenheit)'),
});

export type WeatherForecastArgs = z.infer<typeof weatherForecastSchema>;

interface OpenMeteoResponse {
  latitude: number;
  longitude: number;
  timezone: string;
  current: {
    time: string;
    temperature_2m: number;
    relative_humidity_2m: number;
    weather_code: number;
    wind_speed_10m: number;
  };
  daily: {
    time: string[];
    temperature_2m_max: number[];
    temperature_2m_min: number[];
    weather_code: number[];
  };
}

function getWeatherDescription(code: number): string {
  const descriptions: Record<number, string> = {
    0: 'Clear sky',
    1: 'Mainly clear',
    2: 'Partly cloudy',
    3: 'Overcast',
    45: 'Foggy',
    48: 'Depositing rime fog',
    51: 'Light drizzle',
    53: 'Moderate drizzle',
    55: 'Dense drizzle',
    61: 'Slight rain',
    63: 'Moderate rain',
    65: 'Heavy rain',
    71: 'Slight snow',
    73: 'Moderate snow',
    75: 'Heavy snow',
    80: 'Slight rain showers',
    81: 'Moderate rain showers',
    82: 'Violent rain showers',
    95: 'Thunderstorm',
    96: 'Thunderstorm with hail',
    99: 'Thunderstorm with heavy hail',
  };
  return descriptions[code] || 'Unknown';
}

export async function weatherForecast(args: WeatherForecastArgs) {
  const cityName = sanitizeString(args.city.toLowerCase());
  const coords = CITY_COORDINATES[cityName];

  if (!coords) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          error: 'City not found',
          message: `City "${args.city}" is not in our database. Supported cities: ${Object.keys(CITY_COORDINATES).join(', ')}`,
          hint: 'For other cities, please use latitude/longitude coordinates directly.',
        }, null, 2),
      }],
    };
  }

  if (!isValidLatitude(coords.lat) || !isValidLongitude(coords.lon)) {
    throw new Error('Invalid coordinates for city');
  }

  const temperatureUnit = args.units === 'imperial' ? 'fahrenheit' : 'celsius';
  const windSpeedUnit = args.units === 'imperial' ? 'mph' : 'kmh';

  const url = `${WEATHER_API_BASE}/forecast?` + new URLSearchParams({
    latitude: coords.lat.toString(),
    longitude: coords.lon.toString(),
    current: 'temperature_2m,relative_humidity_2m,weather_code,wind_speed_10m',
    daily: 'temperature_2m_max,temperature_2m_min,weather_code',
    temperature_unit: temperatureUnit,
    wind_speed_unit: windSpeedUnit,
    timezone: 'auto',
    forecast_days: '5',
  });

  const data = await fetchJson<OpenMeteoResponse>(url, {
    timeout: 10000,
    maxResponseSize: 50 * 1024, // 50KB limit per spec
  });

  const tempSymbol = args.units === 'imperial' ? 'F' : 'C';
  const speedUnit = args.units === 'imperial' ? 'mph' : 'km/h';

  const result = {
    city: args.city,
    coordinates: { latitude: data.latitude, longitude: data.longitude },
    timezone: data.timezone,
    units: args.units,
    current: {
      time: data.current.time,
      temperature: `${data.current.temperature_2m}°${tempSymbol}`,
      humidity: `${data.current.relative_humidity_2m}%`,
      conditions: getWeatherDescription(data.current.weather_code),
      windSpeed: `${data.current.wind_speed_10m} ${speedUnit}`,
    },
    forecast: data.daily.time.map((date, i) => ({
      date,
      high: `${data.daily.temperature_2m_max[i]}°${tempSymbol}`,
      low: `${data.daily.temperature_2m_min[i]}°${tempSymbol}`,
      conditions: getWeatherDescription(data.daily.weather_code[i]),
    })),
  };

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify(result, null, 2),
    }],
  };
}
