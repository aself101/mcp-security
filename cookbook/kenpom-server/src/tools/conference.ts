/**
 * KenPom conference tools
 */

import { z } from 'zod';
import { KenpomAPI } from 'kenpom-api';

let apiInstance: KenpomAPI | null = null;

async function getApi(): Promise<KenpomAPI> {
  if (!apiInstance) {
    apiInstance = new KenpomAPI({ logLevel: 'NONE' });
    await apiInstance.login();
  }
  return apiInstance;
}

export const getConferenceStandingsSchema = z.object({
  conference: z.string().describe('Conference name (e.g., "ACC", "Big Ten", "SEC")'),
  season: z.number().min(1999).optional().describe('Season year (defaults to current)')
});

export type GetConferenceStandingsArgs = z.infer<typeof getConferenceStandingsSchema>;

export async function getConferenceStandings(args: GetConferenceStandingsArgs) {
  const api = await getApi();
  const standings = await api.getConferenceStandings(args.conference, args.season);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        conference: args.conference,
        season: args.season || 'current',
        standings
      }, null, 2)
    }]
  };
}

export const getFanMatchSchema = z.object({
  date: z.string().optional().describe('Date in YYYY-MM-DD format (defaults to today)')
});

export type GetFanMatchArgs = z.infer<typeof getFanMatchSchema>;

export async function getFanMatch(args: GetFanMatchArgs) {
  const api = await getApi();
  const fanMatch = await api.getFanMatch(args.date);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        date: args.date || 'today',
        games: fanMatch
      }, null, 2)
    }]
  };
}
