/**
 * NBA league-wide tools
 */

import { z } from 'zod';
import { NbaAPI } from 'nba-api';

let apiInstance: NbaAPI | null = null;

async function getApi(): Promise<NbaAPI> {
  if (!apiInstance) {
    apiInstance = new NbaAPI();
    await apiInstance.connect();
  }
  return apiInstance;
}

export const getLeagueLeadersSchema = z.object({
  season: z.string().optional().describe('Season in YYYY-YY format (e.g., "2024-25")'),
  statCategory: z.enum(['PTS', 'REB', 'AST', 'STL', 'BLK', 'FG_PCT', 'FT_PCT', 'FG3_PCT']).optional()
    .describe('Stat category to rank by')
});

export type GetLeagueLeadersArgs = z.infer<typeof getLeagueLeadersSchema>;

export async function getLeagueLeaders(args: GetLeagueLeadersArgs) {
  const api = await getApi();
  const leaders = await api.getLeagueLeaders(args.season, args.statCategory);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        season: args.season || 'current',
        category: args.statCategory || 'PTS',
        leaders
      }, null, 2)
    }]
  };
}

export const getStandingsSchema = z.object({
  season: z.string().optional().describe('Season in YYYY-YY format (e.g., "2024-25")'),
  seasonType: z.enum(['Regular Season', 'Playoffs']).optional().describe('Season type')
});

export type GetStandingsArgs = z.infer<typeof getStandingsSchema>;

export async function getStandings(args: GetStandingsArgs) {
  const api = await getApi();
  const standings = await api.getLeagueStandings(args.season, args.seasonType);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        season: args.season || 'current',
        standings
      }, null, 2)
    }]
  };
}
