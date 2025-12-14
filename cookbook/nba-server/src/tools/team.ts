/**
 * NBA team tools
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

export const getTeamRosterSchema = z.object({
  teamId: z.number().describe('NBA team ID'),
  season: z.string().optional().describe('Season in YYYY-YY format (e.g., "2024-25")')
});

export type GetTeamRosterArgs = z.infer<typeof getTeamRosterSchema>;

export async function getTeamRoster(args: GetTeamRosterArgs) {
  const api = await getApi();
  const roster = await api.getCommonTeamRoster(args.teamId, args.season);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        teamId: args.teamId,
        season: args.season || 'current',
        roster
      }, null, 2)
    }]
  };
}

export const getTeamGameLogSchema = z.object({
  teamId: z.number().describe('NBA team ID'),
  season: z.string().optional().describe('Season in YYYY-YY format (e.g., "2024-25")'),
  seasonType: z.enum(['Regular Season', 'Playoffs']).optional().describe('Season type filter')
});

export type GetTeamGameLogArgs = z.infer<typeof getTeamGameLogSchema>;

export async function getTeamGameLog(args: GetTeamGameLogArgs) {
  const api = await getApi();
  const gameLog = await api.getTeamGameLog(args.teamId, args.season, args.seasonType);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        teamId: args.teamId,
        season: args.season || 'current',
        games: gameLog
      }, null, 2)
    }]
  };
}
