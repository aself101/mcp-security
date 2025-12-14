/**
 * NBA player stats tools
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

export const getPlayerStatsSchema = z.object({
  playerId: z.number().describe('NBA player ID'),
  seasonType: z.enum(['Regular Season', 'Playoffs']).optional().describe('Season type filter')
});

export type GetPlayerStatsArgs = z.infer<typeof getPlayerStatsSchema>;

export async function getPlayerStats(args: GetPlayerStatsArgs) {
  const api = await getApi();
  const stats = await api.getPlayerCareerStats(args.playerId, {
    perMode: 'PerGame'
  });

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        playerId: args.playerId,
        stats
      }, null, 2)
    }]
  };
}

export const getPlayerGameLogSchema = z.object({
  playerId: z.number().describe('NBA player ID'),
  season: z.string().optional().describe('Season in YYYY-YY format (e.g., "2024-25")'),
  seasonType: z.enum(['Regular Season', 'Playoffs']).optional().describe('Season type filter')
});

export type GetPlayerGameLogArgs = z.infer<typeof getPlayerGameLogSchema>;

export async function getPlayerGameLog(args: GetPlayerGameLogArgs) {
  const api = await getApi();
  const gameLog = await api.getPlayerGameLog(args.playerId, args.season, args.seasonType);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        playerId: args.playerId,
        season: args.season || 'current',
        games: gameLog
      }, null, 2)
    }]
  };
}

export const getPlayerInfoSchema = z.object({
  playerId: z.number().describe('NBA player ID')
});

export type GetPlayerInfoArgs = z.infer<typeof getPlayerInfoSchema>;

export async function getPlayerInfo(args: GetPlayerInfoArgs) {
  const api = await getApi();
  const info = await api.getCommonPlayerInfo(args.playerId);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        playerId: args.playerId,
        info
      }, null, 2)
    }]
  };
}

export const findPlayerSchema = z.object({
  name: z.string().describe('Player name to search for (partial match supported)')
});

export type FindPlayerArgs = z.infer<typeof findPlayerSchema>;

export async function findPlayer(args: FindPlayerArgs) {
  const api = await getApi();
  const players = api.findPlayersByName(args.name);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        searchTerm: args.name,
        count: players.length,
        players: players.slice(0, 20)
      }, null, 2)
    }]
  };
}
