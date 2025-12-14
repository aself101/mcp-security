/**
 * NBA game tools - box scores, play-by-play
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

export const getBoxScoreSchema = z.object({
  gameId: z.string().describe('NBA game ID (e.g., "0022400123")')
});

export type GetBoxScoreArgs = z.infer<typeof getBoxScoreSchema>;

export async function getBoxScore(args: GetBoxScoreArgs) {
  const api = await getApi();
  const boxScore = await api.getBoxScoreTraditional(args.gameId);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        gameId: args.gameId,
        boxScore
      }, null, 2)
    }]
  };
}

export const getPlayByPlaySchema = z.object({
  gameId: z.string().describe('NBA game ID (e.g., "0022400123")')
});

export type GetPlayByPlayArgs = z.infer<typeof getPlayByPlaySchema>;

export async function getPlayByPlay(args: GetPlayByPlayArgs) {
  const api = await getApi();
  const playByPlay = await api.getPlayByPlay(args.gameId);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        gameId: args.gameId,
        plays: playByPlay
      }, null, 2)
    }]
  };
}
