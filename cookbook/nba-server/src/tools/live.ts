/**
 * NBA live data tools - scoreboard, live box scores
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

export const getLiveScoreboardSchema = z.object({});

export async function getLiveScoreboard() {
  const api = await getApi();
  const scoreboard = await api.getLiveScoreboard();

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        date: new Date().toISOString().split('T')[0],
        games: scoreboard
      }, null, 2)
    }]
  };
}

export const getLiveBoxScoreSchema = z.object({
  gameId: z.string().describe('NBA game ID (e.g., "0022400123")')
});

export type GetLiveBoxScoreArgs = z.infer<typeof getLiveBoxScoreSchema>;

export async function getLiveBoxScore(args: GetLiveBoxScoreArgs) {
  const api = await getApi();
  const boxScore = await api.getLiveBoxScore(args.gameId);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        gameId: args.gameId,
        live: true,
        boxScore
      }, null, 2)
    }]
  };
}
