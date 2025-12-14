/**
 * KenPom player stats tools
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

export const getPlayerStatsSchema = z.object({
  season: z.number().min(2004).optional().describe('Season year (defaults to current, min 2004)'),
  metric: z.enum(['ORtg', 'Min', 'eFG', 'TS', 'OR', 'DR', 'TO', 'ARate', 'Blk', 'Stl', 'FC40', 'FD40', '2P', '3P', 'FT']).optional()
    .describe('Specific metric to retrieve'),
  conference: z.string().optional().describe('Filter by conference'),
  conferenceOnly: z.boolean().optional().describe('Only conference games')
});

export type GetPlayerStatsArgs = z.infer<typeof getPlayerStatsSchema>;

export async function getPlayerStats(args: GetPlayerStatsArgs) {
  const api = await getApi();
  const stats = await api.getPlayerStats(args.season, args.metric, args.conference, args.conferenceOnly);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        season: args.season || 'current',
        metric: args.metric || 'all',
        count: stats.length,
        players: stats.slice(0, 100)
      }, null, 2)
    }]
  };
}
