/**
 * KenPom efficiency and four factors tools
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

export const getEfficiencySchema = z.object({
  season: z.number().min(1999).optional().describe('Season year (defaults to current)')
});

export type GetEfficiencyArgs = z.infer<typeof getEfficiencySchema>;

export async function getEfficiency(args: GetEfficiencyArgs) {
  const api = await getApi();
  const efficiency = await api.getEfficiency(args.season);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        season: args.season || 'current',
        count: efficiency.length,
        data: efficiency.slice(0, 50)
      }, null, 2)
    }]
  };
}

export const getFourFactorsSchema = z.object({
  season: z.number().min(1999).optional().describe('Season year (defaults to current)')
});

export type GetFourFactorsArgs = z.infer<typeof getFourFactorsSchema>;

export async function getFourFactors(args: GetFourFactorsArgs) {
  const api = await getApi();
  const fourFactors = await api.getFourFactors(args.season);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        season: args.season || 'current',
        count: fourFactors.length,
        data: fourFactors.slice(0, 50)
      }, null, 2)
    }]
  };
}

export const getTeamStatsSchema = z.object({
  season: z.number().min(1999).optional().describe('Season year (defaults to current)'),
  defense: z.boolean().optional().describe('Get defensive stats instead of offensive')
});

export type GetTeamStatsArgs = z.infer<typeof getTeamStatsSchema>;

export async function getTeamStats(args: GetTeamStatsArgs) {
  const api = await getApi();
  const stats = await api.getTeamStats(args.season, args.defense);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        season: args.season || 'current',
        type: args.defense ? 'defensive' : 'offensive',
        count: stats.length,
        data: stats.slice(0, 50)
      }, null, 2)
    }]
  };
}
