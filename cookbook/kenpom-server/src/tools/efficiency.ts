/**
 * KenPom efficiency and four factors tools
 */

import { z } from 'zod';
import { KenpomAPI } from 'kenpom-api';

let apiInstance: KenpomAPI | null = null;

async function getApi(): Promise<KenpomAPI> {
  if (!apiInstance) {
    if (!process.env.KENPOM_EMAIL || !process.env.KENPOM_PASSWORD) {
      throw new Error(
        'KenPom credentials required. Set KENPOM_EMAIL and KENPOM_PASSWORD environment variables. ' +
        'Get your subscription at https://kenpom.com'
      );
    }
    try {
      apiInstance = new KenpomAPI({ logLevel: 'NONE' });
      await apiInstance.login();
    } catch (error) {
      throw new Error(
        'Failed to authenticate with KenPom. Verify your KENPOM_EMAIL and KENPOM_PASSWORD are correct. ' +
        `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }
  return apiInstance;
}

export const getEfficiencySchema = z.object({
  season: z.number().min(1999).optional().describe('Season year (defaults to current)')
});

export type GetEfficiencyArgs = z.infer<typeof getEfficiencySchema>;

export async function getEfficiency(args: GetEfficiencyArgs) {
  try {
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
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to fetch efficiency data'
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const getFourFactorsSchema = z.object({
  season: z.number().min(1999).optional().describe('Season year (defaults to current)')
});

export type GetFourFactorsArgs = z.infer<typeof getFourFactorsSchema>;

export async function getFourFactors(args: GetFourFactorsArgs) {
  try {
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
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to fetch four factors data'
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const getTeamStatsSchema = z.object({
  season: z.number().min(1999).optional().describe('Season year (defaults to current)'),
  defense: z.boolean().optional().describe('Get defensive stats instead of offensive')
});

export type GetTeamStatsArgs = z.infer<typeof getTeamStatsSchema>;

export async function getTeamStats(args: GetTeamStatsArgs) {
  try {
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
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to fetch team stats'
        }, null, 2)
      }],
      isError: true
    };
  }
}
