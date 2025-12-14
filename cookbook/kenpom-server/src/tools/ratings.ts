/**
 * KenPom ratings tools
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

export const getRatingsSchema = z.object({
  season: z.number().min(1999).optional().describe('Season year (defaults to current)')
});

export type GetRatingsArgs = z.infer<typeof getRatingsSchema>;

export async function getRatings(args: GetRatingsArgs) {
  try {
    const api = await getApi();
    const ratings = await api.getPomeroyRatings(args.season);

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          season: args.season || 'current',
          count: ratings.length,
          ratings: ratings.slice(0, 50)
        }, null, 2)
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to fetch ratings'
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const getProgramRatingsSchema = z.object({});

export async function getProgramRatings() {
  try {
    const api = await getApi();
    const ratings = await api.getProgramRatings();

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          count: ratings.length,
          ratings: ratings.slice(0, 50)
        }, null, 2)
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to fetch program ratings'
        }, null, 2)
      }],
      isError: true
    };
  }
}
