/**
 * KenPom ratings tools
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

export const getRatingsSchema = z.object({
  season: z.number().min(1999).optional().describe('Season year (defaults to current)')
});

export type GetRatingsArgs = z.infer<typeof getRatingsSchema>;

export async function getRatings(args: GetRatingsArgs) {
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
}

export const getProgramRatingsSchema = z.object({});

export async function getProgramRatings() {
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
}
