/**
 * KenPom team tools - schedule, scouting report
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

export const getScheduleSchema = z.object({
  team: z.string().describe('Team name (e.g., "Duke", "Kansas")'),
  season: z.number().min(1999).optional().describe('Season year (defaults to current)')
});

export type GetScheduleArgs = z.infer<typeof getScheduleSchema>;

export async function getSchedule(args: GetScheduleArgs) {
  const api = await getApi();
  const schedule = await api.getSchedule(args.team, args.season);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        team: args.team,
        season: args.season || 'current',
        games: schedule
      }, null, 2)
    }]
  };
}

export const getScoutingReportSchema = z.object({
  team: z.string().describe('Team name (e.g., "Duke", "Kansas")'),
  season: z.number().min(1999).optional().describe('Season year (defaults to current)'),
  conferenceOnly: z.boolean().optional().describe('Only show conference games')
});

export type GetScoutingReportArgs = z.infer<typeof getScoutingReportSchema>;

export async function getScoutingReport(args: GetScoutingReportArgs) {
  const api = await getApi();
  const report = await api.getScoutingReport(args.team, args.season, args.conferenceOnly);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        team: args.team,
        season: args.season || 'current',
        conferenceOnly: args.conferenceOnly || false,
        report
      }, null, 2)
    }]
  };
}
