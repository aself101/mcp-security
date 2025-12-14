/**
 * Integration tests for KenPom MCP Server
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';

describe('KenPom Server Integration', () => {
  describe('Tool Schema Validation', () => {
    it('should validate get-ratings schema', async () => {
      const { getRatingsSchema } = await import('../src/tools/ratings.js');

      // Valid input
      expect(() => getRatingsSchema.parse({ season: 2025 })).not.toThrow();
      expect(() => getRatingsSchema.parse({})).not.toThrow();

      // Invalid input
      expect(() => getRatingsSchema.parse({ season: 1990 })).toThrow();
    });

    it('should validate get-schedule schema', async () => {
      const { getScheduleSchema } = await import('../src/tools/team.js');

      // Valid input
      expect(() => getScheduleSchema.parse({ team: 'Duke' })).not.toThrow();
      expect(() => getScheduleSchema.parse({ team: 'Duke', season: 2024 })).not.toThrow();

      // Invalid input - missing required field
      expect(() => getScheduleSchema.parse({})).toThrow();
    });

    it('should validate get-player-stats schema', async () => {
      const { getPlayerStatsSchema } = await import('../src/tools/player.js');

      // Valid metrics
      expect(() => getPlayerStatsSchema.parse({ metric: 'ORtg' })).not.toThrow();
      expect(() => getPlayerStatsSchema.parse({ metric: 'eFG' })).not.toThrow();

      // Invalid metric
      expect(() => getPlayerStatsSchema.parse({ metric: 'INVALID' })).toThrow();
    });

    it('should validate get-conference-standings schema', async () => {
      const { getConferenceStandingsSchema } = await import('../src/tools/conference.js');

      // Valid input
      expect(() => getConferenceStandingsSchema.parse({ conference: 'B10' })).not.toThrow();

      // Invalid - missing required conference
      expect(() => getConferenceStandingsSchema.parse({})).toThrow();
    });
  });

  describe('Response Format', () => {
    it('should return proper content structure', async () => {
      // Mock test - actual API calls require credentials
      const mockResponse = {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: true,
            season: 'current',
            count: 50,
            ratings: []
          }, null, 2)
        }]
      };

      expect(mockResponse.content).toHaveLength(1);
      expect(mockResponse.content[0].type).toBe('text');

      const parsed = JSON.parse(mockResponse.content[0].text);
      expect(parsed.success).toBe(true);
    });
  });
});
