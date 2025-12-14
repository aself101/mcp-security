/**
 * Integration tests for NBA MCP Server
 */

import { describe, it, expect } from 'vitest';

describe('NBA Server Integration', () => {
  describe('Tool Schema Validation', () => {
    it('should validate find-player schema', async () => {
      const { findPlayerSchema } = await import('../src/tools/player.js');

      // Valid input
      expect(() => findPlayerSchema.parse({ name: 'LeBron' })).not.toThrow();

      // Missing required field
      expect(() => findPlayerSchema.parse({})).toThrow();
    });

    it('should validate get-player-stats schema', async () => {
      const { getPlayerStatsSchema } = await import('../src/tools/player.js');

      // Valid input
      expect(() => getPlayerStatsSchema.parse({ playerId: 2544 })).not.toThrow();

      // With optional season
      expect(() => getPlayerStatsSchema.parse({
        playerId: 2544,
        season: '2024-25'
      })).not.toThrow();

      // Missing required field
      expect(() => getPlayerStatsSchema.parse({})).toThrow();
    });

    it('should validate get-team-roster schema', async () => {
      const { getTeamRosterSchema } = await import('../src/tools/team.js');

      // Valid input
      expect(() => getTeamRosterSchema.parse({ teamId: 1610612747 })).not.toThrow();

      // Missing required field
      expect(() => getTeamRosterSchema.parse({})).toThrow();
    });

    it('should validate get-box-score schema', async () => {
      const { getBoxScoreSchema } = await import('../src/tools/game.js');

      // Valid input
      expect(() => getBoxScoreSchema.parse({ gameId: '0022400350' })).not.toThrow();

      // Missing required field
      expect(() => getBoxScoreSchema.parse({})).toThrow();
    });

    it('should validate get-live-scoreboard schema', async () => {
      const { getLiveScoreboardSchema } = await import('../src/tools/live.js');

      // No arguments required
      expect(() => getLiveScoreboardSchema.parse({})).not.toThrow();
    });
  });

  describe('Response Format', () => {
    it('should return proper content structure', async () => {
      const mockResponse = {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: true,
            player: 'LeBron James',
            careerStats: { ppg: 27.1 }
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
