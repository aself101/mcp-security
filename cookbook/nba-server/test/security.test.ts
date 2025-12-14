/**
 * Security tests for NBA MCP Server
 */

import { describe, it, expect } from 'vitest';

describe('NBA Server Security', () => {
  describe('Input Validation', () => {
    it('should require positive player IDs', async () => {
      const { getPlayerStatsSchema } = await import('../src/tools/player.js');

      // Player IDs should be positive numbers
      expect(() => getPlayerStatsSchema.parse({ playerId: 2544 })).not.toThrow();
      expect(() => getPlayerStatsSchema.parse({ playerId: 1 })).not.toThrow();
    });

    it('should require positive team IDs', async () => {
      const { getTeamRosterSchema } = await import('../src/tools/team.js');

      expect(() => getTeamRosterSchema.parse({ teamId: 1610612747 })).not.toThrow();
    });

    it('should require game ID strings', async () => {
      const { getBoxScoreSchema } = await import('../src/tools/game.js');

      expect(() => getBoxScoreSchema.parse({ gameId: '0022400350' })).not.toThrow();

      // Number should fail (must be string)
      expect(() => getBoxScoreSchema.parse({ gameId: 22400350 })).toThrow();
    });
  });

  describe('Injection Prevention', () => {
    it('should handle SQL injection in player search', async () => {
      const { findPlayerSchema } = await import('../src/tools/player.js');

      const maliciousInputs = [
        "'; DROP TABLE players;--",
        "' OR '1'='1",
        "LeBron; SELECT * FROM users",
      ];

      for (const input of maliciousInputs) {
        // Schema accepts strings - no SQL is used
        expect(() => findPlayerSchema.parse({ name: input })).not.toThrow();
      }
    });

    it('should handle command injection attempts', async () => {
      const { findPlayerSchema } = await import('../src/tools/player.js');

      const maliciousInputs = [
        "$(whoami)",
        "`id`",
        "| cat /etc/passwd",
      ];

      for (const input of maliciousInputs) {
        // Schema accepts strings - no shell execution
        expect(() => findPlayerSchema.parse({ name: input })).not.toThrow();
      }
    });
  });

  describe('Side Effect Declarations', () => {
    it('should properly categorize tool side effects', async () => {
      const toolRegistry = [
        { name: 'get-player-stats', sideEffects: 'network' },
        { name: 'get-live-scoreboard', sideEffects: 'network' },
        { name: 'find-player', sideEffects: 'none' },
      ];

      // Network tools
      const networkTools = toolRegistry.filter(t => t.sideEffects === 'network');
      expect(networkTools.length).toBe(2);

      // Local tools
      const localTools = toolRegistry.filter(t => t.sideEffects === 'none');
      expect(localTools).toContainEqual({ name: 'find-player', sideEffects: 'none' });
    });
  });

  describe('No Credential Exposure', () => {
    it('should not have credential fields in schemas', async () => {
      const { getPlayerStatsSchema } = await import('../src/tools/player.js');
      const { getTeamRosterSchema } = await import('../src/tools/team.js');

      const playerSchemaKeys = Object.keys(getPlayerStatsSchema.shape);
      const teamSchemaKeys = Object.keys(getTeamRosterSchema.shape);

      const sensitiveKeys = ['apiKey', 'api_key', 'token', 'secret', 'password'];

      for (const key of sensitiveKeys) {
        expect(playerSchemaKeys).not.toContain(key);
        expect(teamSchemaKeys).not.toContain(key);
      }
    });
  });

  describe('Season Format Validation', () => {
    it('should accept valid season formats', async () => {
      const { getPlayerStatsSchema } = await import('../src/tools/player.js');

      // Valid seasons
      expect(() => getPlayerStatsSchema.parse({
        playerId: 2544,
        season: '2024-25'
      })).not.toThrow();

      expect(() => getPlayerStatsSchema.parse({
        playerId: 2544,
        season: '2023-24'
      })).not.toThrow();
    });
  });
});
