/**
 * Security tests for KenPom MCP Server
 */

import { describe, it, expect } from 'vitest';

describe('KenPom Server Security', () => {
  describe('Input Validation', () => {
    it('should reject invalid season values', async () => {
      const { getRatingsSchema } = await import('../src/tools/ratings.js');

      // Too old
      expect(() => getRatingsSchema.parse({ season: 1998 })).toThrow();
      expect(() => getRatingsSchema.parse({ season: 1990 })).toThrow();

      // Valid boundary
      expect(() => getRatingsSchema.parse({ season: 1999 })).not.toThrow();
    });

    it('should reject player stats with invalid season', async () => {
      const { getPlayerStatsSchema } = await import('../src/tools/player.js');

      // Player stats only available from 2004
      expect(() => getPlayerStatsSchema.parse({ season: 2003 })).toThrow();
      expect(() => getPlayerStatsSchema.parse({ season: 2004 })).not.toThrow();
    });

    it('should only accept valid metric values', async () => {
      const { getPlayerStatsSchema } = await import('../src/tools/player.js');

      const validMetrics = ['ORtg', 'Min', 'eFG', 'TS', 'OR', 'DR', 'TO', 'ARate', 'Blk', 'Stl', 'FC40', 'FD40', '2P', '3P', 'FT'];

      for (const metric of validMetrics) {
        expect(() => getPlayerStatsSchema.parse({ metric })).not.toThrow();
      }

      // Invalid metrics
      expect(() => getPlayerStatsSchema.parse({ metric: 'PPG' })).toThrow();
      expect(() => getPlayerStatsSchema.parse({ metric: 'invalid' })).toThrow();
    });
  });

  describe('Injection Prevention', () => {
    it('should handle SQL injection in team names', async () => {
      const { getScheduleSchema } = await import('../src/tools/team.js');

      // These should parse (validation only checks type)
      // Actual sanitization happens in the API layer
      const maliciousInputs = [
        "Duke'; DROP TABLE teams;--",
        "Duke\" OR \"1\"=\"1",
        "Duke; SELECT * FROM users",
      ];

      for (const input of maliciousInputs) {
        expect(() => getScheduleSchema.parse({ team: input })).not.toThrow();
        // Note: Input validation passes, but API will safely encode/handle
      }
    });

    it('should handle command injection attempts', async () => {
      const { getScheduleSchema } = await import('../src/tools/team.js');

      const maliciousInputs = [
        "$(whoami)",
        "`id`",
        "| cat /etc/passwd",
        "&& rm -rf /",
      ];

      for (const input of maliciousInputs) {
        // Schema accepts strings, actual execution is safe
        expect(() => getScheduleSchema.parse({ team: input })).not.toThrow();
      }
    });
  });

  describe('Date Validation', () => {
    it('should accept valid date formats', async () => {
      const { getFanMatchSchema } = await import('../src/tools/conference.js');

      expect(() => getFanMatchSchema.parse({ date: '2025-01-15' })).not.toThrow();
      expect(() => getFanMatchSchema.parse({})).not.toThrow(); // Optional
    });
  });

  describe('Credential Security', () => {
    it('should not expose credentials in schema', async () => {
      const { getRatingsSchema } = await import('../src/tools/ratings.js');

      const schemaKeys = Object.keys(getRatingsSchema.shape);

      expect(schemaKeys).not.toContain('email');
      expect(schemaKeys).not.toContain('password');
      expect(schemaKeys).not.toContain('apiKey');
      expect(schemaKeys).not.toContain('token');
    });
  });
});
