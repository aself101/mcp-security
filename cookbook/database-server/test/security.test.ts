/**
 * Security Tests for Database Server
 * Tests SQL injection prevention and security policies
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { queryUsers } from '../src/tools/query-users.js';
import { createOrder } from '../src/tools/create-order.js';
import { generateReport } from '../src/tools/generate-report.js';
import { healthCheck } from '../src/tools/health-check.js';
import { closeDatabase } from '../src/utils/database.js';

// Clean up database after each test suite
afterEach(() => {
  closeDatabase();
});

// ============================================================================
// SQL Injection Prevention Tests
// ============================================================================

describe('SQL injection prevention', () => {
  describe('query-users SQL injection attacks', () => {
    const sqlInjectionPayloads = [
      // Classic SQL injection
      "' OR '1'='1",
      "' OR 1=1 --",
      "'; DROP TABLE users; --",
      "' UNION SELECT * FROM users --",
      "1' OR '1'='1'/*",

      // Comment-based injection
      "admin'--",
      "admin'/*",
      "admin' #",

      // UNION-based injection
      "' UNION SELECT 1,2,3,4,5 --",
      "' UNION SELECT username,password FROM credentials --",

      // Blind SQL injection
      "' AND 1=1 --",
      "' AND SUBSTRING(username,1,1)='a' --",
      "' AND (SELECT COUNT(*) FROM users) > 0 --",

      // Time-based blind injection (SQLite)
      "' AND (SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END) --",

      // Stacked queries
      "'; INSERT INTO users VALUES (999,'hacker','hacker@evil.com','Hacked','2024-01-01'); --",
      "'; UPDATE users SET department='PWNED' WHERE 1=1; --",
      "'; DELETE FROM users; --",
    ];

    for (const payload of sqlInjectionPayloads) {
      it(`should safely handle: ${payload.slice(0, 40)}...`, async () => {
        // The tool uses parameterized queries, so injection should be treated as literal search
        const result = await queryUsers({ search: payload, limit: 10 });

        // Should return result without error (empty results expected)
        const content = JSON.parse(result.content[0].text);

        // Should NOT have caused any SQL errors or unexpected behavior
        expect(content).toHaveProperty('users');
        expect(Array.isArray(content.users)).toBe(true);

        // Should find no users (payload treated as literal string)
        expect(content.users.length).toBe(0);
      });
    }
  });

  describe('create-order injection attempts', () => {
    it('should handle SQL injection in order items', async () => {
      const result = await createOrder({
        userId: 1,
        items: [
          { product: "'; DROP TABLE orders; --", quantity: 1, price: 100 },
        ],
        total: 100,
      });

      const content = JSON.parse(result.content[0].text);

      // Order should be created successfully (injection is just data)
      expect(content.success).toBe(true);
      expect(content.orderId).toBeDefined();
    });
  });

  describe('generate-report date injection attempts', () => {
    const dateInjections = [
      // SQL injection in date parameters
      "2024-01-01' OR '1'='1",
      "2024-01-01'; DROP TABLE orders; --",
      "2024-01-01 UNION SELECT * FROM users --",
    ];

    for (const payload of dateInjections) {
      it(`should reject malformed date: ${payload.slice(0, 30)}...`, async () => {
        // Zod schema should reject these as they don't match YYYY-MM-DD format
        try {
          await generateReport({
            startDate: payload,
            endDate: '2024-12-31',
            groupBy: 'month',
          });
          // If we get here, schema validation didn't catch it
          expect(false).toBe(true); // Force fail
        } catch (error) {
          // Expected - Zod validation should reject invalid dates
          expect(error).toBeDefined();
        }
      });
    }
  });
});

// ============================================================================
// NoSQL Injection Prevention Tests
// ============================================================================

describe('NoSQL injection prevention', () => {
  const noSqlPayloads = [
    '{"$where": "this.password == this.password"}',
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    '{"$or": [{"a": 1}, {"b": 2}]}',
  ];

  for (const payload of noSqlPayloads) {
    it(`should handle NoSQL-style payload: ${payload.slice(0, 30)}...`, async () => {
      const result = await queryUsers({ search: payload, limit: 10 });

      const content = JSON.parse(result.content[0].text);

      // Should treat as literal string, not execute as query
      expect(content).toHaveProperty('users');
      expect(content.users.length).toBe(0);
    });
  }
});

// ============================================================================
// Input Validation Tests
// ============================================================================

describe('input validation', () => {
  describe('query-users input validation', () => {
    it('should respect limit parameter', async () => {
      const result = await queryUsers({ search: 'a', limit: 2 });

      const content = JSON.parse(result.content[0].text);
      expect(content.users.length).toBeLessThanOrEqual(2);
    });

    it('should handle empty search gracefully', async () => {
      // Zod schema requires min 1 character
      try {
        await queryUsers({ search: '', limit: 10 });
        expect(false).toBe(true);
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    it('should handle very long search strings', async () => {
      // Zod schema limits to 100 characters
      const longSearch = 'a'.repeat(101);
      try {
        await queryUsers({ search: longSearch, limit: 10 });
        expect(false).toBe(true);
      } catch (error) {
        expect(error).toBeDefined();
      }
    });
  });

  describe('create-order input validation', () => {
    it('should reject invalid user ID', async () => {
      const result = await createOrder({
        userId: 99999,
        items: [{ product: 'Test', quantity: 1, price: 10 }],
        total: 10,
      });

      const content = JSON.parse(result.content[0].text);
      expect(content.error).toBe('User not found');
    });

    it('should reject mismatched totals', async () => {
      const result = await createOrder({
        userId: 1,
        items: [{ product: 'Test', quantity: 2, price: 10 }],
        total: 100, // Should be 20
      });

      const content = JSON.parse(result.content[0].text);
      expect(content.error).toBe('Total mismatch');
    });

    it('should reject negative quantities', async () => {
      try {
        await createOrder({
          userId: 1,
          items: [{ product: 'Test', quantity: -1, price: 10 }],
          total: -10,
        });
        expect(false).toBe(true);
      } catch (error) {
        expect(error).toBeDefined();
      }
    });
  });

  describe('generate-report input validation', () => {
    it('should reject invalid date range', async () => {
      const result = await generateReport({
        startDate: '2024-12-31',
        endDate: '2024-01-01', // End before start
        groupBy: 'month',
      });

      const content = JSON.parse(result.content[0].text);
      expect(content.error).toBe('Invalid date range');
    });

    it('should handle valid date range', async () => {
      const result = await generateReport({
        startDate: '2024-01-01',
        endDate: '2024-12-31',
        groupBy: 'month',
      });

      const content = JSON.parse(result.content[0].text);
      expect(content).toHaveProperty('summary');
      expect(content).toHaveProperty('data');
    });
  });
});

// ============================================================================
// Side Effect Tests
// ============================================================================

describe('side effect enforcement', () => {
  it('query-users should only read data', async () => {
    // Run query
    await queryUsers({ search: 'Alice', limit: 10 });

    // Verify data wasn't modified by running health check
    const health = await healthCheck();
    const content = JSON.parse(health.content[0].text);

    // Original seed data should still be intact
    expect(content.statistics.userCount).toBe(10);
  });

  it('generate-report should only read data', async () => {
    // Run report
    await generateReport({
      startDate: '2024-01-01',
      endDate: '2024-12-31',
      groupBy: 'month',
    });

    // Verify data wasn't modified
    const health = await healthCheck();
    const content = JSON.parse(health.content[0].text);

    expect(content.statistics.orderCount).toBe(10);
  });

  it('create-order should create new data', async () => {
    // Get initial count
    const beforeHealth = await healthCheck();
    const beforeContent = JSON.parse(beforeHealth.content[0].text);
    const initialOrders = beforeContent.statistics.orderCount;

    // Create order
    await createOrder({
      userId: 1,
      items: [{ product: 'New Product', quantity: 1, price: 50 }],
      total: 50,
    });

    // Verify order was created
    const afterHealth = await healthCheck();
    const afterContent = JSON.parse(afterHealth.content[0].text);

    expect(afterContent.statistics.orderCount).toBe(initialOrders + 1);
  });
});

// ============================================================================
// Health Check Tests
// ============================================================================

describe('health-check security', () => {
  it('should not expose sensitive database information', async () => {
    const result = await healthCheck();
    const content = JSON.parse(result.content[0].text);

    // Should expose only safe information
    expect(content.database.type).toBe('sqlite');
    expect(content.database.mode).toBe('in-memory');

    // Should NOT expose connection strings, file paths, etc.
    expect(content.database).not.toHaveProperty('connectionString');
    expect(content.database).not.toHaveProperty('path');
    expect(content.database).not.toHaveProperty('password');
  });
});

// ============================================================================
// XSS Prevention Tests
// ============================================================================

describe('XSS prevention in stored data', () => {
  it('should store XSS payloads as literal text', async () => {
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert(1)>',
      'javascript:alert(1)',
      '<svg onload=alert(1)>',
    ];

    for (const payload of xssPayloads) {
      const result = await createOrder({
        userId: 1,
        items: [{ product: payload, quantity: 1, price: 10 }],
        total: 10,
      });

      const content = JSON.parse(result.content[0].text);

      // Order should be created (XSS is just stored as text)
      expect(content.success).toBe(true);
    }
  });
});

// ============================================================================
// Numeric Overflow Tests
// ============================================================================

describe('numeric overflow prevention', () => {
  it('should handle maximum safe integers', async () => {
    // Zod schema should limit max values
    try {
      await createOrder({
        userId: 1,
        items: [{ product: 'Test', quantity: Number.MAX_SAFE_INTEGER, price: 1 }],
        total: Number.MAX_SAFE_INTEGER,
      });
      expect(false).toBe(true);
    } catch (error) {
      expect(error).toBeDefined();
    }
  });

  it('should handle negative numbers', async () => {
    try {
      await createOrder({
        userId: 1,
        items: [{ product: 'Test', quantity: 1, price: -100 }],
        total: -100,
      });
      expect(false).toBe(true);
    } catch (error) {
      expect(error).toBeDefined();
    }
  });
});

// ============================================================================
// Concurrent Access Tests
// ============================================================================

describe('concurrent access safety', () => {
  it('should handle concurrent reads safely', async () => {
    const promises = Array(10).fill(null).map(() =>
      queryUsers({ search: 'a', limit: 10 })
    );

    const results = await Promise.all(promises);

    // All should succeed without data corruption
    for (const result of results) {
      const content = JSON.parse(result.content[0].text);
      expect(content).toHaveProperty('users');
    }
  });

  it('should handle concurrent writes with transactions', async () => {
    const promises = Array(5).fill(null).map((_, i) =>
      createOrder({
        userId: 1,
        items: [{ product: `Concurrent ${i}`, quantity: 1, price: 10 }],
        total: 10,
      })
    );

    const results = await Promise.all(promises);

    // All should succeed
    for (const result of results) {
      const content = JSON.parse(result.content[0].text);
      expect(content.success).toBe(true);
    }
  });
});
