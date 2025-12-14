/**
 * Database MCP Server
 *
 * Demonstrates safe database operations with:
 * - Layer 2: SQL injection pattern detection
 * - Layer 4: Parameterized queries validation
 * - Layer 4: Different quotas for different operation costs
 * - Layer 4: Side effect enforcement
 * - Layer 4: Response size limits
 *
 * Tools:
 * - query-users: Safe user search with parameterized queries
 * - create-order: Insert orders with transaction support
 * - generate-report: Complex analytics queries
 * - health-check: Database connection status
 */

import 'dotenv/config';
import { SecureMcpServer } from 'mcp-security';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import {
  queryUsersSchema,
  queryUsers,
  type QueryUsersArgs,
  createOrderSchema,
  createOrder,
  type CreateOrderArgs,
  generateReportSchema,
  generateReport,
  type GenerateReportArgs,
  healthCheckSchema,
  healthCheck,
} from './tools/index.js';

// ============================================================================
// Configuration
// ============================================================================

const MAX_REPORT_SIZE = parseInt(process.env.MAX_REPORT_SIZE || '524288', 10); // 500KB

// ============================================================================
// Security Configuration
// ============================================================================

const server = new SecureMcpServer(
  {
    name: 'database-server',
    version: '1.0.0',
  },
  {
    // Logging configuration
    enableLogging: process.env.VERBOSE_LOGGING === 'true',
    verboseLogging: process.env.VERBOSE_LOGGING === 'true',

    // Tool registry with per-tool security policies
    toolRegistry: [
      {
        name: 'query-users',
        sideEffects: 'read',
        maxArgsSize: 512,
        maxEgressBytes: 50 * 1024, // 50KB for user list
        quotaPerMinute: 60,
        quotaPerHour: 1000,
      },
      {
        name: 'create-order',
        sideEffects: 'write',
        maxArgsSize: 10 * 1024, // 10KB for order data
        maxEgressBytes: 2 * 1024, // 2KB for response
        quotaPerMinute: 10,
        quotaPerHour: 200,
      },
      {
        name: 'generate-report',
        sideEffects: 'read',
        maxArgsSize: 256,
        maxEgressBytes: MAX_REPORT_SIZE,
        quotaPerMinute: 2, // Expensive operation
        quotaPerHour: 20,
      },
      {
        name: 'health-check',
        sideEffects: 'none',
        maxArgsSize: 64,
        maxEgressBytes: 1024,
        quotaPerMinute: 120, // No limit effectively
        quotaPerHour: 3600,
      },
    ],

    // SQL injection patterns are already in Layer 2 content validation
    // The framework will automatically detect and block:
    // - ' OR 1=1 --
    // - '; DROP TABLE users; --
    // - UNION SELECT
    // - etc.

    // Default policy
    defaultPolicy: {
      allowNetwork: false,
      allowWrites: false,
    },

    // Global rate limits
    maxRequestsPerMinute: 100,
    maxRequestsPerHour: 2000,
  }
);

// ============================================================================
// Tool Definitions
// ============================================================================

/**
 * Tool 1: query-users
 * Safe user search using parameterized queries
 * - All inputs are safely escaped via prepared statements
 * - Limited to 100 results max
 * - Side effect: 'read'
 */
server.tool(
  'query-users',
  'Search for users by name or email. Uses parameterized queries for SQL injection protection.',
  queryUsersSchema.shape,
  async (args: QueryUsersArgs) => queryUsers(args)
);

/**
 * Tool 2: create-order
 * Insert new orders with transaction support
 * - Validates user exists
 * - Validates total matches calculated amount
 * - Uses transaction for atomicity
 * - Side effect: 'write'
 * - Rate limited: 10/minute
 */
server.tool(
  'create-order',
  'Create a new order for a user. Validates user and total amount. Transaction-safe.',
  createOrderSchema.shape,
  async (args: CreateOrderArgs) => createOrder(args)
);

/**
 * Tool 3: generate-report
 * Complex analytics queries (expensive)
 * - Read-only queries
 * - Multiple grouping options
 * - Large response possible (500KB max)
 * - Side effect: 'read'
 * - Rate limited: 2/minute (expensive operation)
 */
server.tool(
  'generate-report',
  'Generate sales analytics report. Supports grouping by day, week, month, department, or status.',
  generateReportSchema.shape,
  async (args: GenerateReportArgs) => generateReport(args)
);

/**
 * Tool 4: health-check
 * Database connection verification
 * - No parameters required
 * - Returns connection status and statistics
 * - Side effect: 'none'
 * - No rate limiting
 */
server.tool(
  'health-check',
  'Check database connection status and get basic statistics.',
  healthCheckSchema.shape,
  async () => healthCheck()
);

// ============================================================================
// Server Startup
// ============================================================================

async function main() {
  console.error('Database MCP Server starting...');
  console.error('Security features enabled:');
  console.error('  - Layer 2: SQL injection detection');
  console.error('  - Layer 4: Per-tool quotas');
  console.error('  - Layer 4: Side effect enforcement');
  console.error('  - Layer 4: Response size limits');

  const transport = new StdioServerTransport();
  await server.connect(transport as Parameters<typeof server.connect>[0]);

  console.error('Database MCP Server running on stdio');
  console.error('Tools available: query-users, create-order, generate-report, health-check');
}

main().catch((error) => {
  console.error('Server failed to start:', error);
  process.exit(1);
});
