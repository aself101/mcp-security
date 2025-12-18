/**
 * Multi-Endpoint MCP Server Example
 *
 * Demonstrates using createSecureHttpHandler to compose multiple MCP servers
 * with different tools and security policies on separate endpoints.
 *
 * - /api/admin - Admin API with user management and system stats
 * - /api/public - Public API with health and status checks
 */

import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { createSecureHttpHandler, SecureHttpHandler } from 'mcp-secure-server';
import { createAdminServer, registerAdminTools } from './servers/admin-server.js';
import { createPublicServer, registerPublicTools } from './servers/public-server.js';

// Create separate MCP servers with different configurations
const adminServer = createAdminServer();
const publicServer = createPublicServer();

// Register tools on each server
registerAdminTools(adminServer);
registerPublicTools(publicServer);

// Create HTTP handlers for each server
// Note: Type assertion needed because createSecureHttpHandler accesses internal properties
const adminHandler: SecureHttpHandler = createSecureHttpHandler(
  adminServer as unknown as Parameters<typeof createSecureHttpHandler>[0]
);

const publicHandler: SecureHttpHandler = createSecureHttpHandler(
  publicServer as unknown as Parameters<typeof createSecureHttpHandler>[0]
);

// Compose handlers with custom routing
const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  // CORS headers for browser clients
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Mcp-Session-Id');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Route to appropriate handler
  if (req.url?.startsWith('/api/admin')) {
    return adminHandler(req, res);
  }

  if (req.url?.startsWith('/api/public')) {
    return publicHandler(req, res);
  }

  // Not found - return helpful error
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    error: 'Not found',
    message: 'Use one of the available endpoints',
    endpoints: {
      admin: '/api/admin',
      public: '/api/public'
    }
  }));
});

const PORT = parseInt(process.env.PORT || '3000', 10);

httpServer.listen(PORT, () => {
  console.log(`Multi-Endpoint MCP Server listening on http://localhost:${PORT}`);
  console.log('');
  console.log('Available endpoints:');
  console.log(`  Admin API:  http://localhost:${PORT}/api/admin`);
  console.log('    - list-users: List all users (admin only)');
  console.log('    - system-stats: Get system metrics');
  console.log('');
  console.log(`  Public API: http://localhost:${PORT}/api/public`);
  console.log('    - health: Health check');
  console.log('    - status: Service status');
  console.log('');
  console.log('Test with curl:');
  console.log(`  # Admin API - list users`);
  console.log(`  curl -X POST http://localhost:${PORT}/api/admin \\`);
  console.log('    -H "Content-Type: application/json" \\');
  console.log('    -H "Accept: application/json, text/event-stream" \\');
  console.log('    -d \'{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"list-users","arguments":{}}}\'');
  console.log('');
  console.log(`  # Public API - health check`);
  console.log(`  curl -X POST http://localhost:${PORT}/api/public \\`);
  console.log('    -H "Content-Type: application/json" \\');
  console.log('    -H "Accept: application/json, text/event-stream" \\');
  console.log('    -d \'{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"health","arguments":{}}}\'');
});
