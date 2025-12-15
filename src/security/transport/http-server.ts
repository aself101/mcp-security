/**
 * HTTP server with security validation for MCP requests.
 * Uses node:http directly for zero external dependencies.
 */

import { createServer, IncomingMessage, ServerResponse, Server } from 'node:http';
import type { ValidationPipeline, PipelineContext } from '../utils/validation-pipeline.js';
import type { ErrorSanitizer } from '../utils/error-sanitizer.js';
import type { SecurityLogger } from '../utils/security-logger.js';
import { isSeverity, isViolationType } from '../../types/index.js';
import type { Severity, ViolationType } from '../../types/index.js';

/** Options for createSecureHttpHandler (no routing) */
export interface HttpHandlerOptions {
  /** Maximum request body size in bytes (default: 51200 = 50KB) */
  maxBodySize?: number;
}

/** Options for createSecureHttpServer (includes routing) */
export interface HttpServerOptions extends HttpHandlerOptions {
  /** MCP endpoint path (default: '/mcp') */
  endpoint?: string;
}

/** Request handler function type */
export type SecureHttpHandler = (req: IncomingMessage, res: ServerResponse) => Promise<void>;

/** Internal interface for accessing SecureMcpServer internals */
interface SecureMcpServerInternal {
  validationPipeline: ValidationPipeline;
  _errorSanitizer: ErrorSanitizer;
  _securityLogger: SecurityLogger | null;
  mcpServer: {
    connect(transport: unknown): Promise<void>;
  };
}

/**
 * Creates an HTTP request handler with security validation.
 * Use this for composing multiple MCP endpoints on a single server.
 *
 * @param secureMcpServer - SecureMcpServer instance
 * @param options - Handler configuration options
 * @returns Request handler function (req, res) => Promise<void>
 *
 * @example
 * ```typescript
 * import { SecureMcpServer, createSecureHttpHandler } from 'mcp-security';
 * import { createServer } from 'node:http';
 *
 * const adminServer = new SecureMcpServer({ name: 'admin', version: '1.0' });
 * const publicServer = new SecureMcpServer({ name: 'public', version: '1.0' });
 *
 * const adminHandler = createSecureHttpHandler(adminServer);
 * const publicHandler = createSecureHttpHandler(publicServer);
 *
 * const httpServer = createServer(async (req, res) => {
 *   if (req.url?.startsWith('/api/admin')) return adminHandler(req, res);
 *   if (req.url?.startsWith('/api/public')) return publicHandler(req, res);
 *   res.writeHead(404).end();
 * });
 * ```
 */
export function createSecureHttpHandler(
  secureMcpServer: SecureMcpServerInternal,
  options: HttpHandlerOptions = {}
): SecureHttpHandler {
  const { maxBodySize = 51200 } = options;

  const pipeline = secureMcpServer.validationPipeline;
  const errorSanitizer = secureMcpServer._errorSanitizer;
  const logger = secureMcpServer._securityLogger;

  let transport: { handleRequest(req: IncomingMessage, res: ServerResponse, body?: unknown): Promise<void> } | null = null;
  let connected = false;

  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    // MCP uses POST for JSON-RPC requests
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json', 'Allow': 'POST' });
      res.end(JSON.stringify({ error: 'Method not allowed' }));
      return;
    }

    let body: unknown;
    try {
      body = await parseJsonBody(req, maxBodySize);
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err instanceof Error ? err.message : 'Invalid request' }));
      return;
    }

    const sessionId = (req.headers['mcp-session-id'] as string) || 'stateless';

    const context: PipelineContext = {
      timestamp: Date.now(),
      sessionId,
      transportLevel: true,
      httpRequest: true
    };

    const result = await pipeline.validate(body as Record<string, unknown>, context);

    if (logger) {
      logger.logSecurityDecision(result, body as Record<string, unknown>, 'HTTP-Transport');
    }

    if (!result.passed) {
      const requestId = (body as { id?: string | number | null })?.id ?? null;
      const severity: Severity = isSeverity(result.severity) ? result.severity : 'HIGH';
      const violationType: ViolationType = isViolationType(result.violationType)
        ? result.violationType
        : 'POLICY_VIOLATION';

      const errorResponse = errorSanitizer.createSanitizedErrorResponse(
        requestId,
        result.reason ?? 'Request blocked by security policy',
        severity,
        violationType
      );
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(errorResponse));
      return;
    }

    if (!transport) {
      const { StreamableHTTPServerTransport } = await import(
        '@modelcontextprotocol/sdk/server/streamableHttp.js'
      );
      transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    }

    if (!connected) {
      await secureMcpServer.mcpServer.connect(transport);
      connected = true;
    }

    await transport.handleRequest(req, res, body);
  };
}

/**
 * Creates a standalone HTTP server with security validation.
 * Zero external dependencies - uses node:http directly.
 *
 * @param secureMcpServer - SecureMcpServer instance
 * @param options - Server configuration options
 * @returns Node.js HTTP server (call .listen() to start)
 *
 * @example
 * ```typescript
 * const httpServer = createSecureHttpServer(server, { endpoint: '/mcp' });
 * httpServer.listen(3000, () => {
 *   console.log('MCP server listening on http://localhost:3000/mcp');
 * });
 * ```
 */
export function createSecureHttpServer(
  secureMcpServer: SecureMcpServerInternal,
  options: HttpServerOptions = {}
): Server {
  const { endpoint = '/mcp', ...handlerOptions } = options;
  const handler = createSecureHttpHandler(secureMcpServer, handlerOptions);

  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (req.url !== endpoint) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
      return;
    }

    await handler(req, res);
  });
}

async function parseJsonBody(req: IncomingMessage, maxSize: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;

    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxSize) {
        req.destroy();
        reject(new Error(`Body exceeds ${maxSize} bytes`));
        return;
      }
      data += chunk.toString();
    });

    req.on('end', () => {
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', reject);
  });
}
