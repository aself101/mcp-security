/**
 * Debug Image Generation MCP Server
 * Logs all incoming messages to stderr for comparison
 */

import 'dotenv/config';
import { SecureMcpServer } from 'mcp-security';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import * as fs from 'fs';
import * as path from 'path';

import { generateImageSchema, generateImage } from './tools/generate.js';
import { listModelsSchema, listModels } from './tools/list-models.js';

// Log to file for comparison - use absolute path
const logFile = '/tmp/mcp-debug.log';
function debugLog(label: string, data: unknown) {
  const entry = `[${new Date().toISOString()}] ${label}: ${JSON.stringify(data, null, 2)}\n`;
  try {
    fs.appendFileSync(logFile, entry);
  } catch (e) {
    // Ignore write errors
  }
  console.error(`[DEBUG] ${label}:`, JSON.stringify(data));
}

// Clear log file
try {
  fs.writeFileSync(logFile, '');
} catch (e) {
  // Ignore write errors
}
debugLog('SERVER_START', { pid: process.pid, cwd: process.cwd() });

const server = new SecureMcpServer(
  {
    name: 'image-gen-debug',
    version: '1.0.0'
  },
  {
    enableLogging: true,
    verboseLogging: true,
    toolRegistry: [
      { name: 'generate-image', sideEffects: 'network', maxArgsSize: 5000 },
      { name: 'list-models', sideEffects: 'none', maxArgsSize: 500 }
    ],
    defaultPolicy: {
      allowNetwork: true,
      allowWrites: false
    },
    maxRequestsPerMinute: 100,
    maxRequestsPerHour: 1000
  }
);

// Generate image
server.tool(
  'generate-image',
  'Generate images from text prompts',
  generateImageSchema.shape,
  async (args) => {
    debugLog('TOOL_CALL_generate-image', args);
    return generateImage(args);
  }
);

// List models
server.tool(
  'list-models',
  'List available models',
  listModelsSchema.shape,
  async (args) => {
    debugLog('TOOL_CALL_list-models', args);
    return listModels(args);
  }
);

// Create a logging wrapper for the transport
class LoggingTransport {
  private inner: StdioServerTransport;

  constructor() {
    this.inner = new StdioServerTransport();
  }

  set onmessage(handler: ((message: unknown, extra?: unknown) => void) | null) {
    this.inner.onmessage = handler ? (message: unknown, extra?: unknown) => {
      debugLog('INCOMING_MESSAGE', { message, extra });
      handler(message, extra);
    } : null;
  }

  get onmessage() {
    return this.inner.onmessage;
  }

  set onerror(handler: ((error: Error) => void) | null) {
    this.inner.onerror = handler ? (error: Error) => {
      debugLog('TRANSPORT_ERROR', { error: error.message });
      handler(error);
    } : null;
  }

  get onerror() {
    return this.inner.onerror;
  }

  set onclose(handler: (() => void) | null) {
    this.inner.onclose = handler ? () => {
      debugLog('TRANSPORT_CLOSE', {});
      handler();
    } : null;
  }

  get onclose() {
    return this.inner.onclose;
  }

  async start() {
    debugLog('TRANSPORT_START', {});
    return this.inner.start();
  }

  async close() {
    debugLog('TRANSPORT_CLOSE_CALLED', {});
    return this.inner.close();
  }

  async send(message: unknown) {
    debugLog('OUTGOING_MESSAGE', { message });
    return this.inner.send(message as any);
  }

  get sessionId() {
    return (this.inner as any).sessionId;
  }
}

async function main() {
  const transport = new LoggingTransport();

  await server.connect(transport as any);
  debugLog('SERVER_CONNECTED', {});
  console.error('Debug Image Gen MCP Server running - logging to', logFile);
}

main().catch((err) => {
  debugLog('SERVER_ERROR', { error: err.message, stack: err.stack });
  console.error(err);
});
