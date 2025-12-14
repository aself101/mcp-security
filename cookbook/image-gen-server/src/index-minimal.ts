/**
 * Minimal Image Generation MCP Server (no security framework)
 * For debugging MCP connection issues
 */

import 'dotenv/config';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { generateImageSchema, generateImage } from './tools/generate.js';
import { listModelsSchema, listModels } from './tools/list-models.js';

const server = new McpServer({
  name: 'image-gen-server-minimal',
  version: '1.0.0'
});

// Generate image
server.tool(
  'generate-image',
  'Generate images from text prompts',
  generateImageSchema.shape,
  async (args) => generateImage(args)
);

// List models
server.tool(
  'list-models',
  'List available models',
  listModelsSchema.shape,
  async (args) => listModels(args)
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Minimal Image Gen MCP Server running');
}

main().catch(console.error);
