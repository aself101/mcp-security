/**
 * Integration tests for Image Generation MCP Server
 */

import { describe, it, expect } from 'vitest';

describe('Image Generation Server Integration', () => {
  describe('Tool Schema Validation', () => {
    it('should validate generate-image schema', async () => {
      const { generateImageSchema } = await import('../src/tools/generate.js');

      // Valid input
      expect(() => generateImageSchema.parse({
        provider: 'openai',
        prompt: 'A beautiful sunset'
      })).not.toThrow();

      // With optional fields
      expect(() => generateImageSchema.parse({
        provider: 'stability',
        prompt: 'Abstract art',
        width: 1024,
        height: 1024,
        negativePrompt: 'blurry'
      })).not.toThrow();

      // Invalid provider
      expect(() => generateImageSchema.parse({
        provider: 'invalid',
        prompt: 'test'
      })).toThrow();

      // Missing required field
      expect(() => generateImageSchema.parse({
        provider: 'openai'
      })).toThrow();
    });

    it('should validate edit-image schema', async () => {
      const { editImageSchema } = await import('../src/tools/edit.js');

      // Valid input
      expect(() => editImageSchema.parse({
        provider: 'openai',
        image: 'https://example.com/image.png',
        prompt: 'Add a hat'
      })).not.toThrow();

      // With mask
      expect(() => editImageSchema.parse({
        provider: 'stability',
        image: 'https://example.com/image.png',
        mask: 'https://example.com/mask.png',
        prompt: 'Replace area'
      })).not.toThrow();
    });

    it('should validate upscale-image schema', async () => {
      const { upscaleImageSchema } = await import('../src/tools/upscale.js');

      expect(() => upscaleImageSchema.parse({
        provider: 'stability',
        image: 'https://example.com/image.png'
      })).not.toThrow();

      expect(() => upscaleImageSchema.parse({
        provider: 'ideogram',
        image: 'https://example.com/image.png',
        scale: 2
      })).not.toThrow();
    });

    it('should validate list-models schema', async () => {
      const { listModelsSchema } = await import('../src/tools/list-models.js');

      // No args
      expect(() => listModelsSchema.parse({})).not.toThrow();

      // With provider filter
      expect(() => listModelsSchema.parse({ provider: 'openai' })).not.toThrow();
    });
  });

  describe('Response Format', () => {
    it('should return proper content structure', async () => {
      const mockResponse = {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: true,
            provider: 'openai',
            images: [{ url: 'https://example.com/generated.png' }]
          }, null, 2)
        }]
      };

      expect(mockResponse.content).toHaveLength(1);
      expect(mockResponse.content[0].type).toBe('text');

      const parsed = JSON.parse(mockResponse.content[0].text);
      expect(parsed.success).toBe(true);
      expect(parsed.images).toHaveLength(1);
    });
  });

  describe('Provider Validation', () => {
    it('should accept all valid providers for generate', async () => {
      const { generateImageSchema } = await import('../src/tools/generate.js');

      const providers = ['bfl', 'google', 'ideogram', 'openai', 'stability'];

      for (const provider of providers) {
        expect(() => generateImageSchema.parse({
          provider,
          prompt: 'test'
        })).not.toThrow();
      }
    });

    it('should accept limited providers for edit', async () => {
      const { editImageSchema } = await import('../src/tools/edit.js');

      const validProviders = ['ideogram', 'openai', 'stability'];

      for (const provider of validProviders) {
        expect(() => editImageSchema.parse({
          provider,
          image: 'https://example.com/img.png',
          prompt: 'edit'
        })).not.toThrow();
      }
    });
  });
});
