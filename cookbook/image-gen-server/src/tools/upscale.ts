/**
 * Image upscaling and variation tools
 */

import { z } from 'zod';
import { getProvider, type ProviderName, type GenerateResult } from '../providers/index.js';

type ContentBlock = { type: 'text'; text: string } | { type: 'image'; data: string; mimeType: string };

function buildImageResponse(result: GenerateResult): { content: ContentBlock[] } {
  const content: ContentBlock[] = [
    {
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        provider: result.provider,
        model: result.model,
        imageCount: result.images.length
      }, null, 2)
    }
  ];

  for (const img of result.images) {
    const base64Data = img.startsWith('data:')
      ? img.replace(/^data:image\/\w+;base64,/, '')
      : img;
    content.push({ type: 'image' as const, data: base64Data, mimeType: 'image/png' });
  }

  return { content };
}

export const upscaleImageSchema = z.object({
  provider: z.enum(['ideogram', 'stability']),
  image: z.string().describe('Image URL or base64 data'),
  scale: z.number().optional().describe('Upscale factor (provider-specific)')
});

export type UpscaleImageArgs = z.infer<typeof upscaleImageSchema>;

export async function upscaleImage(args: UpscaleImageArgs) {
  try {
    const provider = getProvider(args.provider as ProviderName);

    if (!provider.upscale) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            error: `Provider "${args.provider}" does not support upscaling. ` +
              `Try: ideogram or stability instead.`
          }, null, 2)
        }],
        isError: true
      };
    }

    const result = await provider.upscale({
      image: args.image,
      scale: args.scale
    });

    return buildImageResponse(result);
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to upscale image'
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const createVariationSchema = z.object({
  image: z.string().describe('Image URL or base64 data')
});

export type CreateVariationArgs = z.infer<typeof createVariationSchema>;

export async function createVariation(args: CreateVariationArgs) {
  try {
    const provider = getProvider('openai');

    if (!provider.createVariation) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            error: 'Create variation is only supported by OpenAI (DALL-E 2).'
          }, null, 2)
        }],
        isError: true
      };
    }

    const result = await provider.createVariation(args.image);
    return buildImageResponse(result);
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to create variation'
        }, null, 2)
      }],
      isError: true
    };
  }
}
