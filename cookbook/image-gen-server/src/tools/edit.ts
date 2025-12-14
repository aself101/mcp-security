/**
 * Image editing tools - edit, replace background
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

export const editImageSchema = z.object({
  provider: z.enum(['ideogram', 'openai', 'stability']),
  image: z.string().describe('Image URL or base64 data'),
  prompt: z.string().max(2000).describe('Description of the edit to make'),
  mask: z.string().optional().describe('Mask image URL or base64 (white = edit area)')
});

export type EditImageArgs = z.infer<typeof editImageSchema>;

export async function editImage(args: EditImageArgs) {
  const provider = getProvider(args.provider as ProviderName);

  if (!provider.edit) {
    throw new Error(`Provider ${args.provider} does not support image editing`);
  }

  const result = await provider.edit({
    image: args.image,
    prompt: args.prompt,
    mask: args.mask
  });

  return buildImageResponse(result);
}

export const removeBackgroundSchema = z.object({
  image: z.string().describe('Image URL or base64 data')
});

export type RemoveBackgroundArgs = z.infer<typeof removeBackgroundSchema>;

export async function removeBackground(args: RemoveBackgroundArgs) {
  const provider = getProvider('stability');

  if (!provider.removeBackground) {
    throw new Error('Remove background not supported');
  }

  const result = await provider.removeBackground(args.image);
  return buildImageResponse(result);
}

export const replaceBackgroundSchema = z.object({
  provider: z.enum(['ideogram', 'stability']),
  image: z.string().describe('Image URL or base64 data'),
  prompt: z.string().max(2000).describe('Description of the new background')
});

export type ReplaceBackgroundArgs = z.infer<typeof replaceBackgroundSchema>;

export async function replaceBackground(args: ReplaceBackgroundArgs) {
  const provider = getProvider(args.provider as ProviderName);

  if (!provider.replaceBackground) {
    throw new Error(`Provider ${args.provider} does not support background replacement`);
  }

  const result = await provider.replaceBackground(args.image, args.prompt);
  return buildImageResponse(result);
}
