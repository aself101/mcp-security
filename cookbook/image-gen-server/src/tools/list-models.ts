/**
 * List models and describe image tools
 */

import { z } from 'zod';
import { listAllModels, getProvider, type ProviderName } from '../providers/index.js';

export const listModelsSchema = z.object({
  provider: z.enum(['bfl', 'google', 'ideogram', 'openai', 'stability']).optional()
    .describe('Filter by provider (omit for all providers)')
});

export type ListModelsArgs = z.infer<typeof listModelsSchema>;

export async function listModels(args: ListModelsArgs) {
  let models: Record<string, string[]>;

  if (args.provider) {
    const provider = getProvider(args.provider as ProviderName);
    models = { [args.provider]: provider.listModels() };
  } else {
    models = listAllModels();
  }

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        models
      }, null, 2)
    }]
  };
}

export const describeImageSchema = z.object({
  image: z.string().describe('Image URL or base64 data')
});

export type DescribeImageArgs = z.infer<typeof describeImageSchema>;

export async function describeImage(args: DescribeImageArgs) {
  const provider = getProvider('ideogram');

  if (!provider.describe) {
    throw new Error('Describe image not supported');
  }

  const description = await provider.describe(args.image);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        provider: 'ideogram',
        description
      }, null, 2)
    }]
  };
}
