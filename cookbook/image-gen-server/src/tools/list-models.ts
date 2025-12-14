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
  try {
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
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to list models'
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const describeImageSchema = z.object({
  image: z.string().describe('Image URL or base64 data')
});

export type DescribeImageArgs = z.infer<typeof describeImageSchema>;

export async function describeImage(args: DescribeImageArgs) {
  try {
    const provider = getProvider('ideogram');

    if (!provider.describe) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            error: 'Describe image is only supported by Ideogram.'
          }, null, 2)
        }],
        isError: true
      };
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
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to describe image'
        }, null, 2)
      }],
      isError: true
    };
  }
}
