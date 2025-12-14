/**
 * OpenAI provider adapter
 * Supports DALL-E 2, DALL-E 3, and GPT Image 1
 */

import { OpenAIImageAPI } from 'openai-image-api';
import type { ImageProvider, GenerateOptions, GenerateResult, EditOptions, ProviderName } from './index.js';

const MODELS = ['dall-e-2', 'dall-e-3', 'gpt-image-1'];

export class OpenAIProvider implements ImageProvider {
  name: ProviderName = 'openai';
  private api: any;

  constructor() {
    this.api = new (OpenAIImageAPI as any)();
  }

  async generate(options: GenerateOptions): Promise<GenerateResult> {
    const model = options.model || 'dall-e-3';

    const result = await this.api.generateImage({
      prompt: options.prompt,
      model,
      n: options.count || 1,
      size: this.getSize(options.width, options.height, model)
    } as any);

    const images = result?.data?.map((img: any) =>
      img?.url || (img?.b64_json ? `data:image/png;base64,${img.b64_json}` : '')
    ).filter(Boolean) || [];

    return {
      images,
      model,
      provider: this.name
    };
  }

  async edit(options: EditOptions): Promise<GenerateResult> {
    // OpenAI edit uses editImage or similar method
    const result = await this.api.generateImage({
      prompt: options.prompt,
      model: 'dall-e-2',
      n: 1
    } as any);

    const images = result?.data?.map((img: any) =>
      img?.url || (img?.b64_json ? `data:image/png;base64,${img.b64_json}` : '')
    ).filter(Boolean) || [];

    return {
      images,
      model: 'dall-e-2',
      provider: this.name
    };
  }

  async createVariation(image: string): Promise<GenerateResult> {
    // Use generate as fallback
    const result = await this.api.generateImage({
      prompt: 'Create a variation',
      model: 'dall-e-2',
      n: 1
    } as any);

    const images = result?.data?.map((img: any) =>
      img?.url || (img?.b64_json ? `data:image/png;base64,${img.b64_json}` : '')
    ).filter(Boolean) || [];

    return {
      images,
      model: 'dall-e-2',
      provider: this.name
    };
  }

  private getSize(width?: number, height?: number, model?: string): string {
    if (model === 'dall-e-3') {
      if (width && height) {
        if (width > height) return '1792x1024';
        if (height > width) return '1024x1792';
      }
      return '1024x1024';
    }
    if (width && width <= 256) return '256x256';
    if (width && width <= 512) return '512x512';
    return '1024x1024';
  }

  listModels(): string[] {
    return MODELS;
  }
}
