/**
 * Stability AI provider adapter
 * Supports Stable Diffusion, SDXL, and various editing operations
 */

import { StabilityAPI } from 'stability-ai-api';
import type { ImageProvider, GenerateOptions, GenerateResult, EditOptions, UpscaleOptions, ProviderName } from './index.js';

const MODELS = [
  'stable-image-ultra',
  'stable-image-core',
  'sd3-large'
];

export class StabilityProvider implements ImageProvider {
  name: ProviderName = 'stability';
  private api: any;

  constructor() {
    const apiKey = process.env.STABILITY_API_KEY;
    if (!apiKey) {
      throw new Error('API key is required. Please provide STABILITY_API_KEY.');
    }
    this.api = new (StabilityAPI as any)(apiKey);
  }

  async generate(options: GenerateOptions): Promise<GenerateResult> {
    const model = options.model || 'stable-image-ultra';

    const params: any = {
      prompt: options.prompt,
      negative_prompt: options.negativePrompt,
      aspect_ratio: options.aspectRatio
    };

    let result: any;

    switch (model) {
      case 'stable-image-ultra':
        result = await this.api.generateUltra(params);
        break;
      case 'stable-image-core':
        result = await this.api.generateCore(params);
        break;
      case 'sd3-large':
        result = await this.api.generateSD3({ ...params, model: 'sd3-large' });
        break;
      default:
        result = await this.api.generateUltra(params);
    }

    const images = this.extractImages(result);

    return {
      images,
      model,
      provider: this.name
    };
  }

  async edit(options: EditOptions): Promise<GenerateResult> {
    const result = await this.api.inpaint(options.image, options.prompt, {
      mask: options.mask
    } as any);

    return {
      images: this.extractImages(result),
      model: 'stable-image-core',
      provider: this.name
    };
  }

  async upscale(options: UpscaleOptions): Promise<GenerateResult> {
    const result = await this.api.upscaleFast(options.image);

    return {
      images: this.extractImages(result),
      model: 'upscale-fast',
      provider: this.name
    };
  }

  async removeBackground(image: string): Promise<GenerateResult> {
    const result = await this.api.removeBackground(image);

    return {
      images: this.extractImages(result),
      model: 'remove-background',
      provider: this.name
    };
  }

  async replaceBackground(image: string, prompt: string): Promise<GenerateResult> {
    const result = await this.api.replaceBackgroundAndRelight(image, {
      background_prompt: prompt
    } as any);

    return {
      images: this.extractImages(result),
      model: 'replace-background',
      provider: this.name
    };
  }

  private extractImages(result: any): string[] {
    if (result?.images) {
      return result.images.map((img: any) =>
        Buffer.isBuffer(img) ? `data:image/png;base64,${img.toString('base64')}` : String(img)
      );
    }
    if (result?.image) {
      const img = result.image;
      return [Buffer.isBuffer(img) ? `data:image/png;base64,${img.toString('base64')}` : String(img)];
    }
    return [];
  }

  listModels(): string[] {
    return MODELS;
  }
}
