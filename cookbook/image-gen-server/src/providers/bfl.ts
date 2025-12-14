/**
 * Black Forest Labs (BFL) provider adapter
 * Supports FLUX models with async polling
 */

import { BflAPI } from 'bfl-api';
import type { ImageProvider, GenerateOptions, GenerateResult, ProviderName } from './index.js';

const MODELS = [
  'flux-dev',
  'flux-pro',
  'flux-pro-ultra'
];

export class BflProvider implements ImageProvider {
  name: ProviderName = 'bfl';
  private api: BflAPI;

  constructor() {
    this.api = new BflAPI();
  }

  async generate(options: GenerateOptions): Promise<GenerateResult> {
    const model = options.model || 'flux-pro';
    const params: any = {
      prompt: options.prompt,
      width: options.width,
      height: options.height,
      aspect_ratio: options.aspectRatio
    };

    let task: any;

    switch (model) {
      case 'flux-dev':
        task = await this.api.generateFluxDev(params);
        break;
      case 'flux-pro':
        task = await this.api.generateFluxPro(params);
        break;
      case 'flux-pro-ultra':
        task = await this.api.generateFluxProUltra(params);
        break;
      default:
        task = await this.api.generateFluxPro(params);
    }

    // BFL API is async - need to poll for result
    const result = await this.api.waitForResult(task.id, {
      pollingUrl: task.polling_url,
      showSpinner: false
    });

    // Extract image URL from result
    const images = result?.result?.sample ? [result.result.sample] : [];

    return {
      images,
      model,
      provider: this.name
    };
  }

  listModels(): string[] {
    return MODELS;
  }
}
