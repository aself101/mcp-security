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
  private api: BflAPI | null = null;

  private getApi(): BflAPI {
    if (!this.api) {
      if (!process.env.BFL_API_KEY) {
        throw new Error(
          'BFL API key required. Set BFL_API_KEY environment variable. ' +
          'Get your API key at https://api.bfl.ml'
        );
      }
      this.api = new BflAPI();
    }
    return this.api;
  }

  async generate(options: GenerateOptions): Promise<GenerateResult> {
    const model = options.model || 'flux-pro';
    const params: any = {
      prompt: options.prompt,
      width: options.width,
      height: options.height,
      aspect_ratio: options.aspectRatio
    };

    const api = this.getApi();
    let task: any;

    switch (model) {
      case 'flux-dev':
        task = await api.generateFluxDev(params);
        break;
      case 'flux-pro':
        task = await api.generateFluxPro(params);
        break;
      case 'flux-pro-ultra':
        task = await api.generateFluxProUltra(params);
        break;
      default:
        task = await api.generateFluxPro(params);
    }

    // BFL API is async - need to poll for result
    const result = await api.waitForResult(task.id, {
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
