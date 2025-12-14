/**
 * Google Generative AI provider adapter
 * Supports Gemini and Imagen models
 */

import { GoogleGenAIAPI } from 'google-genai-api';
import type { ImageProvider, GenerateOptions, GenerateResult, ProviderName } from './index.js';

const MODELS = [
  'gemini-2.5-flash-image',
  'imagen-4'
];

export class GoogleProvider implements ImageProvider {
  name: ProviderName = 'google';
  private api: any;

  constructor() {
    const apiKey = process.env.GOOGLE_GENAI_API_KEY;
    if (!apiKey) {
      throw new Error('API key is required. Please provide GOOGLE_GENAI_API_KEY.');
    }
    this.api = new (GoogleGenAIAPI as any)(apiKey);
  }

  async generate(options: GenerateOptions): Promise<GenerateResult> {
    const model = options.model || 'imagen-4';
    const isImagen = model.startsWith('imagen');

    let images: string[] = [];

    try {
      if (isImagen) {
        const result = await this.api.generateWithImagen({
          prompt: options.prompt,
          numberOfImages: options.count || 1,
          aspectRatio: options.aspectRatio as any
        });
        images = result?.generatedImages?.map((img: any) =>
          img?.image?.imageBytes ? `data:image/png;base64,${img.image.imageBytes}` : ''
        ).filter(Boolean) || [];
      } else {
        const result = await this.api.generateWithGemini({
          prompt: options.prompt,
          model: model as any
        });
        if (result?.candidates?.[0]?.content?.parts) {
          for (const part of result.candidates[0].content.parts) {
            if (part.inlineData?.data) {
              images.push(`data:${part.inlineData.mimeType};base64,${part.inlineData.data}`);
            }
          }
        }
      }
    } catch (error: any) {
      throw new Error(`Google API error: ${error?.message || 'Unknown error'}`);
    }

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
