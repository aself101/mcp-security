# Advanced Configuration

This document covers advanced configuration options for the Image Generation MCP server.

## Provider-Specific Features

### BFL (Flux) Models

```typescript
// Flux Pro - highest quality
{
  provider: 'bfl',
  model: 'flux-pro',
  prompt: 'Detailed illustration'
}

// Flux Dev - faster, good quality
{
  provider: 'bfl',
  model: 'flux-dev',
  prompt: 'Quick concept art'
}
```

### Google Imagen

```typescript
// Imagen 3 - photorealistic
{
  provider: 'google',
  model: 'imagen-3',
  prompt: 'Photorealistic landscape',
  aspectRatio: '16:9'
}
```

### Ideogram

```typescript
// V2 Turbo - fast generation
{
  provider: 'ideogram',
  model: 'V_2_TURBO',
  prompt: 'Quick design concept'
}

// V2 - higher quality
{
  provider: 'ideogram',
  model: 'V_2',
  prompt: 'Detailed artwork',
  style: 'DESIGN'
}
```

### OpenAI DALL-E

```typescript
// DALL-E 3 - best quality, auto-enhances prompts
{
  provider: 'openai',
  model: 'dall-e-3',
  prompt: 'A serene lake',
  style: 'natural'  // or 'vivid'
}

// DALL-E 2 - supports variations and edit
{
  provider: 'openai',
  model: 'dall-e-2',
  prompt: 'Abstract art'
}
```

### Stability AI

```typescript
// SD3 Large - highest quality
{
  provider: 'stability',
  model: 'sd3-large',
  prompt: 'Detailed scene',
  negativePrompt: 'blurry, low quality'
}

// SD3 Medium - balanced
{
  provider: 'stability',
  model: 'sd3-medium',
  prompt: 'Quick generation'
}
```

## Using Negative Prompts

Negative prompts help avoid unwanted elements:

```json
{
  "provider": "stability",
  "prompt": "Professional headshot portrait",
  "negativePrompt": "cartoon, anime, drawing, painting, blurry, deformed, ugly, duplicate"
}
```

## Style Presets

### OpenAI Styles

| Style | Description |
|-------|-------------|
| `natural` | More natural, less stylized |
| `vivid` | Hyper-real, dramatic |

### Ideogram Styles

| Style | Description |
|-------|-------------|
| `AUTO` | Automatic selection |
| `GENERAL` | General purpose |
| `REALISTIC` | Photorealistic |
| `DESIGN` | Graphic design |
| `RENDER_3D` | 3D rendered look |
| `ANIME` | Anime style |

## Rate Limit Management

For high-volume usage:

```typescript
const server = new SecureMcpServer({
  name: 'image-gen-server',
  version: '1.0.0',
}, {
  maxRequestsPerMinute: 100,
  maxRequestsPerHour: 1000,
  toolRegistry: [
    // Per-tool limits for expensive operations
    { name: 'generate-image', quotaPerMinute: 50 },
    { name: 'upscale-image', quotaPerMinute: 20 },
    { name: 'edit-image', quotaPerMinute: 20 },
  ],
});
```

## Handling Large Images

For base64-encoded images:

```typescript
toolRegistry: [
  { name: 'edit-image', sideEffects: 'network', maxArgsSize: 10000 },
  { name: 'upscale-image', sideEffects: 'network', maxArgsSize: 10000 },
]
```

## Error Handling

Common error responses:

```json
{
  "error": "Content policy violation",
  "message": "The prompt was rejected by the provider's content moderation"
}
```

```json
{
  "error": "Provider unavailable",
  "message": "BFL API is currently unavailable. Try another provider."
}
```

```json
{
  "error": "Invalid image format",
  "message": "Image must be PNG or JPEG format"
}
```

## Cost Optimization

Different providers have different pricing:

| Provider | Relative Cost | Best For |
|----------|--------------|----------|
| BFL | Medium | High-quality art |
| Google | Medium | Photorealism |
| Ideogram | Low | Text in images |
| OpenAI | High | Prompt understanding |
| Stability | Low-Medium | Volume generation |

## Multi-Provider Fallback

Implement fallback logic:

```typescript
async function generateWithFallback(prompt: string) {
  const providers = ['openai', 'stability', 'ideogram'];

  for (const provider of providers) {
    try {
      return await generateImage({ provider, prompt });
    } catch (error) {
      console.error(`${provider} failed, trying next...`);
    }
  }

  throw new Error('All providers failed');
}
```
