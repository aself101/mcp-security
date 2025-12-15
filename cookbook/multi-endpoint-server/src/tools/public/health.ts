import { z } from 'zod';

export const healthSchema = z.object({
  // No parameters - simple health check
});

export type HealthArgs = z.infer<typeof healthSchema>;

export async function healthHandler(_args: HealthArgs) {
  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        status: 'healthy',
        timestamp: new Date().toISOString()
      }, null, 2)
    }]
  };
}
