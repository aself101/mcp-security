import { z } from 'zod';

export const statusSchema = z.object({
  // No parameters - simple status check
});

export type StatusArgs = z.infer<typeof statusSchema>;

export async function statusHandler(_args: StatusArgs) {
  const uptime = process.uptime();

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        service: 'multi-endpoint-server',
        version: '1.0.0',
        status: 'running',
        uptime: `${Math.floor(uptime)}s`,
        endpoints: {
          admin: '/api/admin',
          public: '/api/public'
        },
        timestamp: new Date().toISOString()
      }, null, 2)
    }]
  };
}
