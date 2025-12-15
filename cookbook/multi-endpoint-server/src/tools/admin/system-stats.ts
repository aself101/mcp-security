import { z } from 'zod';

export const systemStatsSchema = z.object({
  verbose: z.boolean().optional().default(false).describe('Include detailed metrics')
});

export type SystemStatsArgs = z.infer<typeof systemStatsSchema>;

export async function systemStatsHandler(args: SystemStatsArgs) {
  const { verbose } = args;

  const memUsage = process.memoryUsage();
  const uptime = process.uptime();

  const basicStats = {
    uptime: formatUptime(uptime),
    uptimeSeconds: Math.floor(uptime),
    nodeVersion: process.version,
    platform: process.platform,
    timestamp: new Date().toISOString()
  };

  if (!verbose) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({ stats: basicStats }, null, 2)
      }]
    };
  }

  // Verbose mode includes detailed memory stats
  const detailedStats = {
    ...basicStats,
    memory: {
      heapUsed: formatBytes(memUsage.heapUsed),
      heapTotal: formatBytes(memUsage.heapTotal),
      external: formatBytes(memUsage.external),
      rss: formatBytes(memUsage.rss)
    },
    cpu: {
      cores: require('os').cpus().length,
      loadAvg: require('os').loadavg()
    },
    env: {
      nodeEnv: process.env.NODE_ENV || 'development',
      pid: process.pid
    }
  };

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({ stats: detailedStats }, null, 2)
    }]
  };
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);

  const parts = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  parts.push(`${secs}s`);

  return parts.join(' ');
}

function formatBytes(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let unitIndex = 0;

  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex++;
  }

  return `${value.toFixed(2)} ${units[unitIndex]}`;
}
