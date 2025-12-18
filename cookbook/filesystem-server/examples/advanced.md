# Advanced Configuration Examples

This document covers advanced configuration patterns for production deployments.

## Custom Resource Policies

### Multi-tenant file isolation

```typescript
import { SecureMcpServer } from 'mcp-secure-server';

const tenantId = process.env.TENANT_ID;

const server = new SecureMcpServer({
  name: 'tenant-filesystem',
  version: '1.0.0',
}, {
  resourcePolicy: {
    // Each tenant gets isolated directories
    rootDirs: [
      `/data/tenants/${tenantId}/files`,
      `/data/tenants/${tenantId}/uploads`,
    ],
    denyGlobs: [
      '**/*.key',
      '**/.env',
      '**/.*',  // Block all hidden files
    ],
    maxReadBytes: 1 * 1024 * 1024,  // 1MB per tenant
  },
});
```

### Read-only vs Read-write zones

```typescript
const server = new SecureMcpServer({
  name: 'zoned-filesystem',
  version: '1.0.0',
}, {
  toolRegistry: [
    {
      name: 'read-file',
      sideEffects: 'read',
      // Can read from all zones
    },
    {
      name: 'write-file',
      sideEffects: 'write',
      // Additional restrictions for write operations
    },
  ],
  resourcePolicy: {
    rootDirs: [
      '/app/readonly',   // Read-only data
      '/app/uploads',    // Read-write uploads
      '/app/logs',       // Write-only logs
    ],
  },
});

// In write-file tool implementation:
async function writeFile(args, config) {
  // Only allow writes to /app/uploads and /app/logs
  const writableDirs = ['/app/uploads', '/app/logs'];
  // Validate path is within writable directories
}
```

## Audit Logging

### Log all file access

```typescript
import { SecureMcpServer } from 'mcp-secure-server';
import * as fs from 'fs';

const auditLog = fs.createWriteStream('/var/log/file-access.log', { flags: 'a' });

function logAccess(operation: string, path: string, result: string) {
  const entry = JSON.stringify({
    timestamp: new Date().toISOString(),
    operation,
    path,
    result,
    pid: process.pid,
  });
  auditLog.write(entry + '\n');
}

// Wrap tool handlers with audit logging
server.tool('read-file', 'Read a file', schema, async (args) => {
  const result = await readFile(args, config);
  logAccess('read', args.filepath, result.isError ? 'denied' : 'allowed');
  return result;
});
```

## Custom Validators

### File type validation

```typescript
import * as path from 'path';

const ALLOWED_EXTENSIONS = ['.txt', '.json', '.md', '.csv'];

function validateFileType(filepath: string): boolean {
  const ext = path.extname(filepath).toLowerCase();
  return ALLOWED_EXTENSIONS.includes(ext);
}

server.tool('read-file', 'Read a file', schema, async (args) => {
  if (!validateFileType(args.filepath)) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Invalid file type',
          message: `Only ${ALLOWED_EXTENSIONS.join(', ')} files are allowed`,
        }),
      }],
      isError: true,
    };
  }
  return readFile(args, config);
});
```

### Content-based validation

```typescript
async function validateContent(content: string): Promise<boolean> {
  // Check for sensitive patterns that shouldn't be exposed
  const sensitivePatterns = [
    /password\s*[=:]\s*['"][^'"]+['"]/i,
    /api[_-]?key\s*[=:]\s*['"][^'"]+['"]/i,
    /-----BEGIN.*PRIVATE KEY-----/,
    /\b\d{3}-\d{2}-\d{4}\b/,  // SSN pattern
  ];

  for (const pattern of sensitivePatterns) {
    if (pattern.test(content)) {
      return false;  // Block files containing sensitive data
    }
  }
  return true;
}
```

## Performance Optimization

### Caching for repeated reads

```typescript
import { LRUCache } from 'lru-cache';

const fileCache = new LRUCache<string, { content: string; mtime: number }>({
  max: 100,  // Cache up to 100 files
  ttl: 1000 * 60 * 5,  // 5 minute TTL
});

async function readFileWithCache(filepath: string, stats: fs.Stats) {
  const cached = fileCache.get(filepath);

  if (cached && cached.mtime === stats.mtimeMs) {
    return cached.content;
  }

  const content = await fs.promises.readFile(filepath, 'utf-8');
  fileCache.set(filepath, { content, mtime: stats.mtimeMs });
  return content;
}
```

### Streaming for large files

```typescript
import { createReadStream } from 'fs';

async function streamLargeFile(filepath: string, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;

    const stream = createReadStream(filepath, {
      highWaterMark: 64 * 1024,  // 64KB chunks
    });

    stream.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        stream.destroy();
        reject(new Error('File too large'));
        return;
      }
      chunks.push(chunk);
    });

    stream.on('end', () => {
      resolve(Buffer.concat(chunks).toString('utf-8'));
    });

    stream.on('error', reject);
  });
}
```

## Production Deployment

### Docker configuration

```dockerfile
FROM node:20-alpine

WORKDIR /app

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Create data directories with proper permissions
RUN mkdir -p /app/data /app/documents /app/logs && \
    chown -R appuser:appgroup /app

COPY --chown=appuser:appgroup package*.json ./
RUN npm ci --only=production

COPY --chown=appuser:appgroup dist/ ./dist/

USER appuser

ENV NODE_ENV=production
ENV BASE_DIR=/app

CMD ["node", "dist/index.js"]
```

### Kubernetes security context

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: filesystem-server
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: server
    image: filesystem-server:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
    volumeMounts:
    - name: data
      mountPath: /app/data
      readOnly: true
    - name: documents
      mountPath: /app/documents
      readOnly: true
    - name: logs
      mountPath: /app/logs
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: data-pvc
  - name: documents
    persistentVolumeClaim:
      claimName: documents-pvc
  - name: logs
    emptyDir: {}
```

## Monitoring and Alerting

### Prometheus metrics

```typescript
import { Counter, Histogram } from 'prom-client';

const fileOpsCounter = new Counter({
  name: 'filesystem_operations_total',
  help: 'Total file operations',
  labelNames: ['operation', 'status'],
});

const fileOpsLatency = new Histogram({
  name: 'filesystem_operation_duration_seconds',
  help: 'File operation latency',
  labelNames: ['operation'],
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1],
});

// Instrument operations
async function instrumentedReadFile(args, config) {
  const timer = fileOpsLatency.startTimer({ operation: 'read' });
  try {
    const result = await readFile(args, config);
    fileOpsCounter.inc({ operation: 'read', status: result.isError ? 'error' : 'success' });
    return result;
  } finally {
    timer();
  }
}
```

### Security event alerting

```typescript
const securityEvents = new Counter({
  name: 'filesystem_security_events_total',
  help: 'Security events',
  labelNames: ['type'],
});

function recordSecurityEvent(type: string, details: object) {
  securityEvents.inc({ type });

  // Alert on critical events
  if (['path_traversal', 'sensitive_file_access'].includes(type)) {
    sendAlert({
      severity: 'high',
      type,
      details,
      timestamp: new Date().toISOString(),
    });
  }
}
```
