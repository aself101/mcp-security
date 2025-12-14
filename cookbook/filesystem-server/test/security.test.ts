/**
 * Security Tests for Filesystem Server
 * Tests attack vector prevention and security policies
 */

import { describe, it, expect } from 'vitest';
import * as path from 'path';

import { readFile } from '../src/tools/read-file.js';
import { listDirectory } from '../src/tools/list-directory.js';
import { searchFiles } from '../src/tools/search-files.js';
import {
  createPathPolicy,
  hasPathTraversal,
  validatePath,
  matchesGlob,
} from '../src/utils/path-validator.js';

const BASE_DIR = path.resolve(__dirname, '..');
const DATA_DIR = path.resolve(BASE_DIR, 'data');
const DOCUMENTS_DIR = path.resolve(BASE_DIR, 'documents');
const LOGS_DIR = path.resolve(BASE_DIR, 'logs');

const readPolicy = createPathPolicy(
  [DATA_DIR, DOCUMENTS_DIR],
  ['**/*.key', '**/.env', '**/.env.*', '**/secrets*', '/etc/**']
);

// ============================================================================
// Path Traversal Prevention Tests
// ============================================================================

describe('path traversal prevention', () => {
  describe('hasPathTraversal detection', () => {
    it('should detect basic ../ traversal', () => {
      expect(hasPathTraversal('../etc/passwd')).toBe(true);
      expect(hasPathTraversal('data/../../../etc/passwd')).toBe(true);
      expect(hasPathTraversal('..\\windows\\system32')).toBe(true);
    });

    it('should detect URL-encoded traversal', () => {
      expect(hasPathTraversal('%2e%2e/etc/passwd')).toBe(true);
      expect(hasPathTraversal('%252e%252e/etc/passwd')).toBe(true);
    });

    it('should detect overlong UTF-8 sequences', () => {
      expect(hasPathTraversal('..%c0%af/etc/passwd')).toBe(true);
      expect(hasPathTraversal('..%c1%9c/etc/passwd')).toBe(true);
    });

    it('should allow safe paths', () => {
      expect(hasPathTraversal('data/file.txt')).toBe(false);
      expect(hasPathTraversal('documents/report.pdf')).toBe(false);
      expect(hasPathTraversal('./local/file.txt')).toBe(false);
    });
  });

  describe('read-file path traversal attacks', () => {
    const attacks = [
      '../../../etc/passwd',
      '....//....//etc/passwd',
      'data/../../../etc/passwd',
      '%2e%2e/%2e%2e/etc/passwd',
      '..%c0%af..%c0%af/etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      'data/..%252f..%252f/etc/passwd',
    ];

    for (const attack of attacks) {
      it(`should block: ${attack}`, async () => {
        const result = await readFile(
          { filepath: attack },
          { baseDir: BASE_DIR, policy: readPolicy }
        );

        expect(result.isError).toBe(true);
        const content = JSON.parse(result.content[0].text);
        expect(content.error).toMatch(/Access denied|Path traversal/i);
      });
    }
  });

  describe('list-directory path traversal attacks', () => {
    const attacks = ['../..', '../../etc', '%2e%2e/%2e%2e', '..%00/'];

    for (const attack of attacks) {
      it(`should block: ${attack}`, async () => {
        const result = await listDirectory(
          { path: attack },
          { baseDir: BASE_DIR, policy: readPolicy }
        );

        expect(result.isError).toBe(true);
        const content = JSON.parse(result.content[0].text);
        expect(content.error).toMatch(/Access denied|Path traversal/i);
      });
    }
  });

  describe('search-files path traversal attacks', () => {
    const attacks = ['../..', '../../', '%2e%2e'];

    for (const attack of attacks) {
      it(`should block directory: ${attack}`, async () => {
        const result = await searchFiles(
          { pattern: 'password', directory: attack },
          { baseDir: BASE_DIR, policy: readPolicy }
        );

        expect(result.isError).toBe(true);
        const content = JSON.parse(result.content[0].text);
        expect(content.error).toMatch(/Access denied|Path traversal/i);
      });
    }
  });
});

// ============================================================================
// Root Directory Restriction Tests
// ============================================================================

describe('root directory restrictions', () => {
  it('should block absolute paths outside root', async () => {
    const result = await readFile(
      { filepath: '/etc/passwd' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    expect(result.isError).toBe(true);
    const content = JSON.parse(result.content[0].text);
    expect(content.error).toContain('Access denied');
  });

  it('should block access to logs directory via read-file', async () => {
    const result = await readFile(
      { filepath: 'logs/test.log' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    expect(result.isError).toBe(true);
    const content = JSON.parse(result.content[0].text);
    expect(content.error).toContain('Access denied');
  });

  it('should block access to parent directories', async () => {
    const result = await listDirectory(
      { path: '..' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    expect(result.isError).toBe(true);
  });

  it('should block access to system directories', async () => {
    const systemPaths = ['/proc/self/environ', '/sys/class', '/dev/null'];

    for (const sysPath of systemPaths) {
      const result = await readFile(
        { filepath: sysPath },
        { baseDir: BASE_DIR, policy: readPolicy }
      );

      expect(result.isError).toBe(true);
    }
  });
});

// ============================================================================
// Deny Glob Pattern Tests
// ============================================================================

describe('deny glob patterns', () => {
  describe('matchesGlob function', () => {
    it('should match .env files', () => {
      expect(matchesGlob('.env', '**/.env')).toBe(true);
      expect(matchesGlob('config/.env', '**/.env')).toBe(true);
    });

    it('should match .env.* files', () => {
      expect(matchesGlob('.env.local', '**/.env.*')).toBe(true);
      expect(matchesGlob('.env.production', '**/.env.*')).toBe(true);
    });

    it('should match .key files', () => {
      expect(matchesGlob('private.key', '**/*.key')).toBe(true);
      expect(matchesGlob('ssl/server.key', '**/*.key')).toBe(true);
    });

    it('should match /etc/** pattern', () => {
      expect(matchesGlob('/etc/passwd', '/etc/**')).toBe(true);
      expect(matchesGlob('/etc/shadow', '/etc/**')).toBe(true);
    });
  });

  describe('sensitive file blocking', () => {
    it('should block .env files', async () => {
      const policyWithEnv = createPathPolicy([DATA_DIR], ['**/.env']);

      const validation = validatePath('data/.env', BASE_DIR, policyWithEnv);
      expect(validation.valid).toBe(false);
      expect(validation.reason).toBe('denied_pattern');
    });

    it('should block .key files', async () => {
      const policyWithKey = createPathPolicy([DATA_DIR], ['**/*.key']);

      const validation = validatePath(
        'data/private.key',
        BASE_DIR,
        policyWithKey
      );
      expect(validation.valid).toBe(false);
    });

    it('should block secrets files', async () => {
      const policyWithSecrets = createPathPolicy([DATA_DIR], ['**/secrets*']);

      const validation = validatePath(
        'data/secrets.json',
        BASE_DIR,
        policyWithSecrets
      );
      expect(validation.valid).toBe(false);
    });
  });
});

// ============================================================================
// Null Byte Injection Tests
// ============================================================================

describe('null byte injection prevention', () => {
  it('should strip null bytes from paths', async () => {
    const result = await readFile(
      { filepath: 'data/sample.txt\x00.jpg' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    // Should either find the file (null byte stripped) or not find it
    // But should NOT expose unintended files
    const content = JSON.parse(result.content[0].text);
    if (!result.isError) {
      expect(content.path).not.toContain('\x00');
    }
  });

  it('should handle URL-encoded null bytes', async () => {
    const result = await readFile(
      { filepath: 'data/sample.txt%00.jpg' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    // Should handle gracefully
    expect(result.content).toBeDefined();
  });
});

// ============================================================================
// File Size Limit Tests
// ============================================================================

describe('file size limits', () => {
  it('should respect maxFileSize parameter', async () => {
    const result = await readFile(
      { filepath: 'data/sample.txt' },
      {
        baseDir: BASE_DIR,
        policy: readPolicy,
        maxFileSize: 10, // Very small limit
      }
    );

    expect(result.isError).toBe(true);
    const content = JSON.parse(result.content[0].text);
    expect(content.error).toBe('File too large');
  });
});

// ============================================================================
// Directory Entry Limit Tests
// ============================================================================

describe('directory entry limits', () => {
  it('should respect maxEntries parameter', async () => {
    const result = await listDirectory(
      { path: 'data' },
      {
        baseDir: BASE_DIR,
        policy: readPolicy,
        maxEntries: 1,
      }
    );

    const content = JSON.parse(result.content[0].text);
    expect(content.returnedEntries).toBeLessThanOrEqual(1);
    if (content.totalEntries > 1) {
      expect(content.truncated).toBe(true);
    }
  });
});

// ============================================================================
// Search Limit Tests
// ============================================================================

describe('search limits', () => {
  it('should respect maxFiles parameter', async () => {
    const result = await searchFiles(
      { pattern: 'test', directory: 'data' },
      {
        baseDir: BASE_DIR,
        policy: readPolicy,
        maxFiles: 1,
      }
    );

    const content = JSON.parse(result.content[0].text);
    expect(content.filesScanned).toBeLessThanOrEqual(1);
  });
});

// ============================================================================
// Symlink Attack Prevention
// ============================================================================

describe('symlink handling', () => {
  it('should identify symlinks in directory listing', async () => {
    // This test verifies symlinks are properly identified
    // Actual symlink attack prevention depends on rootDir validation
    const result = await listDirectory(
      { path: 'data' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    const content = JSON.parse(result.content[0].text);
    // Verify structure includes type field for symlink identification
    expect(content.entries[0]).toHaveProperty('type');
  });
});

// ============================================================================
// Input Validation Tests
// ============================================================================

describe('input validation', () => {
  it('should handle empty filepath', async () => {
    const result = await readFile(
      { filepath: '' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    expect(result.isError).toBe(true);
  });

  it('should handle extremely long paths', async () => {
    const longPath = 'a'.repeat(10000);
    const result = await readFile(
      { filepath: longPath },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    expect(result.isError).toBe(true);
  });

  it('should handle special characters in paths', async () => {
    const specialPaths = [
      'data/<script>alert(1)</script>',
      "data/'; DROP TABLE users; --",
      'data/${process.env.SECRET}',
      'data/$(whoami)',
    ];

    for (const specialPath of specialPaths) {
      const result = await readFile(
        { filepath: specialPath },
        { baseDir: BASE_DIR, policy: readPolicy }
      );

      // Should either reject or handle safely (file not found)
      if (!result.isError) {
        const content = JSON.parse(result.content[0].text);
        // Should not execute anything dangerous
        expect(content.path).toBeDefined();
      }
    }
  });
});
