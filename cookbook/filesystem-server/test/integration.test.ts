/**
 * Integration Tests for Filesystem Server
 * Tests basic functionality of all tools
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as path from 'path';
import * as fs from 'fs';

import { readFile } from '../src/tools/read-file.js';
import { listDirectory } from '../src/tools/list-directory.js';
import { searchFiles } from '../src/tools/search-files.js';
import { writeLog } from '../src/tools/write-log.js';
import { createPathPolicy } from '../src/utils/path-validator.js';

const BASE_DIR = path.resolve(__dirname, '..');
const DATA_DIR = path.resolve(BASE_DIR, 'data');
const DOCUMENTS_DIR = path.resolve(BASE_DIR, 'documents');
const LOGS_DIR = path.resolve(BASE_DIR, 'logs');

const readPolicy = createPathPolicy([DATA_DIR, DOCUMENTS_DIR], []);

describe('read-file tool', () => {
  it('should read a valid file from data directory', async () => {
    const result = await readFile(
      { filepath: 'data/sample.txt' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    expect(result.isError).toBeUndefined();
    const content = JSON.parse(result.content[0].text);
    expect(content.path).toBe('data/sample.txt');
    expect(content.content).toContain('sample text file');
  });

  it('should read JSON files correctly', async () => {
    const result = await readFile(
      { filepath: 'data/users.json' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    expect(result.isError).toBeUndefined();
    const content = JSON.parse(result.content[0].text);
    const fileContent = JSON.parse(content.content);
    expect(fileContent.users).toHaveLength(3);
    expect(fileContent.users[0].name).toBe('Alice Johnson');
  });

  it('should read files from documents directory', async () => {
    const result = await readFile(
      { filepath: 'documents/readme.md' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    expect(result.isError).toBeUndefined();
    const content = JSON.parse(result.content[0].text);
    expect(content.content).toContain('Sample Documents');
  });

  it('should read files from nested directories', async () => {
    const result = await readFile(
      { filepath: 'documents/nested/deep-file.txt' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    expect(result.isError).toBeUndefined();
    const content = JSON.parse(result.content[0].text);
    expect(content.content).toContain('nested directory');
  });

  it('should return error for non-existent file', async () => {
    const result = await readFile(
      { filepath: 'data/nonexistent.txt' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    expect(result.isError).toBe(true);
    const content = JSON.parse(result.content[0].text);
    expect(content.error).toBe('File not found');
  });

  it('should return error when reading a directory', async () => {
    const result = await readFile(
      { filepath: 'data' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    expect(result.isError).toBe(true);
    const content = JSON.parse(result.content[0].text);
    expect(content.error).toBe('Not a file');
  });
});

describe('list-directory tool', () => {
  it('should list contents of data directory', async () => {
    const result = await listDirectory(
      { path: 'data' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    expect(result.isError).toBeUndefined();
    const content = JSON.parse(result.content[0].text);
    expect(content.entries).toBeDefined();
    expect(content.entries.length).toBeGreaterThan(0);

    const fileNames = content.entries.map((e: { name: string }) => e.name);
    expect(fileNames).toContain('sample.txt');
    expect(fileNames).toContain('users.json');
  });

  it('should list contents of documents directory', async () => {
    const result = await listDirectory(
      { path: 'documents' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    expect(result.isError).toBeUndefined();
    const content = JSON.parse(result.content[0].text);

    const fileNames = content.entries.map((e: { name: string }) => e.name);
    expect(fileNames).toContain('readme.md');
    expect(fileNames).toContain('nested');
  });

  it('should show directories first, then files', async () => {
    const result = await listDirectory(
      { path: 'documents' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    const content = JSON.parse(result.content[0].text);
    const types = content.entries.map((e: { type: string }) => e.type);
    const firstFileIndex = types.indexOf('file');
    const lastDirIndex = types.lastIndexOf('directory');

    if (firstFileIndex !== -1 && lastDirIndex !== -1) {
      expect(lastDirIndex).toBeLessThan(firstFileIndex);
    }
  });

  it('should include file metadata', async () => {
    const result = await listDirectory(
      { path: 'data' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    const content = JSON.parse(result.content[0].text);
    const fileEntry = content.entries.find(
      (e: { type: string }) => e.type === 'file'
    );

    expect(fileEntry).toBeDefined();
    expect(fileEntry.size).toBeGreaterThan(0);
    expect(fileEntry.modified).toBeDefined();
  });

  it('should return error for non-existent directory within allowed paths', async () => {
    const result = await listDirectory(
      { path: 'data/nonexistent' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    expect(result.isError).toBe(true);
    const content = JSON.parse(result.content[0].text);
    expect(content.error).toBe('Directory not found');
  });
});

describe('search-files tool', () => {
  it('should find text in files', async () => {
    const result = await searchFiles(
      { pattern: 'sample', directory: 'data' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    expect(result.isError).toBeUndefined();
    const content = JSON.parse(result.content[0].text);
    expect(content.totalMatches).toBeGreaterThan(0);
    expect(content.results.length).toBeGreaterThan(0);
  });

  it('should be case-insensitive', async () => {
    const result = await searchFiles(
      { pattern: 'SAMPLE', directory: 'data' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    const content = JSON.parse(result.content[0].text);
    expect(content.totalMatches).toBeGreaterThan(0);
  });

  it('should search across directories', async () => {
    const result = await searchFiles(
      { pattern: 'directory', directory: 'documents' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    const content = JSON.parse(result.content[0].text);
    expect(content.filesScanned).toBeGreaterThan(0);
  });

  it('should return empty results for no matches', async () => {
    const result = await searchFiles(
      { pattern: 'xyznonexistentpattern123', directory: 'data' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    const content = JSON.parse(result.content[0].text);
    expect(content.totalMatches).toBe(0);
    expect(content.results).toHaveLength(0);
  });

  it('should include match details', async () => {
    const result = await searchFiles(
      { pattern: 'Alice', directory: 'data' },
      { baseDir: BASE_DIR, policy: readPolicy }
    );

    const content = JSON.parse(result.content[0].text);
    expect(content.results.length).toBeGreaterThan(0);

    const match = content.results[0].matches[0];
    expect(match.line).toBeGreaterThan(0);
    expect(match.column).toBeGreaterThan(0);
    expect(match.content).toContain('Alice');
  });
});

describe('write-log tool', () => {
  const testLogFile = path.join(
    LOGS_DIR,
    `app-${new Date().toISOString().split('T')[0]}.log`
  );

  afterAll(async () => {
    // Clean up test log file
    try {
      await fs.promises.unlink(testLogFile);
    } catch {
      // Ignore if file doesn't exist
    }
  });

  it('should write a log message', async () => {
    const result = await writeLog(
      { message: 'Test log message', level: 'info' },
      { baseDir: BASE_DIR, logsDir: LOGS_DIR }
    );

    expect(result.isError).toBeUndefined();
    const content = JSON.parse(result.content[0].text);
    expect(content.success).toBe(true);
    expect(content.level).toBe('info');
    expect(content.message).toBe('Test log message');
  });

  it('should append to existing log file', async () => {
    await writeLog(
      { message: 'First message', level: 'info' },
      { baseDir: BASE_DIR, logsDir: LOGS_DIR }
    );

    await writeLog(
      { message: 'Second message', level: 'warn' },
      { baseDir: BASE_DIR, logsDir: LOGS_DIR }
    );

    const logContent = await fs.promises.readFile(testLogFile, 'utf-8');
    expect(logContent).toContain('First message');
    expect(logContent).toContain('Second message');
    expect(logContent).toContain('[INFO]');
    expect(logContent).toContain('[WARN]');
  });

  it('should support different log levels', async () => {
    const levels = ['debug', 'info', 'warn', 'error'] as const;

    for (const level of levels) {
      const result = await writeLog(
        { message: `${level} level test`, level },
        { baseDir: BASE_DIR, logsDir: LOGS_DIR }
      );

      const content = JSON.parse(result.content[0].text);
      expect(content.level).toBe(level);
    }
  });
});
