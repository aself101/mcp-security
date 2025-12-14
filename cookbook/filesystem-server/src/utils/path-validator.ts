/**
 * Path Validation Utilities
 * Secure path handling with traversal prevention and policy enforcement
 */

import * as path from 'path';
import * as fs from 'fs';

export interface PathPolicy {
  rootDirs: string[];
  denyGlobs: string[];
}

const DEFAULT_DENY_GLOBS = [
  '**/*.key',
  '**/*.pem',
  '**/.env',
  '**/.env.*',
  '**/credentials*',
  '**/secrets*',
  '/etc/**',
  '/proc/**',
  '/sys/**',
  '**/node_modules/**',
];

export function createPathPolicy(
  rootDirs: string[],
  additionalDenyGlobs: string[] = []
): PathPolicy {
  return {
    rootDirs: rootDirs.map((dir) => path.resolve(dir)),
    denyGlobs: [...DEFAULT_DENY_GLOBS, ...additionalDenyGlobs],
  };
}

export function normalizePath(inputPath: string, baseDir: string): string {
  // Remove null bytes and other dangerous characters
  const cleaned = inputPath.replace(/\0/g, '').trim();

  // Resolve to absolute path
  const absolute = path.isAbsolute(cleaned)
    ? path.normalize(cleaned)
    : path.resolve(baseDir, cleaned);

  return path.normalize(absolute);
}

export function isWithinRootDirs(
  filePath: string,
  rootDirs: string[]
): { allowed: boolean; matchedRoot: string | null } {
  const normalizedPath = path.normalize(filePath);

  for (const rootDir of rootDirs) {
    const normalizedRoot = path.normalize(rootDir);
    // Ensure path starts with root and doesn't escape via symlinks or traversal
    if (
      normalizedPath.startsWith(normalizedRoot + path.sep) ||
      normalizedPath === normalizedRoot
    ) {
      return { allowed: true, matchedRoot: normalizedRoot };
    }
  }

  return { allowed: false, matchedRoot: null };
}

export function matchesGlob(filePath: string, pattern: string): boolean {
  // Normalize the path
  const normalizedPath = path.normalize(filePath);
  const basename = path.basename(normalizedPath);

  // Handle patterns that start with **/ (match at any level including root)
  if (pattern.startsWith('**/')) {
    const suffix = pattern.slice(3); // Remove **/
    // Check if basename or any path suffix matches
    if (matchesSimpleGlob(basename, suffix)) {
      return true;
    }
    // Also check if the path ends with the pattern suffix
    if (matchesSimpleGlob(normalizedPath, suffix)) {
      return true;
    }
    // Check if any part of the path matches
    const parts = normalizedPath.split(path.sep);
    for (let i = 0; i < parts.length; i++) {
      const subpath = parts.slice(i).join(path.sep);
      if (matchesSimpleGlob(subpath, suffix)) {
        return true;
      }
    }
    return false;
  }

  // For other patterns, do direct matching
  return matchesSimpleGlob(normalizedPath, pattern) || matchesSimpleGlob(basename, pattern);
}

function matchesSimpleGlob(text: string, pattern: string): boolean {
  // Escape special regex characters except * and ?
  let regexPattern = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')  // Escape special chars first
    .replace(/\*\*/g, '{{GLOBSTAR}}')       // Preserve **
    .replace(/\*/g, '[^/\\\\]*')            // * matches anything except path separator
    .replace(/\?/g, '[^/\\\\]')             // ? matches single char except path separator
    .replace(/{{GLOBSTAR}}/g, '.*');        // ** matches anything including path separators

  const regex = new RegExp(`^${regexPattern}$`);
  return regex.test(text);
}

export function isDenied(filePath: string, denyGlobs: string[]): { denied: boolean; matchedPattern: string | null } {
  const normalizedPath = path.normalize(filePath);

  for (const pattern of denyGlobs) {
    if (matchesGlob(normalizedPath, pattern)) {
      return { denied: true, matchedPattern: pattern };
    }
  }

  return { denied: false, matchedPattern: null };
}

export function hasPathTraversal(inputPath: string): boolean {
  const dangerous = [
    '..',
    '%2e%2e',
    '%252e%252e',
    '..%c0%af',
    '..%c1%9c',
    '..../',
    '....//',
  ];

  const normalized = inputPath.toLowerCase();
  return dangerous.some((pattern) => normalized.includes(pattern));
}

export interface PathValidationResult {
  valid: boolean;
  normalizedPath: string;
  error?: string;
  reason?: string;
}

export function validatePath(
  inputPath: string,
  baseDir: string,
  policy: PathPolicy
): PathValidationResult {
  // Check for obvious traversal attempts first (defense in depth)
  if (hasPathTraversal(inputPath)) {
    return {
      valid: false,
      normalizedPath: '',
      error: 'Path traversal attempt detected',
      reason: 'path_traversal',
    };
  }

  // Normalize the path
  const normalizedPath = normalizePath(inputPath, baseDir);

  // Check if within allowed root directories
  const rootCheck = isWithinRootDirs(normalizedPath, policy.rootDirs);
  if (!rootCheck.allowed) {
    return {
      valid: false,
      normalizedPath,
      error: 'Path outside allowed directories',
      reason: 'outside_root',
    };
  }

  // Check against deny patterns
  const denyCheck = isDenied(normalizedPath, policy.denyGlobs);
  if (denyCheck.denied) {
    return {
      valid: false,
      normalizedPath,
      error: `Access to this file type is denied`,
      reason: 'denied_pattern',
    };
  }

  return {
    valid: true,
    normalizedPath,
  };
}

export async function getFileStats(filePath: string): Promise<fs.Stats | null> {
  try {
    return await fs.promises.stat(filePath);
  } catch {
    return null;
  }
}

export async function fileExists(filePath: string): Promise<boolean> {
  const stats = await getFileStats(filePath);
  return stats !== null && stats.isFile();
}

export async function directoryExists(dirPath: string): Promise<boolean> {
  const stats = await getFileStats(dirPath);
  return stats !== null && stats.isDirectory();
}
