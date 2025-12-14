/**
 * Search Files Tool
 * Text search within files with path validation and scan limits
 */

import { z } from 'zod';
import * as fs from 'fs';
import * as path from 'path';
import { validatePath, isDenied, type PathPolicy } from '../utils/index.js';

const MAX_SEARCH_FILES = 100;
const MAX_FILE_SIZE_FOR_SEARCH = 1 * 1024 * 1024; // 1MB
const MAX_MATCHES_PER_FILE = 10;

export const searchFilesSchema = z.object({
  pattern: z
    .string()
    .min(1)
    .max(200)
    .describe('Text pattern to search for (case-insensitive)'),
  directory: z
    .string()
    .min(1)
    .max(500)
    .describe('Directory to search in (relative to allowed directories)'),
});

export type SearchFilesArgs = z.infer<typeof searchFilesSchema>;

export interface SearchFilesConfig {
  baseDir: string;
  policy: PathPolicy;
  maxFiles?: number;
}

interface SearchMatch {
  file: string;
  line: number;
  content: string;
  column: number;
}

interface SearchResult {
  file: string;
  matches: SearchMatch[];
  truncated: boolean;
}

async function searchInFile(
  filePath: string,
  pattern: string,
  relativePath: string
): Promise<SearchResult | null> {
  try {
    const stats = await fs.promises.stat(filePath);

    // Skip files that are too large
    if (stats.size > MAX_FILE_SIZE_FOR_SEARCH) {
      return null;
    }

    const content = await fs.promises.readFile(filePath, 'utf-8');
    const lines = content.split('\n');
    const matches: SearchMatch[] = [];
    const patternLower = pattern.toLowerCase();

    for (let i = 0; i < lines.length && matches.length < MAX_MATCHES_PER_FILE; i++) {
      const line = lines[i];
      const lineLower = line.toLowerCase();
      const index = lineLower.indexOf(patternLower);

      if (index !== -1) {
        matches.push({
          file: relativePath,
          line: i + 1,
          column: index + 1,
          content: line.slice(0, 200), // Truncate long lines
        });
      }
    }

    if (matches.length === 0) {
      return null;
    }

    return {
      file: relativePath,
      matches,
      truncated: matches.length >= MAX_MATCHES_PER_FILE,
    };
  } catch {
    // Skip files we can't read
    return null;
  }
}

async function collectFiles(
  dir: string,
  baseDir: string,
  policy: PathPolicy,
  maxFiles: number,
  collected: string[] = []
): Promise<string[]> {
  if (collected.length >= maxFiles) {
    return collected;
  }

  try {
    const entries = await fs.promises.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      if (collected.length >= maxFiles) {
        break;
      }

      const fullPath = path.join(dir, entry.name);

      // Check if path is denied by policy
      if (isDenied(fullPath, policy.denyGlobs).denied) {
        continue;
      }

      if (entry.isFile()) {
        collected.push(fullPath);
      } else if (entry.isDirectory()) {
        // Skip common non-content directories
        if (['node_modules', '.git', '.svn', '__pycache__'].includes(entry.name)) {
          continue;
        }
        await collectFiles(fullPath, baseDir, policy, maxFiles, collected);
      }
    }
  } catch {
    // Skip directories we can't read
  }

  return collected;
}

export async function searchFiles(
  args: SearchFilesArgs,
  config: SearchFilesConfig
) {
  const { pattern, directory } = args;
  const { baseDir, policy, maxFiles = MAX_SEARCH_FILES } = config;

  // Validate the directory path against security policy
  const validation = validatePath(directory, baseDir, policy);

  if (!validation.valid) {
    return {
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify(
            {
              error: 'Access denied',
              message: validation.error,
              directory,
            },
            null,
            2
          ),
        },
      ],
      isError: true,
    };
  }

  const normalizedDir = validation.normalizedPath;

  try {
    const stats = await fs.promises.stat(normalizedDir);

    if (!stats.isDirectory()) {
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                error: 'Not a directory',
                message: 'The specified path is not a directory',
                directory,
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      };
    }

    // Collect files to search
    const files = await collectFiles(normalizedDir, baseDir, policy, maxFiles);
    const filesScanned = files.length;
    const truncatedScan = filesScanned >= maxFiles;

    // Search in each file
    const results: SearchResult[] = [];

    for (const filePath of files) {
      const relativePath = path.relative(baseDir, filePath);
      const result = await searchInFile(filePath, pattern, relativePath);

      if (result) {
        results.push(result);
      }
    }

    // Calculate total matches
    const totalMatches = results.reduce(
      (sum, r) => sum + r.matches.length,
      0
    );

    return {
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify(
            {
              pattern,
              directory,
              normalizedDirectory: path.relative(baseDir, normalizedDir),
              filesScanned,
              filesWithMatches: results.length,
              totalMatches,
              truncatedScan,
              results,
            },
            null,
            2
          ),
        },
      ],
    };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;

    if (error.code === 'ENOENT') {
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                error: 'Directory not found',
                message: 'The specified directory does not exist',
                directory,
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      };
    }

    throw error;
  }
}
