/**
 * List Directory Tool
 * Safe directory listing with path validation and entry limits
 */

import { z } from 'zod';
import * as fs from 'fs';
import * as path from 'path';
import { validatePath, type PathPolicy } from '../utils/index.js';

const MAX_ENTRIES = 1000;

export const listDirectorySchema = z.object({
  path: z
    .string()
    .min(1)
    .max(500)
    .describe('Path to the directory to list (relative to allowed directories)'),
});

export type ListDirectoryArgs = z.infer<typeof listDirectorySchema>;

export interface ListDirectoryConfig {
  baseDir: string;
  policy: PathPolicy;
  maxEntries?: number;
}

interface DirectoryEntry {
  name: string;
  type: 'file' | 'directory' | 'symlink' | 'other';
  size?: number;
  modified?: string;
}

export async function listDirectory(
  args: ListDirectoryArgs,
  config: ListDirectoryConfig
) {
  const { path: dirPath } = args;
  const { baseDir, policy, maxEntries = MAX_ENTRIES } = config;

  // Validate the path against security policy
  const validation = validatePath(dirPath, baseDir, policy);

  if (!validation.valid) {
    return {
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify(
            {
              error: 'Access denied',
              message: validation.error,
              path: dirPath,
            },
            null,
            2
          ),
        },
      ],
      isError: true,
    };
  }

  const normalizedPath = validation.normalizedPath;

  try {
    const stats = await fs.promises.stat(normalizedPath);

    if (!stats.isDirectory()) {
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                error: 'Not a directory',
                message: 'The specified path is not a directory',
                path: dirPath,
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      };
    }

    // Read directory entries
    const entries = await fs.promises.readdir(normalizedPath, {
      withFileTypes: true,
    });

    // Limit entries
    const limitedEntries = entries.slice(0, maxEntries);
    const truncated = entries.length > maxEntries;

    // Map entries to structured format
    const formattedEntries: DirectoryEntry[] = await Promise.all(
      limitedEntries.map(async (entry) => {
        const entryPath = path.join(normalizedPath, entry.name);
        let entryType: DirectoryEntry['type'] = 'other';

        if (entry.isFile()) {
          entryType = 'file';
        } else if (entry.isDirectory()) {
          entryType = 'directory';
        } else if (entry.isSymbolicLink()) {
          entryType = 'symlink';
        }

        const result: DirectoryEntry = {
          name: entry.name,
          type: entryType,
        };

        // Add file size and modified time for files
        if (entry.isFile()) {
          try {
            const fileStats = await fs.promises.stat(entryPath);
            result.size = fileStats.size;
            result.modified = fileStats.mtime.toISOString();
          } catch {
            // Ignore stat errors for individual files
          }
        }

        return result;
      })
    );

    // Sort: directories first, then files, alphabetically
    formattedEntries.sort((a, b) => {
      if (a.type === 'directory' && b.type !== 'directory') return -1;
      if (a.type !== 'directory' && b.type === 'directory') return 1;
      return a.name.localeCompare(b.name);
    });

    return {
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify(
            {
              path: dirPath,
              normalizedPath: path.relative(baseDir, normalizedPath),
              totalEntries: entries.length,
              returnedEntries: formattedEntries.length,
              truncated,
              entries: formattedEntries,
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
                path: dirPath,
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      };
    }

    if (error.code === 'EACCES') {
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                error: 'Permission denied',
                message: 'Cannot read the specified directory',
                path: dirPath,
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
