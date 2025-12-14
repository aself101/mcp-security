/**
 * Read File Tool
 * Safe file reading with path validation and size limits
 */

import { z } from 'zod';
import * as fs from 'fs';
import * as path from 'path';
import { validatePath, type PathPolicy } from '../utils/index.js';

const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2MB default

export const readFileSchema = z.object({
  filepath: z
    .string()
    .min(1)
    .max(500)
    .describe('Path to the file to read (relative to allowed directories)'),
});

export type ReadFileArgs = z.infer<typeof readFileSchema>;

export interface ReadFileConfig {
  baseDir: string;
  policy: PathPolicy;
  maxFileSize?: number;
}

export async function readFile(args: ReadFileArgs, config: ReadFileConfig) {
  const { filepath } = args;
  const { baseDir, policy, maxFileSize = MAX_FILE_SIZE } = config;

  // Validate the path against security policy
  const validation = validatePath(filepath, baseDir, policy);

  if (!validation.valid) {
    return {
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify(
            {
              error: 'Access denied',
              message: validation.error,
              path: filepath,
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

  // Check if file exists
  try {
    const stats = await fs.promises.stat(normalizedPath);

    if (!stats.isFile()) {
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                error: 'Not a file',
                message: 'The specified path is not a file',
                path: filepath,
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      };
    }

    // Check file size
    if (stats.size > maxFileSize) {
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                error: 'File too large',
                message: `File size (${stats.size} bytes) exceeds maximum allowed (${maxFileSize} bytes)`,
                path: filepath,
                size: stats.size,
                maxSize: maxFileSize,
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      };
    }

    // Read the file
    const content = await fs.promises.readFile(normalizedPath, 'utf-8');

    return {
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify(
            {
              path: filepath,
              normalizedPath: path.relative(baseDir, normalizedPath),
              size: stats.size,
              content,
              encoding: 'utf-8',
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
                error: 'File not found',
                message: 'The specified file does not exist',
                path: filepath,
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
                message: 'Cannot read the specified file',
                path: filepath,
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
