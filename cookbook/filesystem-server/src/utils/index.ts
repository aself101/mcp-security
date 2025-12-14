/**
 * Utility exports for filesystem server
 */

export {
  createPathPolicy,
  normalizePath,
  isWithinRootDirs,
  matchesGlob,
  isDenied,
  hasPathTraversal,
  validatePath,
  getFileStats,
  fileExists,
  directoryExists,
  type PathPolicy,
  type PathValidationResult,
} from './path-validator.js';
