/**
 * Pattern detection functions for Layer 2
 */

import type { Severity, ViolationType } from '../../../types/index.js';
import type { AttackPattern } from '../layer-utils/content/patterns/index.js';
import { ATTACK_PATTERNS, attackConfigs, sensitiveFileCategories } from '../layer-utils/content/dangerous-patterns.js';

/**
 * Path context indicators that suggest file system access intent.
 * Sensitive file patterns only trigger when these are present.
 * These patterns are designed to work on JSON-stringified content.
 */
const PATH_CONTEXT_PATTERNS = [
  /\.\.[/\\]/,            // Path traversal: ../ or ..\
  /["'][/\\]/,            // Absolute path in JSON: "/" or "\" at start of value
  /[/\\]\.\.[/\\]/,       // Mid-path traversal: /../
  /[/\\]etc[/\\]/,        // Unix system path: /etc/
  /[/\\]proc[/\\]/,       // Unix proc filesystem: /proc/
  /[/\\]var[/\\]/,        // Unix var path: /var/
  /[/\\]home[/\\]/,       // Unix home path: /home/
  /[/\\]usr[/\\]/,        // Unix usr path: /usr/
  /[a-zA-Z]:[/\\]/,       // Windows absolute path: C:\ or C:/
  /%2e%2e[%/\\]/i,        // URL-encoded traversal
  /%252e/i,               // Double-encoded dot
  /file:\/\//i,           // File protocol
  /\.\.%c0%af/i,          // UTF-8 overlong encoding
];

/** Validation result from pattern detection */
export interface PatternDetectionResult {
  passed: boolean;
  reason?: string;
  severity?: Severity;
  violationType?: ViolationType;
  confidence?: number;
}

/**
 * Consolidated malicious pattern detection for decoded content
 */
export function containsMaliciousPatterns(content: string): boolean {
  const patternGroups: AttackPattern[] = [
    ...ATTACK_PATTERNS.xss.basicVectors,
    ...ATTACK_PATTERNS.xss.eventHandlers,
    ...ATTACK_PATTERNS.xss.jsExecution,
    ...ATTACK_PATTERNS.xss.extraAttributes,
    ...ATTACK_PATTERNS.css.expressions,
    ...ATTACK_PATTERNS.script.pythonInjection,
    ...ATTACK_PATTERNS.script.nodeInjection,
    ...ATTACK_PATTERNS.command.basicInjection,
    ...ATTACK_PATTERNS.command.executionWrappers
  ];

  return patternGroups.some(({ pattern }) => pattern.test(content));
}

/**
 * Generic pattern detection method
 */
export function detectPatternCategories(
  content: string,
  attackType: string,
  patternCategories: readonly AttackPattern[][],
  violationType: ViolationType,
  confidence = 0.85
): PatternDetectionResult {
  for (const category of patternCategories) {
    for (const { pattern, name, severity } of category) {
      if (pattern.test(content)) {
        return {
          passed: false,
          reason: `${attackType} detected: ${name}`,
          severity,
          violationType,
          confidence
        };
      }
    }
  }
  return { passed: true };
}

/**
 * Check if content contains path context indicators.
 * Used to determine if sensitive file patterns should be checked.
 */
function hasPathContext(content: string): boolean {
  return PATH_CONTEXT_PATTERNS.some(pattern => pattern.test(content));
}

/**
 * Validate payload safety against all attack configs.
 * Uses context-aware detection for sensitive file patterns.
 */
export function validatePayloadSafety(content: string): PatternDetectionResult {
  // Check all standard attack patterns
  for (const config of attackConfigs) {
    const result = detectPatternCategories(
      content,
      config.name,
      config.categories,
      config.violationType,
      config.confidence
    );
    if (!result.passed) return result;
  }

  // Context-aware check: Only check sensitive file patterns
  // when path context is present (path separators, traversal, etc.)
  if (hasPathContext(content)) {
    const result = detectPatternCategories(
      content,
      'Sensitive file access',
      sensitiveFileCategories,
      'PATH_TRAVERSAL',
      0.85
    );
    if (!result.passed) return result;
  }

  return { passed: true };
}
