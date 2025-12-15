/**
 * Workflow State Validator - Layer 5 Custom Validator
 *
 * Enforces the transaction workflow state machine at the application level.
 * Works alongside Layer 4 method chaining for defense-in-depth security.
 */

import {
  getSession,
  isTransitionAllowed,
  getAllowedTools,
  ALLOWED_TRANSITIONS,
} from '../utils/index.js';

/** Validation result for Layer 5 */
interface ValidationResult {
  passed: boolean;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  reason?: string;
  violationType?: string;
}

/** MCP message structure */
interface McpMessage {
  method?: string;
  params?: {
    name?: string;
    arguments?: Record<string, unknown>;
    [key: string]: unknown;
  };
}

/** Validation context */
interface ValidationContext {
  sessionId?: string;
  clientId?: string;
}

/**
 * Creates the workflow state validator for Layer 5
 *
 * This validator ensures that tools are called in the correct order
 * according to the financial transaction state machine.
 *
 * @returns Validator function for Layer 5 registration
 */
export function createWorkflowStateValidator() {
  return (message: unknown, context: unknown): ValidationResult | null => {
    const msg = message as McpMessage;
    const ctx = context as ValidationContext;

    // Only validate tools/call requests
    if (msg.method !== 'tools/call') {
      return null; // Pass through to other validators
    }

    const toolName = msg.params?.name;
    if (!toolName) {
      return null; // No tool name, let other validators handle
    }

    // Get session ID from context
    const sessionId = ctx.sessionId ?? ctx.clientId ?? 'default';

    // Special case: connect-session creates a new session
    if (toolName === 'connect-session') {
      const session = getSession(sessionId);
      if (session && session.state !== 'DISCONNECTED') {
        return {
          passed: false,
          severity: 'HIGH',
          reason: `Cannot connect: session already in state '${session.state}'. Use disconnect-session first.`,
          violationType: 'WORKFLOW_STATE_VIOLATION',
        };
      }
      return null; // Allow connection
    }

    // For all other tools, check session exists
    const session = getSession(sessionId);
    if (!session) {
      return {
        passed: false,
        severity: 'HIGH',
        reason: 'No active session. Call connect-session first.',
        violationType: 'NO_SESSION',
      };
    }

    // Check if transition is allowed from current state
    if (!isTransitionAllowed(sessionId, toolName)) {
      const allowedTools = getAllowedTools(sessionId);
      return {
        passed: false,
        severity: 'HIGH',
        reason: `Invalid workflow: '${toolName}' not allowed in state '${session.state}'. Allowed: [${allowedTools.join(', ')}]`,
        violationType: 'WORKFLOW_STATE_VIOLATION',
      };
    }

    return null; // Transition allowed, pass to tool handler
  };
}

/**
 * Get human-readable state description
 */
export function getStateDescription(state: string): string {
  const descriptions: Record<string, string> = {
    DISCONNECTED: 'No active session',
    CONNECTED: 'Session connected, ready to list accounts',
    ACCOUNTS_LISTED: 'Accounts listed, ready to select',
    ACCOUNT_SELECTED: 'Account selected, ready to prepare transaction',
    TRANSACTION_PREPARED: 'Transaction prepared, ready to confirm',
    TRANSACTION_CONFIRMED: 'Transaction confirmed, ready to execute',
    TRANSACTION_EXECUTED: 'Transaction completed',
  };
  return descriptions[state] ?? 'Unknown state';
}
