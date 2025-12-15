/**
 * Session Store - In-memory state management for transaction workflow
 *
 * Implements a state machine that tracks each session's progress through
 * the transaction pipeline. This is the core of the method chaining security.
 */

import type { Currency } from './mock-data.js';

/** All possible workflow states */
export type WorkflowState =
  | 'DISCONNECTED'
  | 'CONNECTED'
  | 'ACCOUNTS_LISTED'
  | 'ACCOUNT_SELECTED'
  | 'TRANSACTION_PREPARED'
  | 'TRANSACTION_CONFIRMED'
  | 'TRANSACTION_EXECUTED';

/** Pending transaction details */
export interface PendingTransaction {
  id: string;
  fromAccountId: string;
  toAccountId: string;
  amount: number;
  currency: Currency;
  description: string;
  preparedAt: number;
  confirmedAt?: number;
}

/** Session data structure */
export interface Session {
  id: string;
  state: WorkflowState;
  selectedAccountId?: string;
  pendingTransaction?: PendingTransaction;
  createdAt: number;
  updatedAt: number;
}

/**
 * State machine transitions
 * Maps: current state -> { tool name -> next state }
 */
export const ALLOWED_TRANSITIONS: Record<WorkflowState, Record<string, WorkflowState>> = {
  DISCONNECTED: {
    'connect-session': 'CONNECTED',
  },
  CONNECTED: {
    'list-accounts': 'ACCOUNTS_LISTED',
    'check-status': 'CONNECTED',
    'disconnect-session': 'DISCONNECTED',
  },
  ACCOUNTS_LISTED: {
    'select-account': 'ACCOUNT_SELECTED',
    'list-accounts': 'ACCOUNTS_LISTED',
    'check-status': 'ACCOUNTS_LISTED',
    'disconnect-session': 'DISCONNECTED',
  },
  ACCOUNT_SELECTED: {
    'prepare-transaction': 'TRANSACTION_PREPARED',
    'select-account': 'ACCOUNT_SELECTED',
    'list-accounts': 'ACCOUNTS_LISTED',
    'check-status': 'ACCOUNT_SELECTED',
    'disconnect-session': 'DISCONNECTED',
  },
  TRANSACTION_PREPARED: {
    'confirm-transaction': 'TRANSACTION_CONFIRMED',
    'prepare-transaction': 'TRANSACTION_PREPARED',
    'select-account': 'ACCOUNT_SELECTED',
    'check-status': 'TRANSACTION_PREPARED',
    'disconnect-session': 'DISCONNECTED',
  },
  TRANSACTION_CONFIRMED: {
    'execute-transaction': 'TRANSACTION_EXECUTED',
    'prepare-transaction': 'TRANSACTION_PREPARED',
    'check-status': 'TRANSACTION_CONFIRMED',
    'disconnect-session': 'DISCONNECTED',
  },
  TRANSACTION_EXECUTED: {
    'prepare-transaction': 'TRANSACTION_PREPARED',
    'select-account': 'ACCOUNT_SELECTED',
    'list-accounts': 'ACCOUNTS_LISTED',
    'check-status': 'TRANSACTION_EXECUTED',
    'disconnect-session': 'DISCONNECTED',
  },
};

/** In-memory session storage */
let sessions: Map<string, Session> = new Map();

/** Initialize/reset session store */
export function initializeSessionStore(): void {
  sessions = new Map();
}

/** Get session by ID */
export function getSession(sessionId: string): Session | undefined {
  return sessions.get(sessionId);
}

/** Create a new session */
export function createSession(sessionId: string): Session {
  const session: Session = {
    id: sessionId,
    state: 'CONNECTED',
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  sessions.set(sessionId, session);
  return session;
}

/** Update session state */
export function updateSessionState(sessionId: string, newState: WorkflowState): void {
  const session = sessions.get(sessionId);
  if (session) {
    session.state = newState;
    session.updatedAt = Date.now();
  }
}

/** Set selected account for session */
export function setSelectedAccount(sessionId: string, accountId: string): void {
  const session = sessions.get(sessionId);
  if (session) {
    session.selectedAccountId = accountId;
    session.updatedAt = Date.now();
  }
}

/** Set pending transaction for session */
export function setPendingTransaction(sessionId: string, transaction: PendingTransaction): void {
  const session = sessions.get(sessionId);
  if (session) {
    session.pendingTransaction = transaction;
    session.updatedAt = Date.now();
  }
}

/** Confirm pending transaction */
export function confirmTransaction(sessionId: string): void {
  const session = sessions.get(sessionId);
  if (session?.pendingTransaction) {
    session.pendingTransaction.confirmedAt = Date.now();
    session.updatedAt = Date.now();
  }
}

/** Clear pending transaction */
export function clearPendingTransaction(sessionId: string): void {
  const session = sessions.get(sessionId);
  if (session) {
    session.pendingTransaction = undefined;
    session.updatedAt = Date.now();
  }
}

/** Check if a tool transition is allowed from current state */
export function isTransitionAllowed(sessionId: string, toolName: string): boolean {
  const session = sessions.get(sessionId);
  const currentState = session?.state ?? 'DISCONNECTED';
  const transitions = ALLOWED_TRANSITIONS[currentState];
  return toolName in transitions;
}

/** Get the next state for a given tool (if allowed) */
export function getNextState(currentState: WorkflowState, toolName: string): WorkflowState | null {
  const transitions = ALLOWED_TRANSITIONS[currentState];
  return transitions[toolName] ?? null;
}

/** Get allowed tools from current state */
export function getAllowedTools(sessionId: string): string[] {
  const session = sessions.get(sessionId);
  const currentState = session?.state ?? 'DISCONNECTED';
  return Object.keys(ALLOWED_TRANSITIONS[currentState]);
}

/** Delete a session */
export function deleteSession(sessionId: string): void {
  sessions.delete(sessionId);
}

/** Get total session count */
export function getSessionCount(): number {
  return sessions.size;
}

/** Get all sessions (for debugging) */
export function getAllSessions(): Session[] {
  return Array.from(sessions.values());
}
