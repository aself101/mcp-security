/**
 * Security Tests for Transaction Server
 *
 * Tests method chaining enforcement and workflow state validation.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  initializeSessionStore,
  getSession,
  createSession,
  updateSessionState,
  isTransitionAllowed,
  getAllowedTools,
  deleteSession,
  setSelectedAccount,
  setPendingTransaction,
  confirmTransaction,
  type WorkflowState,
  type PendingTransaction,
} from '../src/utils/index.js';
import { createWorkflowStateValidator } from '../src/validators/index.js';

describe('Method Chaining Security', () => {
  beforeEach(() => {
    initializeSessionStore();
  });

  describe('Out-of-order call blocking', () => {
    it('should block execute-transaction before prepare-transaction', () => {
      const sessionId = 'test-session-1';
      createSession(sessionId);
      updateSessionState(sessionId, 'ACCOUNT_SELECTED');

      expect(isTransitionAllowed(sessionId, 'execute-transaction')).toBe(false);
    });

    it('should block execute-transaction before confirm-transaction', () => {
      const sessionId = 'test-session-2';
      createSession(sessionId);
      updateSessionState(sessionId, 'TRANSACTION_PREPARED');

      expect(isTransitionAllowed(sessionId, 'execute-transaction')).toBe(false);
    });

    it('should block prepare-transaction before select-account', () => {
      const sessionId = 'test-session-3';
      createSession(sessionId);
      updateSessionState(sessionId, 'ACCOUNTS_LISTED');

      expect(isTransitionAllowed(sessionId, 'prepare-transaction')).toBe(false);
    });

    it('should block select-account before list-accounts', () => {
      const sessionId = 'test-session-4';
      createSession(sessionId);
      // Session is in CONNECTED state

      expect(isTransitionAllowed(sessionId, 'select-account')).toBe(false);
    });

    it('should block confirm-transaction without prepare-transaction', () => {
      const sessionId = 'test-session-5';
      createSession(sessionId);
      updateSessionState(sessionId, 'ACCOUNT_SELECTED');

      expect(isTransitionAllowed(sessionId, 'confirm-transaction')).toBe(false);
    });
  });

  describe('Valid workflow sequences', () => {
    it('should allow complete happy path flow', () => {
      const sessionId = 'test-happy-path';
      createSession(sessionId);

      // Step through the entire workflow
      expect(isTransitionAllowed(sessionId, 'list-accounts')).toBe(true);
      updateSessionState(sessionId, 'ACCOUNTS_LISTED');

      expect(isTransitionAllowed(sessionId, 'select-account')).toBe(true);
      updateSessionState(sessionId, 'ACCOUNT_SELECTED');

      expect(isTransitionAllowed(sessionId, 'prepare-transaction')).toBe(true);
      updateSessionState(sessionId, 'TRANSACTION_PREPARED');

      expect(isTransitionAllowed(sessionId, 'confirm-transaction')).toBe(true);
      updateSessionState(sessionId, 'TRANSACTION_CONFIRMED');

      expect(isTransitionAllowed(sessionId, 'execute-transaction')).toBe(true);
      updateSessionState(sessionId, 'TRANSACTION_EXECUTED');

      expect(isTransitionAllowed(sessionId, 'disconnect-session')).toBe(true);
    });

    it('should allow check-status from any connected state', () => {
      const sessionId = 'test-check-status';
      createSession(sessionId);

      const states: WorkflowState[] = [
        'CONNECTED',
        'ACCOUNTS_LISTED',
        'ACCOUNT_SELECTED',
        'TRANSACTION_PREPARED',
        'TRANSACTION_CONFIRMED',
        'TRANSACTION_EXECUTED',
      ];

      for (const state of states) {
        updateSessionState(sessionId, state);
        expect(isTransitionAllowed(sessionId, 'check-status')).toBe(true);
      }
    });

    it('should allow disconnect from any connected state', () => {
      const sessionId = 'test-disconnect';
      createSession(sessionId);

      const states: WorkflowState[] = [
        'CONNECTED',
        'ACCOUNTS_LISTED',
        'ACCOUNT_SELECTED',
        'TRANSACTION_PREPARED',
        'TRANSACTION_CONFIRMED',
        'TRANSACTION_EXECUTED',
      ];

      for (const state of states) {
        updateSessionState(sessionId, state);
        expect(isTransitionAllowed(sessionId, 'disconnect-session')).toBe(true);
      }
    });

    it('should allow re-listing accounts', () => {
      const sessionId = 'test-relist';
      createSession(sessionId);
      updateSessionState(sessionId, 'ACCOUNTS_LISTED');

      expect(isTransitionAllowed(sessionId, 'list-accounts')).toBe(true);
    });

    it('should allow re-preparing transaction', () => {
      const sessionId = 'test-reprepare';
      createSession(sessionId);
      updateSessionState(sessionId, 'TRANSACTION_PREPARED');

      expect(isTransitionAllowed(sessionId, 'prepare-transaction')).toBe(true);
    });

    it('should allow going back to select-account from TRANSACTION_PREPARED', () => {
      const sessionId = 'test-cancel';
      createSession(sessionId);
      updateSessionState(sessionId, 'TRANSACTION_PREPARED');

      expect(isTransitionAllowed(sessionId, 'select-account')).toBe(true);
    });
  });

  describe('Session isolation', () => {
    it('should isolate state between sessions', () => {
      const session1 = 'session-a';
      const session2 = 'session-b';

      createSession(session1);
      createSession(session2);

      // Advance session1 to TRANSACTION_CONFIRMED
      updateSessionState(session1, 'ACCOUNTS_LISTED');
      updateSessionState(session1, 'ACCOUNT_SELECTED');
      updateSessionState(session1, 'TRANSACTION_PREPARED');
      updateSessionState(session1, 'TRANSACTION_CONFIRMED');

      // session2 is still in CONNECTED state
      expect(getSession(session1)?.state).toBe('TRANSACTION_CONFIRMED');
      expect(getSession(session2)?.state).toBe('CONNECTED');

      // session2 cannot execute (still in CONNECTED)
      expect(isTransitionAllowed(session2, 'execute-transaction')).toBe(false);

      // session1 can execute
      expect(isTransitionAllowed(session1, 'execute-transaction')).toBe(true);
    });

    it('should maintain independent state after deletion', () => {
      const session1 = 'session-delete-1';
      const session2 = 'session-delete-2';

      createSession(session1);
      createSession(session2);
      updateSessionState(session1, 'ACCOUNT_SELECTED');

      deleteSession(session1);

      // session2 should be unaffected
      expect(getSession(session2)?.state).toBe('CONNECTED');
      expect(getSession(session1)).toBeUndefined();
    });
  });

  describe('getAllowedTools function', () => {
    it('should return correct tools for CONNECTED state', () => {
      const sessionId = 'test-allowed-1';
      createSession(sessionId);

      const allowed = getAllowedTools(sessionId);
      expect(allowed).toContain('list-accounts');
      expect(allowed).toContain('check-status');
      expect(allowed).toContain('disconnect-session');
      expect(allowed).not.toContain('execute-transaction');
    });

    it('should return correct tools for TRANSACTION_CONFIRMED state', () => {
      const sessionId = 'test-allowed-2';
      createSession(sessionId);
      updateSessionState(sessionId, 'TRANSACTION_CONFIRMED');

      const allowed = getAllowedTools(sessionId);
      expect(allowed).toContain('execute-transaction');
      expect(allowed).toContain('prepare-transaction'); // Can go back
      expect(allowed).not.toContain('list-accounts');
    });
  });
});

describe('Workflow State Validator', () => {
  const validator = createWorkflowStateValidator();

  beforeEach(() => {
    initializeSessionStore();
  });

  describe('Session requirements', () => {
    it('should reject tools/call without session', () => {
      const result = validator(
        { method: 'tools/call', params: { name: 'list-accounts' } },
        { sessionId: 'nonexistent-session' }
      );

      expect(result).not.toBeNull();
      expect(result?.passed).toBe(false);
      expect(result?.violationType).toBe('NO_SESSION');
      expect(result?.reason).toContain('No active session');
    });

    it('should pass non-tools/call methods', () => {
      const result = validator(
        { method: 'tools/list' },
        { sessionId: 'any' }
      );

      expect(result).toBeNull();
    });

    it('should allow connect-session without existing session', () => {
      const result = validator(
        { method: 'tools/call', params: { name: 'connect-session' } },
        { sessionId: 'new-session' }
      );

      expect(result).toBeNull();
    });
  });

  describe('Workflow violations', () => {
    it('should reject invalid workflow transition', () => {
      createSession('validator-test-1');
      // Session is in CONNECTED state

      const result = validator(
        { method: 'tools/call', params: { name: 'execute-transaction' } },
        { sessionId: 'validator-test-1' }
      );

      expect(result).not.toBeNull();
      expect(result?.passed).toBe(false);
      expect(result?.violationType).toBe('WORKFLOW_STATE_VIOLATION');
      expect(result?.reason).toContain('not allowed in state');
      expect(result?.reason).toContain('CONNECTED');
    });

    it('should pass valid workflow transition', () => {
      createSession('validator-test-2');

      const result = validator(
        { method: 'tools/call', params: { name: 'list-accounts' } },
        { sessionId: 'validator-test-2' }
      );

      expect(result).toBeNull();
    });

    it('should reject duplicate connect-session', () => {
      createSession('validator-test-3');
      updateSessionState('validator-test-3', 'ACCOUNT_SELECTED');

      const result = validator(
        { method: 'tools/call', params: { name: 'connect-session' } },
        { sessionId: 'validator-test-3' }
      );

      expect(result).not.toBeNull();
      expect(result?.passed).toBe(false);
      expect(result?.reason).toContain('already in state');
    });
  });
});

describe('Attack Prevention', () => {
  beforeEach(() => {
    initializeSessionStore();
  });

  describe('State confusion attacks', () => {
    it('should prevent skipping confirmation step', () => {
      const sessionId = 'attack-skip-confirm';
      createSession(sessionId);
      updateSessionState(sessionId, 'ACCOUNTS_LISTED');
      updateSessionState(sessionId, 'ACCOUNT_SELECTED');
      updateSessionState(sessionId, 'TRANSACTION_PREPARED');

      // Attacker tries to skip confirm and go straight to execute
      expect(isTransitionAllowed(sessionId, 'execute-transaction')).toBe(false);
    });

    it('should prevent skipping preparation step', () => {
      const sessionId = 'attack-skip-prepare';
      createSession(sessionId);
      updateSessionState(sessionId, 'ACCOUNTS_LISTED');
      updateSessionState(sessionId, 'ACCOUNT_SELECTED');

      // Attacker tries to skip prepare and go straight to confirm
      expect(isTransitionAllowed(sessionId, 'confirm-transaction')).toBe(false);
    });

    it('should prevent direct execution from fresh session', () => {
      const sessionId = 'attack-direct-exec';
      createSession(sessionId);

      // Attacker tries to execute immediately
      expect(isTransitionAllowed(sessionId, 'execute-transaction')).toBe(false);
    });
  });

  describe('Session hijacking simulation', () => {
    it('should prevent cross-session state manipulation', () => {
      const victimSession = 'victim-session';
      const attackerSession = 'attacker-session';

      // Victim completes workflow up to confirmed
      createSession(victimSession);
      updateSessionState(victimSession, 'ACCOUNTS_LISTED');
      updateSessionState(victimSession, 'ACCOUNT_SELECTED');
      updateSessionState(victimSession, 'TRANSACTION_PREPARED');
      updateSessionState(victimSession, 'TRANSACTION_CONFIRMED');

      // Attacker creates their own session
      createSession(attackerSession);

      // Attacker cannot execute on their session
      expect(isTransitionAllowed(attackerSession, 'execute-transaction')).toBe(false);

      // Sessions remain isolated
      expect(getSession(victimSession)?.state).toBe('TRANSACTION_CONFIRMED');
      expect(getSession(attackerSession)?.state).toBe('CONNECTED');

      // Victim can still execute
      expect(isTransitionAllowed(victimSession, 'execute-transaction')).toBe(true);
    });
  });

  describe('Protocol order enforcement', () => {
    it('should enforce complete workflow before execution', () => {
      const sessionId = 'protocol-test';
      createSession(sessionId);

      // Cannot execute from any intermediate state
      const intermediateStates: WorkflowState[] = [
        'CONNECTED',
        'ACCOUNTS_LISTED',
        'ACCOUNT_SELECTED',
        'TRANSACTION_PREPARED',
      ];

      for (const state of intermediateStates) {
        updateSessionState(sessionId, state);
        expect(isTransitionAllowed(sessionId, 'execute-transaction')).toBe(false);
      }

      // Only from TRANSACTION_CONFIRMED can execute
      updateSessionState(sessionId, 'TRANSACTION_CONFIRMED');
      expect(isTransitionAllowed(sessionId, 'execute-transaction')).toBe(true);
    });
  });
});

describe('Session Data Management', () => {
  beforeEach(() => {
    initializeSessionStore();
  });

  it('should track selected account', () => {
    const sessionId = 'data-test-1';
    createSession(sessionId);
    setSelectedAccount(sessionId, 'acct-001');

    const session = getSession(sessionId);
    expect(session?.selectedAccountId).toBe('acct-001');
  });

  it('should track pending transaction', () => {
    const sessionId = 'data-test-2';
    createSession(sessionId);

    const tx: PendingTransaction = {
      id: 'txn-123',
      fromAccountId: 'acct-001',
      toAccountId: 'acct-002',
      amount: 100,
      currency: 'USD',
      description: 'Test',
      preparedAt: Date.now(),
    };

    setPendingTransaction(sessionId, tx);

    const session = getSession(sessionId);
    expect(session?.pendingTransaction?.id).toBe('txn-123');
    expect(session?.pendingTransaction?.amount).toBe(100);
  });

  it('should track confirmation timestamp', () => {
    const sessionId = 'data-test-3';
    createSession(sessionId);

    const tx: PendingTransaction = {
      id: 'txn-456',
      fromAccountId: 'acct-001',
      toAccountId: 'acct-002',
      amount: 200,
      currency: 'USD',
      description: 'Test',
      preparedAt: Date.now(),
    };

    setPendingTransaction(sessionId, tx);
    confirmTransaction(sessionId);

    const session = getSession(sessionId);
    expect(session?.pendingTransaction?.confirmedAt).toBeDefined();
    expect(session?.pendingTransaction?.confirmedAt).toBeGreaterThan(0);
  });
});
