/**
 * Mock Financial Data
 *
 * Provides in-memory accounts and transaction history for demonstration.
 */

/** Account types */
export type AccountType = 'checking' | 'savings' | 'investment';

/** Currency types */
export type Currency = 'USD' | 'EUR' | 'GBP';

/** Account interface */
export interface Account {
  id: string;
  name: string;
  type: AccountType;
  balance: number;
  currency: Currency;
  ownerId: string;
}

/** Transaction status */
export type TransactionStatus = 'pending' | 'completed' | 'failed';

/** Executed transaction record */
export interface Transaction {
  id: string;
  fromAccountId: string;
  toAccountId: string;
  amount: number;
  currency: Currency;
  status: TransactionStatus;
  description: string;
  createdAt: number;
  completedAt?: number;
}

/** Mock accounts */
const accounts: Map<string, Account> = new Map([
  ['acct-001', {
    id: 'acct-001',
    name: 'Primary Checking',
    type: 'checking',
    balance: 5000,
    currency: 'USD',
    ownerId: 'user-1'
  }],
  ['acct-002', {
    id: 'acct-002',
    name: 'Savings Account',
    type: 'savings',
    balance: 25000,
    currency: 'USD',
    ownerId: 'user-1'
  }],
  ['acct-003', {
    id: 'acct-003',
    name: 'Investment Portfolio',
    type: 'investment',
    balance: 100000,
    currency: 'USD',
    ownerId: 'user-1'
  }],
  ['acct-004', {
    id: 'acct-004',
    name: 'EUR Account',
    type: 'checking',
    balance: 3000,
    currency: 'EUR',
    ownerId: 'user-1'
  }],
  ['acct-ext-001', {
    id: 'acct-ext-001',
    name: 'External Transfer Dest',
    type: 'checking',
    balance: 0,
    currency: 'USD',
    ownerId: 'external'
  }],
]);

/** Transaction history */
const transactions: Transaction[] = [];

/** Get account by ID */
export function getAccount(accountId: string): Account | undefined {
  return accounts.get(accountId);
}

/** Get all accounts for an owner */
export function getAllAccounts(ownerId: string = 'user-1'): Account[] {
  return Array.from(accounts.values()).filter(a => a.ownerId === ownerId);
}

/** Update account balance */
export function updateBalance(accountId: string, delta: number): boolean {
  const account = accounts.get(accountId);
  if (!account) return false;
  account.balance += delta;
  return true;
}

/** Record a transaction */
export function recordTransaction(tx: Omit<Transaction, 'createdAt' | 'completedAt'>): Transaction {
  const transaction: Transaction = {
    ...tx,
    createdAt: Date.now(),
    completedAt: tx.status === 'completed' ? Date.now() : undefined,
  };
  transactions.push(transaction);
  return transaction;
}

/** Get transaction history for an account */
export function getTransactionHistory(accountId: string): Transaction[] {
  return transactions.filter(
    t => t.fromAccountId === accountId || t.toAccountId === accountId
  );
}

/** Get all transactions */
export function getAllTransactions(): Transaction[] {
  return [...transactions];
}

/** Get transaction by ID */
export function getTransaction(transactionId: string): Transaction | undefined {
  return transactions.find(t => t.id === transactionId);
}

/** Reset mock data (for testing) */
export function resetMockData(): void {
  // Reset account balances
  accounts.set('acct-001', { ...accounts.get('acct-001')!, balance: 5000 });
  accounts.set('acct-002', { ...accounts.get('acct-002')!, balance: 25000 });
  accounts.set('acct-003', { ...accounts.get('acct-003')!, balance: 100000 });
  accounts.set('acct-004', { ...accounts.get('acct-004')!, balance: 3000 });
  accounts.set('acct-ext-001', { ...accounts.get('acct-ext-001')!, balance: 0 });

  // Clear transaction history
  transactions.length = 0;
}
