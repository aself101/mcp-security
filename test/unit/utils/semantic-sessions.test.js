import { describe, it, expect, beforeEach } from 'vitest';
import { SessionMemory } from '@/security/layers/layer-utils/semantics/semantic-sessions.js';

describe('SessionMemory', () => {
    let sessionMemory;

    beforeEach(() => {
        sessionMemory = new SessionMemory({ maxEntries: 5, ttlMs: 1000 });
    });

    describe('constructor', () => {
        it('should use default values when no options provided', () => {
            const defaultMemory = new SessionMemory();
            expect(defaultMemory.maxEntries).toBe(5000);
            expect(defaultMemory.ttlMs).toBe(30 * 60_000);
        });

        it('should use custom values when provided', () => {
            expect(sessionMemory.maxEntries).toBe(5);
            expect(sessionMemory.ttlMs).toBe(1000);
        });
    });

    describe('set and get', () => {
        it('should store and retrieve a method', () => {
            sessionMemory.set('session1', 'initialize');
            expect(sessionMemory.get('session1')).toBe('initialize');
        });

        it('should return undefined for non-existent key', () => {
            expect(sessionMemory.get('nonexistent')).toBeUndefined();
        });

        it('should update existing entry', () => {
            sessionMemory.set('session1', 'initialize');
            sessionMemory.set('session1', 'tools/list');
            expect(sessionMemory.get('session1')).toBe('tools/list');
        });

        it('should return undefined for expired entries', () => {
            const now = Date.now();
            sessionMemory.set('session1', 'initialize', now);
            // Access after TTL has passed
            expect(sessionMemory.get('session1', now + 2000)).toBeUndefined();
        });

        it('should refresh LRU position on get', () => {
            sessionMemory.set('session1', 'method1');
            sessionMemory.set('session2', 'method2');
            sessionMemory.set('session3', 'method3');

            // Access session1 to refresh its position
            sessionMemory.get('session1');

            // Fill up to max and add one more
            sessionMemory.set('session4', 'method4');
            sessionMemory.set('session5', 'method5');
            sessionMemory.set('session6', 'method6');

            // session1 should still exist (was refreshed)
            // session2 should be evicted (oldest after session1's refresh)
            expect(sessionMemory.get('session1')).toBe('method1');
            expect(sessionMemory.get('session2')).toBeUndefined();
        });
    });

    describe('has', () => {
        it('should return true for existing non-expired entry', () => {
            sessionMemory.set('session1', 'initialize');
            expect(sessionMemory.has('session1')).toBe(true);
        });

        it('should return false for non-existent key', () => {
            expect(sessionMemory.has('nonexistent')).toBe(false);
        });

        it('should return false for expired entry and delete it', () => {
            const now = Date.now();
            sessionMemory.set('session1', 'initialize', now);
            expect(sessionMemory.has('session1', now + 2000)).toBe(false);
            // Entry should be deleted
            expect(sessionMemory.map.has('session1')).toBe(false);
        });
    });

    describe('delete', () => {
        it('should delete an existing entry', () => {
            sessionMemory.set('session1', 'initialize');
            expect(sessionMemory.delete('session1')).toBe(true);
            expect(sessionMemory.get('session1')).toBeUndefined();
        });

        it('should return false when deleting non-existent entry', () => {
            expect(sessionMemory.delete('nonexistent')).toBe(false);
        });
    });

    describe('clear', () => {
        it('should remove all entries', () => {
            sessionMemory.set('session1', 'method1');
            sessionMemory.set('session2', 'method2');
            sessionMemory.set('session3', 'method3');

            sessionMemory.clear();

            expect(sessionMemory.size()).toBe(0);
            expect(sessionMemory.get('session1')).toBeUndefined();
        });
    });

    describe('size', () => {
        it('should return current number of entries', () => {
            expect(sessionMemory.size()).toBe(0);

            sessionMemory.set('session1', 'method1');
            expect(sessionMemory.size()).toBe(1);

            sessionMemory.set('session2', 'method2');
            expect(sessionMemory.size()).toBe(2);
        });
    });

    describe('LRU eviction', () => {
        it('should evict oldest entry when max is reached', () => {
            sessionMemory.set('session1', 'method1');
            sessionMemory.set('session2', 'method2');
            sessionMemory.set('session3', 'method3');
            sessionMemory.set('session4', 'method4');
            sessionMemory.set('session5', 'method5');

            // At max capacity
            expect(sessionMemory.size()).toBe(5);

            // Add one more, should evict session1 (oldest)
            sessionMemory.set('session6', 'method6');

            expect(sessionMemory.size()).toBe(5);
            expect(sessionMemory.get('session1')).toBeUndefined();
            expect(sessionMemory.get('session6')).toBe('method6');
        });
    });

    describe('cleanup', () => {
        it('should remove expired sessions', () => {
            const now = Date.now();
            sessionMemory.set('active1', 'method1', now);
            sessionMemory.set('active2', 'method2', now);
            sessionMemory.set('expired1', 'method3', now - 2000);
            sessionMemory.set('expired2', 'method4', now - 2000);

            const removed = sessionMemory.cleanup(now);

            expect(removed).toBe(2);
            expect(sessionMemory.size()).toBe(2);
            expect(sessionMemory.get('active1', now)).toBe('method1');
            expect(sessionMemory.get('expired1', now)).toBeUndefined();
        });

        it('should return 0 when no expired sessions', () => {
            sessionMemory.set('session1', 'method1');
            const removed = sessionMemory.cleanup();
            expect(removed).toBe(0);
        });
    });

    describe('getActiveSessions', () => {
        it('should return only active session keys', () => {
            const now = Date.now();
            sessionMemory.set('active1', 'method1', now);
            sessionMemory.set('active2', 'method2', now);
            sessionMemory.set('expired1', 'method3', now - 2000);

            const active = sessionMemory.getActiveSessions(now);

            expect(active).toHaveLength(2);
            expect(active).toContain('active1');
            expect(active).toContain('active2');
            expect(active).not.toContain('expired1');
        });

        it('should return empty array when no sessions', () => {
            expect(sessionMemory.getActiveSessions()).toEqual([]);
        });
    });

    describe('getStats', () => {
        it('should return correct statistics', () => {
            const now = Date.now();
            sessionMemory.set('active1', 'method1', now);
            sessionMemory.set('active2', 'method2', now);
            sessionMemory.set('expired1', 'method3', now - 2000);

            const stats = sessionMemory.getStats(now);

            expect(stats.total).toBe(3);
            expect(stats.active).toBe(2);
            expect(stats.expired).toBe(1);
            expect(stats.maxEntries).toBe(5);
            expect(stats.ttlMs).toBe(1000);
            expect(stats.utilizationPercent).toBe(60);
        });

        it('should return zeros for empty session memory', () => {
            const stats = sessionMemory.getStats();

            expect(stats.total).toBe(0);
            expect(stats.active).toBe(0);
            expect(stats.expired).toBe(0);
            expect(stats.utilizationPercent).toBe(0);
        });
    });

    describe('createSessionKey', () => {
        it('should use sessionId when available', () => {
            const key = SessionMemory.createSessionKey({ sessionId: 'session-123' });
            expect(key).toBe('session-123');
        });

        it('should fall back to clientId when sessionId not available', () => {
            const key = SessionMemory.createSessionKey({ clientId: 'client-456' });
            expect(key).toBe('client-456');
        });

        it('should return global when no identifiers available', () => {
            const key = SessionMemory.createSessionKey({});
            expect(key).toBe('global');
        });

        it('should return global for null/undefined context', () => {
            expect(SessionMemory.createSessionKey(null)).toBe('global');
            expect(SessionMemory.createSessionKey(undefined)).toBe('global');
        });

        it('should prefer sessionId over clientId', () => {
            const key = SessionMemory.createSessionKey({
                sessionId: 'session-123',
                clientId: 'client-456'
            });
            expect(key).toBe('session-123');
        });
    });
});
