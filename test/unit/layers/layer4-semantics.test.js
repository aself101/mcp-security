import { describe, it, expect, beforeEach } from 'vitest';
import SemanticsValidationLayer from '@/security/layers/layer4-semantics.js';

describe('Semantics Validation Layer', () => {
  let layer;

  beforeEach(() => {
    // Use the default policies which are well-configured
    // The default policies already include:
    // - denyGlobs for *.key, *.pem, .env, id_rsa, etc.
    // - rootDirs pointing to test-data
    layer = new SemanticsValidationLayer({
      toolRegistry: [
        {
          name: 'allowed-tool',
          sideEffects: 'none',
          argsShape: { input: { type: 'string' } }
        },
        {
          name: 'read-file',
          sideEffects: 'read',
          argsShape: { path: { type: 'string' } }
        },
        {
          name: 'write-file',
          sideEffects: 'write',
          argsShape: {
            path: { type: 'string' },
            content: { type: 'string' }
          }
        },
        {
          name: 'egress-limited-tool',
          sideEffects: 'none',
          maxEgressBytes: 1000000,
          argsShape: { data: { type: 'object' } }
        }
      ]
      // Let resourcePolicy use defaults which have properly configured paths
    });
  });

  describe('Method Validation', () => {
    it('should pass valid MCP methods', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'allowed-tool', arguments: { input: 'test' } }
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(true);
    });

    it('should reject unknown methods', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'unknown/dangerous',
        id: 1
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/unknown|disallowed/i);
    });

    it('should reject messages without method', async () => {
      const message = { jsonrpc: '2.0', id: 1 };
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Tool Contract Enforcement', () => {
    it('should pass when tool is registered', async () => {
      const message = createToolCallMessage('allowed-tool', { input: 'test data' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should reject calls to unregistered tools', async () => {
      const message = createToolCallMessage('unregistered-tool', { data: 'test' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/not.*allowed|unknown/i);
    });

    it('should validate args shape when defined', async () => {
      // allowed-tool expects { input: string }
      const message = createToolCallMessage('allowed-tool', { wrong: 'field' });
      const result = await layer.validate(message, {});

      // Should fail because 'input' is missing
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/input|required|missing/i);
    });
  });

  describe('Resource Access Policies', () => {
    it('should block reading outside allowed roots', async () => {
      // /etc/passwd is definitely outside test-data root
      const message = {
        jsonrpc: '2.0',
        method: 'resources/read',
        id: 1,
        params: { uri: 'file:///etc/passwd' }
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/not.*under.*allowed|root/i);
    });

    it('should block non-file schemes', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'resources/read',
        id: 1,
        params: { uri: 'http://evil.com/malware' }
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/scheme.*not.*allowed/i);
    });

    it('should block reading .key files (deny glob)', async () => {
      // Uses deny glob pattern **/*.key
      const message = {
        jsonrpc: '2.0',
        method: 'resources/read',
        id: 1,
        params: { uri: 'file:///proc/self/creds.key' }
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
    });

    it('should block reading /proc paths (deny glob)', async () => {
      // Uses deny glob pattern /proc/**
      const message = {
        jsonrpc: '2.0',
        method: 'resources/read',
        id: 1,
        params: { uri: 'file:///proc/self/environ' }
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
    });

    it('should block reading .env files (deny glob)', async () => {
      // Uses deny glob pattern **/.env
      const message = {
        jsonrpc: '2.0',
        method: 'resources/read',
        id: 1,
        params: { uri: 'file:///var/app/.env' }
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
    });
  });

  describe('Side Effects and Egress Detection', () => {
    it('should block write tools without permission', async () => {
      // write-file requires policy.allowWrites
      const message = createToolCallMessage('write-file', {
        path: '/tmp/output.txt',
        content: 'data'
      });

      // Without allowWrites in context, should fail
      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/write.*permission|requires.*write/i);
    });

    it('should allow write tools with permission', async () => {
      const message = createToolCallMessage('write-file', {
        path: '/tmp/output.txt',
        content: 'data'
      });

      // With allowWrites in context, should pass
      const result = await layer.validate(message, { policy: { allowWrites: true } });
      expect(result.passed).toBe(true);
    });

    it('should pass read operations for registered tools', async () => {
      const message = createToolCallMessage('read-file', {
        path: '/some/file.txt'
      });

      // read-file has sideEffects: 'read' which is always allowed
      const result = await layer.validate(message, {});
      expect(result.passed).toBe(true);
    });
  });

  describe('Valid Semantic Patterns', () => {
    it('should pass initialize method', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'initialize',
        id: 1,
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'test', version: '1.0' }
        }
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(true);
    });

    it('should pass tools/list method', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/list',
        id: 1
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(true);
    });

    it('should pass resources/list method', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'resources/list',
        id: 1
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle null message', async () => {
      const result = await layer.validate(null, {});
      expect(result.passed).toBe(false);
    });

    it('should handle message with null params', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: null
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
    });

    it('should handle tools/call without tool name', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {}
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
    });

    it('should handle circular reference in tool arguments (safeSizeOrFail)', async () => {
      // Create a circular reference that will cause JSON.stringify to fail
      const circularObj = { name: 'test' };
      circularObj.self = circularObj;

      // Use egress-limited-tool which has maxEgressBytes, triggering safeSizeOrFail
      const message = createToolCallMessage('egress-limited-tool', { data: circularObj });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('ARG_SERIALIZATION_ERROR');
      expect(result.reason).toMatch(/serialization error/i);
    });

    it('should report policy validation failure with proper fields (wrapPolicyResult)', async () => {
      // Trigger a policy validation failure - accessing outside allowed roots
      const message = {
        jsonrpc: '2.0',
        method: 'resources/read',
        id: 1,
        params: { uri: 'file:///etc/shadow' }
      };

      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.severity).toBeDefined();
      expect(result.reason).toBeDefined();
      expect(result.reason.length).toBeGreaterThan(0);
    });
  });
});

function createToolCallMessage(toolName, args = {}) {
  return {
    jsonrpc: '2.0',
    method: 'tools/call',
    id: 1,
    params: {
      name: toolName,
      arguments: args
    }
  };
}

describe('Method Chaining Validation', () => {
  let layer;

  beforeEach(() => {
    layer = new SemanticsValidationLayer({
      enforceChaining: true,
      toolRegistry: [
        { name: 'test-tool', sideEffects: 'none' }
      ]
    });
  });

  it('should be disabled by default', async () => {
    const defaultLayer = new SemanticsValidationLayer({
      toolRegistry: [{ name: 'test-tool', sideEffects: 'none' }]
    });

    // Calling tools/list without initialize should pass when chaining disabled
    const message = { jsonrpc: '2.0', method: 'tools/list', id: 1 };
    const result = await defaultLayer.validate(message, { sessionId: 'default-test' });
    expect(result.passed).toBe(true);
  });

  it('should allow initialize as first method', async () => {
    const message = {
      jsonrpc: '2.0',
      method: 'initialize',
      id: 1,
      params: {}
    };

    const result = await layer.validate(message, { sessionId: 'init-test' });
    expect(result.passed).toBe(true);
  });

  it('should block tools/list before initialize', async () => {
    const message = { jsonrpc: '2.0', method: 'tools/list', id: 1 };

    const result = await layer.validate(message, { sessionId: 'chain-test-1' });
    expect(result.passed).toBe(false);
    expect(result.violationType).toBe('CHAIN_VIOLATION');
    expect(result.reason).toMatch(/Method chaining not allowed.*\*.*tools\/list/);
  });

  it('should allow tools/list after initialize', async () => {
    const sessionId = 'chain-test-2';

    // First: initialize
    const initMsg = { jsonrpc: '2.0', method: 'initialize', id: 1, params: {} };
    const initResult = await layer.validate(initMsg, { sessionId });
    expect(initResult.passed).toBe(true);

    // Then: tools/list
    const listMsg = { jsonrpc: '2.0', method: 'tools/list', id: 2 };
    const listResult = await layer.validate(listMsg, { sessionId });
    expect(listResult.passed).toBe(true);
  });

  it('should allow tools/call after tools/list', async () => {
    const sessionId = 'chain-test-3';

    // initialize → tools/list → tools/call
    await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, { sessionId });
    await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, { sessionId });

    const callMsg = createToolCallMessage('test-tool');
    const result = await layer.validate(callMsg, { sessionId });
    expect(result.passed).toBe(true);
  });

  it('should allow repeated tools/call', async () => {
    const sessionId = 'chain-test-4';

    // initialize → tools/list → tools/call → tools/call
    await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, { sessionId });
    await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, { sessionId });
    await layer.validate(createToolCallMessage('test-tool'), { sessionId });

    const result = await layer.validate(createToolCallMessage('test-tool'), { sessionId });
    expect(result.passed).toBe(true);
  });

  it('should allow ping from any state', async () => {
    const sessionId = 'ping-test';

    // ping is allowed from * (any state)
    const pingMsg = { jsonrpc: '2.0', method: 'ping', id: 1 };
    const result = await layer.validate(pingMsg, { sessionId });
    expect(result.passed).toBe(true);
  });

  it('should track sessions independently', async () => {
    // Session A initializes
    await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, { sessionId: 'session-a' });

    // Session B tries tools/list without initialize - should fail
    const result = await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 1 }, { sessionId: 'session-b' });
    expect(result.passed).toBe(false);
    expect(result.violationType).toBe('CHAIN_VIOLATION');
  });

  it('should use clientId as fallback for session key', async () => {
    // Using clientId instead of sessionId
    await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, { clientId: 'client-1' });
    const result = await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, { clientId: 'client-1' });
    expect(result.passed).toBe(true);
  });
});
