/**
 * @fileoverview Request normalization utilities for MCP messages.
 * Converts various request formats into consistent JSON-RPC structure.
 */

/**
 * Map of SDK-specific request types to MCP methods
 */
const SDK_METHOD_MAP = {
    'tools/call': 'tools/call',
    'tools/list': 'tools/list',
    'resources/read': 'resources/read',
    'resources/list': 'resources/list',
    'prompts/get': 'prompts/get',
    'prompts/list': 'prompts/list',
    'initialize': 'initialize',
    'ping': 'ping'
};

/**
 * Normalize different request formats into consistent JSON-RPC structure.
 * Handles: JSON-RPC messages, SDK request objects, HTTP requests, raw objects.
 *
 * @param {Object} request - The request to normalize
 * @returns {Object} Normalized JSON-RPC message
 */
export function normalizeRequest(request) {
    // Case 1: Already a JSON-RPC message
    if (request.jsonrpc && request.method) {
        return request;
    }

    // Case 2: Official SDK request object (CallToolRequest, etc.)
    if (request.method && request.params) {
        return {
            jsonrpc: "2.0",
            method: mapSdkMethod(request.method),
            params: request.params,
            id: request.id || generateRequestId()
        };
    }

    // Case 3: HTTP request body
    if (request.body && typeof request.body === 'object') {
        return request.body;
    }

    // Case 4: Raw object - convert to JSON-RPC format
    return {
        jsonrpc: "2.0",
        method: request.method || "unknown",
        params: request.params || request,
        id: request.id || generateRequestId()
    };
}

/**
 * Map SDK-specific request types to MCP methods.
 * @param {string} method - SDK method name
 * @returns {string} MCP method name
 */
export function mapSdkMethod(method) {
    return SDK_METHOD_MAP[method] || method;
}

/**
 * Generate a random request ID.
 * @returns {string} Random ID string
 */
function generateRequestId() {
    return Math.random().toString(36);
}
