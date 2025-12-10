/**
 * MCP Security Framework - Universal security middleware for MCP servers.
 * Provides multi-layered defense against traditional attacks and AI-driven threats.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

// Validation Result Types
export interface ValidationResult {
    passed: boolean;
    allowed?: boolean;
    reason?: string;
    severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    violationType?: string;
    confidence?: number;
    detectionLayer?: string;
    validatorSource?: string;
    timestamp?: number;
}

// Server Info
export interface ServerInfo {
    name: string;
    version: string;
}

// Security Options
export interface SecurityOptions {
    /** McpServer options passed to underlying SDK */
    server?: Record<string, unknown>;
    /** Maximum message size in bytes (default: 50000) */
    maxMessageSize?: number;
    /** Rate limit per minute (default: 30) */
    maxRequestsPerMinute?: number;
    /** Rate limit per hour (default: 500) */
    maxRequestsPerHour?: number;
    /** Max requests in 10-second window (default: 10) */
    burstThreshold?: number;
    /** Enable security logging - opt-in (default: false) */
    enableLogging?: boolean;
    /** Enable verbose decision logs (default: false) */
    verboseLogging?: boolean;
    /** Enable timing statistics (default: false) */
    logPerformanceMetrics?: boolean;
    /** Log level when logging enabled (default: 'info') */
    logLevel?: 'debug' | 'info' | 'warn' | 'error';
    /** Custom tool registry for Layer 4 */
    toolRegistry?: unknown;
    /** Custom resource policy for Layer 4 */
    resourcePolicy?: unknown;
    /** Maximum concurrent sessions (default: 5000) */
    maxSessions?: number;
    /** Session TTL in ms (default: 1800000 / 30 min) */
    sessionTtlMs?: number;
    /** Layer 5 contextual validation config */
    contextual?: ContextualOptions;
    /** Default policy for side effects */
    defaultPolicy?: {
        allowNetwork?: boolean;
        allowWrites?: boolean;
    };
}

// Contextual (Layer 5) Options
export interface ContextualOptions {
    /** Enable Layer 5 (default: true) */
    enabled?: boolean;
    /** OAuth URL validation config */
    oauthValidation?: OAuthValidationOptions;
    /** Domain restriction config */
    domainRestrictions?: DomainRestrictionsOptions;
    /** Per-tool rate limiting config */
    rateLimiting?: RateLimitingOptions;
    /** Response validation config */
    responseValidation?: ResponseValidationOptions;
}

export interface OAuthValidationOptions {
    enabled?: boolean;
    allowedDomains?: string[];
    blockDangerousSchemes?: boolean;
}

export interface DomainRestrictionsOptions {
    enabled?: boolean;
    allowedDomains?: string[];
    blockedDomains?: string[];
}

export interface RateLimitingOptions {
    enabled?: boolean;
    limit?: number;
    windowMs?: number;
}

export interface ResponseValidationOptions {
    enabled?: boolean;
    blockSensitiveData?: boolean;
}

// Validator Function Types
export type ValidatorFunction = (
    message: Record<string, unknown>,
    context: Record<string, unknown>
) => ValidationResult | Promise<ValidationResult>;

export type ResponseValidatorFunction = (
    response: Record<string, unknown>,
    request: Record<string, unknown>,
    context: Record<string, unknown>
) => ValidationResult | Promise<ValidationResult>;

export type GlobalRuleFunction = (
    message: Record<string, unknown>,
    context: Record<string, unknown>
) => ValidationResult | null | Promise<ValidationResult | null>;

export interface ValidatorOptions {
    enabled?: boolean;
    priority?: number;
    skipOnSuccess?: boolean;
    failOnError?: boolean;
}

// Security Stats
export interface SecurityStats {
    server: {
        uptime: number;
        totalLayers: number;
        enabledLayers: number;
        loggingEnabled: boolean;
    };
    behaviorLayer?: unknown;
    logger?: unknown;
}

/**
 * Drop-in replacement for McpServer with built-in 5-layer security.
 * All incoming messages are validated before reaching handlers.
 */
export class SecureMcpServer {
    constructor(serverInfo: ServerInfo, options?: SecurityOptions);

    /** Connect with automatic security wrapping */
    connect(transport: Transport): Promise<void>;

    /** Close the server connection */
    close(): Promise<void>;

    /** Check if server is connected */
    isConnected(): boolean;

    /** Register a tool */
    tool(name: string, ...args: unknown[]): unknown;

    /** Register a tool with config */
    registerTool(name: string, config: unknown, callback: unknown): unknown;

    /** Register a resource */
    resource(name: string, uriOrTemplate: string, ...args: unknown[]): unknown;

    /** Register a resource with config */
    registerResource(name: string, uriOrTemplate: string, config: unknown, callback: unknown): unknown;

    /** Register a prompt */
    prompt(name: string, ...args: unknown[]): unknown;

    /** Register a prompt with config */
    registerPrompt(name: string, config: unknown, callback: unknown): unknown;

    /** Send logging message */
    sendLoggingMessage(params: unknown, sessionId?: string): Promise<void>;

    /** Notify resource list changed */
    sendResourceListChanged(): void;

    /** Notify tool list changed */
    sendToolListChanged(): void;

    /** Notify prompt list changed */
    sendPromptListChanged(): void;

    /** Get security statistics */
    getSecurityStats(): SecurityStats;

    /** Get verbose security report (requires logging enabled) */
    getVerboseSecurityReport(): unknown;

    /** Generate full security report (requires logging enabled) */
    generateSecurityReport(): Promise<unknown>;

    /** Graceful shutdown with optional final report */
    shutdown(): Promise<unknown>;

    /** Access underlying McpServer */
    readonly mcpServer: McpServer;

    /** Access underlying Server */
    readonly server: unknown;

    /** Access validation pipeline */
    readonly validationPipeline: unknown;
}

/**
 * Transport wrapper for message-level validation.
 * Intercepts all messages and validates before delivery.
 */
export class SecureTransport {
    constructor(
        transport: Transport,
        validator: (message: unknown, context: unknown) => Promise<ValidationResult>,
        options?: { errorSanitizer?: unknown }
    );

    /** Start the transport */
    start(): Promise<void>;

    /** Close the transport */
    close(): Promise<void>;

    /** Send a message */
    send(message: unknown): Promise<void>;

    /** Set message handler */
    set onmessage(handler: ((message: unknown, extra?: unknown) => void) | null);

    /** Set error handler */
    set onerror(handler: ((error: Error) => void) | null);

    /** Set close handler */
    set onclose(handler: (() => void) | null);

    /** Get session ID */
    readonly sessionId?: string;
}

/**
 * Layer 5 contextual validation layer.
 * Provides extensible validation with custom validators, domain restrictions, and more.
 */
export class ContextualValidationLayer {
    constructor(options?: ContextualOptions);

    /** Map of registered validators */
    readonly validators: Map<string, { validate: ValidatorFunction; options: ValidatorOptions }>;

    /** Map of registered response validators */
    readonly responseValidators: Map<string, { validate: ResponseValidatorFunction; options: ValidatorOptions }>;

    /** Array of global rules */
    readonly globalRules: Array<{ validate: GlobalRuleFunction; options: ValidatorOptions }>;

    /**
     * Register a custom validation function
     * @param name - Validator identifier
     * @param validator - Validation function
     * @param options - Validator options
     */
    addValidator(name: string, validator: ValidatorFunction, options?: ValidatorOptions): void;

    /**
     * Register response validation (for MCP server responses)
     * @param name - Validator identifier
     * @param validator - Response validation function
     * @param options - Validator options
     */
    addResponseValidator(name: string, validator: ResponseValidatorFunction, options?: ValidatorOptions): void;

    /**
     * Add global validation rules that apply to all requests
     * @param rule - Global rule function
     * @param options - Rule options
     */
    addGlobalRule(rule: GlobalRuleFunction, options?: ValidatorOptions): void;

    /**
     * Validate a message
     * @param message - The message to validate
     * @param context - Validation context
     */
    validate(message: Record<string, unknown>, context?: Record<string, unknown>): Promise<ValidationResult>;

    /**
     * Validate server responses
     * @param response - The response to validate
     * @param request - The original request
     * @param context - Validation context
     */
    validateResponse(
        response: Record<string, unknown>,
        request: Record<string, unknown>,
        context?: Record<string, unknown>
    ): Promise<ValidationResult>;

    /**
     * Store contextual data with TTL
     * @param key - Storage key
     * @param value - Value to store
     * @param ttl - Time to live in ms (default: 300000 / 5 min)
     */
    setContext(key: string, value: unknown, ttl?: number): void;

    /**
     * Retrieve stored contextual data
     * @param key - Storage key
     */
    getContext(key: string): unknown | null;
}

/**
 * Builder for Layer 5 configuration.
 * Provides fluent API for common configuration scenarios.
 */
export class ContextualConfigBuilder {
    constructor();

    /**
     * Enable OAuth URL validation
     * @param allowedDomains - List of allowed domains
     */
    enableOAuthValidation(allowedDomains?: string[]): this;

    /**
     * Enable rate limiting
     * @param limit - Max requests in window (default: 10)
     * @param windowMs - Time window in ms (default: 60000)
     */
    enableRateLimiting(limit?: number, windowMs?: number): this;

    /**
     * Enable response validation
     * @param options - Response validation options
     */
    enableResponseValidation(options?: ResponseValidationOptions): this;

    /**
     * Build the configuration object
     */
    build(): ContextualOptions;
}

/**
 * Factory function to create a Layer 5 contextual validation layer with defaults.
 * @param customConfig - Custom configuration to merge with defaults
 * @returns Configured ContextualValidationLayer instance
 */
export function createContextualLayer(customConfig?: ContextualOptions): ContextualValidationLayer;
