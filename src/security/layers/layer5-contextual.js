/**
 * @fileoverview Layer 5 - User-configurable contextual validation layer.
 * Handles complex scenarios without bloating core framework.
 */

import { ValidationLayer } from './validation-layer-base.js';
import { ContextualConfigBuilder } from './contextual-config-builder.js';

export default class ContextualValidationLayer extends ValidationLayer {
    constructor(options = {}) {
        super(options);
        
        this.validators = new Map();
        this.responseValidators = new Map();
        this.globalRules = [];
        this.contextStore = new Map();
        
        // Configure built-in validators
        this.setupBuiltinValidators(options);
        
        this.logDebug('Contextual Validation Layer initialized');
    }

    /**
     * Register custom validation functions
     * @param {string} name - Validator identifier
     * @param {Function} validator - (message, context) => ValidationResult | Promise<ValidationResult>
     * @param {Object} options - Validator options
     */
    addValidator(name, validator, options = {}) {
        if (typeof validator !== 'function') {
            throw new Error(`Validator ${name} must be a function`);
        }
        
        this.validators.set(name, {
            validate: validator,
            options: {
                enabled: true,
                priority: 100,
                skipOnSuccess: false,
                ...options
            }
        });
    }

    /**
     * Register response validation (for MCP server responses)
     * @param {string} name - Validator identifier  
     * @param {Function} validator - (response, request, context) => ValidationResult
     */
    addResponseValidator(name, validator, options = {}) {
        this.responseValidators.set(name, {
            validate: validator,
            options: { enabled: true, ...options }
        });
    }

    /**
     * Add global validation rules that apply to all requests
     * @param {Function} rule - (message, context) => ValidationResult | null
     */
    addGlobalRule(rule, options = {}) {
        this.globalRules.push({
            validate: rule,
            options: { enabled: true, priority: 0, ...options }
        });
    }

    async validate(message, context = {}) {
        // Run global rules first
        for (const { validate, options } of this.globalRules) {
            if (!options.enabled) continue;
            
            try {
                const result = await validate(message, context);
                if (result && !result.passed) {
                    return this.enhanceResult(result, 'global_rule');
                }
            } catch (error) {
                // Global rules are user-provided - log but don't fail validation
                this.logDebug(`Global rule error: ${error.message}`);
                // Continue to next rule
            }
        }

        // Run custom validators in priority order
        const sortedValidators = Array.from(this.validators.entries())
            .filter(([_, { options }]) => options.enabled)
            .sort(([_, a], [__, b]) => (a.options.priority || 100) - (b.options.priority || 100));

        for (const [name, { validate, options }] of sortedValidators) {
            try {
                const result = await validate(message, context);
                if (result && !result.passed) {
                    return this.enhanceResult(result, `validator:${name}`);
                }
                
                if (options.skipOnSuccess && result?.passed) {
                    break;
                }
            } catch (error) {
                // User validators may throw - handle gracefully
                this.logDebug(`Validator ${name} error: ${error.message}`);

                if (options.failOnError) {
                    return this.createFailureResult(
                        `Validator ${name} failed: ${error.message}`,
                        'MEDIUM',
                        'VALIDATOR_ERROR'
                    );
                }
                // Continue to next validator if failOnError is not set
            }
        }

        return this.createSuccessResult();
    }

    /**
     * Validate server responses (if enabled)
     */
    async validateResponse(response, request, context = {}) {
        if (this.responseValidators.size === 0) {
            return this.createSuccessResult();
        }

        for (const [name, { validate, options }] of this.responseValidators) {
            if (!options.enabled) continue;

            try {
                const result = await validate(response, request, context);
                if (result && !result.passed) {
                    return this.enhanceResult(result, `response_validator:${name}`);
                }
            } catch (error) {
                // Response validators are user-provided - log but don't fail
                this.logDebug(`Response validator ${name} error: ${error.message}`);
                // Continue to next validator
            }
        }

        return this.createSuccessResult();
    }

    /**
     * Store and retrieve contextual data across requests
     */
    setContext(key, value, ttl = 300000) { // 5 min default TTL
        this.contextStore.set(key, {
            value,
            expires: Date.now() + ttl
        });
    }

    getContext(key) {
        const entry = this.contextStore.get(key);
        if (!entry) return null;
        
        if (Date.now() > entry.expires) {
            this.contextStore.delete(key);
            return null;
        }
        
        return entry.value;
    }

    /**
     * Built-in validators for common scenarios
     */
    setupBuiltinValidators(options) {
        // OAuth URL validation (if user enables it)
        if (options.oauthValidation?.enabled) {
            this.addValidator('oauth_urls',
                (message, _context) => this.validateOAuthUrls(message, options.oauthValidation),
                { priority: 50 }
            );
        }

        // Rate limiting by tool/method
        if (options.rateLimiting?.enabled) {
            this.addValidator('rate_limiting',
                (message, _context) => this.validateRateLimit(message, _context, options.rateLimiting),
                { priority: 10 }
            );
        }

        // Domain restrictions
        if (options.domainRestrictions?.enabled) {
            this.addValidator('domain_restrictions',
                (message, _context) => this.validateDomainRestrictions(message, options.domainRestrictions),
                { priority: 30 }
            );
        }

        // Response validation for server output
        if (options.responseValidation?.enabled) {
            this.addResponseValidator('malicious_content',
                (response, _request, _context) => this.validateResponseContent(response, options.responseValidation)
            );
        }
    }

    // Built-in validator implementations
    validateOAuthUrls(message, config) {
        const urls = this.extractUrls(JSON.stringify(message));
        const { allowedDomains = [], blockDangerousSchemes = true } = config;

        for (const url of urls) {
            if (blockDangerousSchemes) {
                if (/^(javascript|vbscript|data):/i.test(url)) {
                    return this.createFailureResult(
                        `Dangerous URL scheme detected: ${url}`,
                        'HIGH',
                        'DANGEROUS_URL_SCHEME'
                    );
                }
            }

            if (allowedDomains.length > 0) {
                const isAllowed = allowedDomains.some(domain => 
                    url.includes(domain) || new URL(url).hostname.endsWith(domain)
                );
                
                if (!isAllowed) {
                    return this.createFailureResult(
                        `URL not in allowed domains: ${url}`,
                        'MEDIUM',
                        'DOMAIN_RESTRICTION_VIOLATION'
                    );
                }
            }
        }

        return this.createSuccessResult();
    }

    validateRateLimit(message, context, config) {
        const key = `${context.sessionId || 'anonymous'}:${message.method}`;
        const history = this.getContext(key) || [];
        const now = Date.now();
        const windowMs = config.windowMs || 60000;
        
        // Clean old entries
        const recentRequests = history.filter(time => now - time < windowMs);
        
        if (recentRequests.length >= (config.limit || 10)) {
            return this.createFailureResult(
                `Rate limit exceeded for ${message.method}`,
                'HIGH',
                'RATE_LIMIT_EXCEEDED'
            );
        }

        // Update history
        recentRequests.push(now);
        this.setContext(key, recentRequests, windowMs);

        return this.createSuccessResult();
    }

    validateDomainRestrictions(message, config) {
        const content = JSON.stringify(message);
        const urls = this.extractUrls(content);
        const { allowedDomains = [], blockedDomains = [] } = config;

        for (const url of urls) {
            try {
                const hostname = new URL(url).hostname;

                // Check blocked domains first
                if (blockedDomains.length > 0) {
                    const isBlocked = blockedDomains.some(domain =>
                        hostname === domain || hostname.endsWith(`.${domain}`)
                    );
                    if (isBlocked) {
                        return this.createFailureResult(
                            `Domain blocked by policy: ${hostname}`,
                            'HIGH',
                            'BLOCKED_DOMAIN'
                        );
                    }
                }

                // Check allowed domains if configured
                if (allowedDomains.length > 0) {
                    const isAllowed = allowedDomains.some(domain =>
                        hostname === domain || hostname.endsWith(`.${domain}`)
                    );
                    if (!isAllowed) {
                        return this.createFailureResult(
                            `Domain not in allowlist: ${hostname}`,
                            'MEDIUM',
                            'DOMAIN_NOT_ALLOWED'
                        );
                    }
                }
            } catch (_e) {
                // Invalid URL - skip domain check
            }
        }

        return this.createSuccessResult();
    }

    validateResponseContent(response, config) {
        const content = JSON.stringify(response);
        
        // Check for sensitive data in responses
        if (config.blockSensitiveData) {
            const patterns = [
                /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, // emails
                /\b\d{3}-\d{2}-\d{4}\b/g, // SSNs
                /\b(?:\d{4}[\s-]?){3}\d{4}\b/g // credit cards
            ];

            for (const pattern of patterns) {
                if (pattern.test(content)) {
                    return this.createFailureResult(
                        'Sensitive data detected in response',
                        'HIGH',
                        'SENSITIVE_DATA_EXPOSURE'
                    );
                }
            }
        }

        return this.createSuccessResult();
    }

    extractUrls(text) {
        const urlPattern = /https?:\/\/[^\s<>"'{}|\\^`[\]]+/gi;
        return text.match(urlPattern) || [];
    }

    enhanceResult(result, source) {
        return {
            ...result,
            detectionLayer: 'Layer5-Contextual',
            validatorSource: source,
            timestamp: Date.now()
        };
    }
}

// Re-export ContextualConfigBuilder for convenience
export { ContextualConfigBuilder };

/**
 * Factory function to create a Layer 5 contextual validation layer with sensible defaults.
 * Creates a pre-configured layer with rate limiting enabled (20 req/min).
 *
 * @param {Object} customConfig - Custom configuration to merge with defaults
 * @param {boolean} [customConfig.enabled=true] - Enable the layer
 * @param {Object} [customConfig.oauthValidation] - OAuth URL validation config
 * @param {Object} [customConfig.domainRestrictions] - Domain blocklist/allowlist config
 * @param {Object} [customConfig.rateLimiting] - Per-method rate limiting config
 * @param {Object} [customConfig.responseValidation] - Response content validation config
 * @returns {ContextualValidationLayer} Configured contextual validation layer
 *
 * @example
 * // Create with defaults (rate limiting: 20 req/min)
 * const layer = createContextualLayer();
 *
 * @example
 * // Create with custom config
 * const layer = createContextualLayer({
 *   domainRestrictions: {
 *     enabled: true,
 *     blockedDomains: ['evil.com']
 *   }
 * });
 */
export function createContextualLayer(customConfig = {}) {
    const builder = new ContextualConfigBuilder();

    const defaultConfig = builder
        .enableRateLimiting(20, 60000)
        .build();

    return new ContextualValidationLayer({
        ...defaultConfig,
        ...customConfig
    });
}