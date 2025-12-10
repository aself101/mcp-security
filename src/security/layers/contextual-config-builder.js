/**
 * @fileoverview Configuration builder for Layer 5 contextual validation.
 * Provides fluent API for common configuration scenarios.
 */

/**
 * Builder for Layer 5 contextual validation configuration.
 * Provides a fluent API for common configuration scenarios.
 *
 * @example
 * const config = new ContextualConfigBuilder()
 *   .enableOAuthValidation(['oauth.example.com'])
 *   .enableRateLimiting(20, 60000)
 *   .enableResponseValidation({ blockSensitiveData: true })
 *   .build();
 */
export class ContextualConfigBuilder {
    constructor() {
        this.config = {};
    }

    /**
     * Enable OAuth URL validation with allowed domains.
     * Blocks dangerous URL schemes (javascript:, vbscript:, data:) by default.
     * @param {string[]} allowedDomains - List of allowed OAuth domains
     * @returns {ContextualConfigBuilder} this for chaining
     */
    enableOAuthValidation(allowedDomains = []) {
        this.config.oauthValidation = {
            enabled: true,
            allowedDomains,
            blockDangerousSchemes: true
        };
        return this;
    }

    /**
     * Enable domain restrictions (blocklist/allowlist).
     * @param {Object} options - Domain restriction options
     * @param {string[]} [options.blockedDomains] - Domains to block
     * @param {string[]} [options.allowedDomains] - Domains to allow (empty = allow all except blocked)
     * @returns {ContextualConfigBuilder} this for chaining
     */
    enableDomainRestrictions(options = {}) {
        this.config.domainRestrictions = {
            enabled: true,
            blockedDomains: options.blockedDomains || [],
            allowedDomains: options.allowedDomains || []
        };
        return this;
    }

    /**
     * Enable per-method/tool rate limiting.
     * @param {number} limit - Maximum requests per window (default: 10)
     * @param {number} windowMs - Time window in milliseconds (default: 60000)
     * @returns {ContextualConfigBuilder} this for chaining
     */
    enableRateLimiting(limit = 10, windowMs = 60000) {
        this.config.rateLimiting = {
            enabled: true,
            limit,
            windowMs
        };
        return this;
    }

    /**
     * Enable response content validation.
     * Checks server responses for sensitive data exposure.
     * @param {Object} options - Response validation options
     * @param {boolean} [options.blockSensitiveData=true] - Block responses containing PII
     * @returns {ContextualConfigBuilder} this for chaining
     */
    enableResponseValidation(options = {}) {
        this.config.responseValidation = {
            enabled: true,
            blockSensitiveData: true,
            ...options
        };
        return this;
    }

    /**
     * Build the configuration object.
     * @returns {Object} Configuration object for ContextualValidationLayer
     */
    build() {
        return this.config;
    }
}
