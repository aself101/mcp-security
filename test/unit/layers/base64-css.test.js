import { describe, it, expect } from 'vitest';
import {
    validateBase64Content,
    validateDataUriMimeType,
    validateBase64Data,
    validateCSSContent
} from '@/security/layers/layer2-validators/base64-css.js';

describe('Base64 and CSS Validation', () => {
    describe('validateBase64Content', () => {
        it('should pass for content without data URIs', () => {
            const result = validateBase64Content('Hello world, no data URIs here');
            expect(result.passed).toBe(true);
        });

        it('should pass for safe image data URI', () => {
            // Base64 of "safe content"
            const safeBase64 = Buffer.from('safe content').toString('base64');
            const content = `data:image/png;base64,${safeBase64}`;
            const result = validateBase64Content(content);
            expect(result.passed).toBe(true);
        });

        it('should detect dangerous MIME type in data URI', () => {
            const content = 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==';
            const result = validateBase64Content(content);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('DANGEROUS_DATA_URI');
        });

        it('should detect malicious content in base64 data', () => {
            // Base64 of "<script>alert(1)</script>"
            const maliciousBase64 = Buffer.from('<script>alert(1)</script>').toString('base64');
            const content = `data:image/png;base64,${maliciousBase64}`;
            const result = validateBase64Content(content);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('BASE64_INJECTION');
        });

        it('should handle multiple data URIs', () => {
            const safe1 = Buffer.from('safe1').toString('base64');
            const safe2 = Buffer.from('safe2').toString('base64');
            const content = `First: data:text/plain;base64,${safe1} Second: data:text/plain;base64,${safe2}`;
            const result = validateBase64Content(content);
            expect(result.passed).toBe(true);
        });

        it('should call logDebug when provided and URIs found', () => {
            const safeBase64 = Buffer.from('test').toString('base64');
            const content = `data:text/plain;base64,${safeBase64}`;
            let logCalled = false;
            const logDebug = () => { logCalled = true; };

            validateBase64Content(content, logDebug);
            expect(logCalled).toBe(true);
        });

        it('should handle data URI without base64 encoding', () => {
            const content = 'data:text/plain,Hello%20World';
            const result = validateBase64Content(content);
            expect(result.passed).toBe(true);
        });
    });

    describe('validateDataUriMimeType', () => {
        it('should pass for safe MIME types', () => {
            expect(validateDataUriMimeType('image/png').passed).toBe(true);
            expect(validateDataUriMimeType('image/jpeg').passed).toBe(true);
            expect(validateDataUriMimeType('text/plain').passed).toBe(true);
            expect(validateDataUriMimeType('application/json').passed).toBe(true);
        });

        it('should block text/html MIME type', () => {
            const result = validateDataUriMimeType('text/html');
            expect(result.passed).toBe(false);
            expect(result.severity).toBe('CRITICAL');
            expect(result.violationType).toBe('DANGEROUS_DATA_URI');
        });

        it('should block application/javascript MIME type', () => {
            const result = validateDataUriMimeType('application/javascript');
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('DANGEROUS_DATA_URI');
        });

        it('should block text/javascript MIME type', () => {
            const result = validateDataUriMimeType('text/javascript');
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('DANGEROUS_DATA_URI');
        });

        it('should handle empty MIME type', () => {
            const result = validateDataUriMimeType('');
            expect(result.passed).toBe(true);
        });
    });

    describe('validateBase64Data', () => {
        it('should pass for safe base64 content', () => {
            const safe = Buffer.from('Hello, World!').toString('base64');
            const result = validateBase64Data(safe);
            expect(result.passed).toBe(true);
        });

        it('should detect script tags in decoded content', () => {
            const malicious = Buffer.from('<script>alert("xss")</script>').toString('base64');
            const result = validateBase64Data(malicious);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('BASE64_INJECTION');
            expect(result.reason).toMatch(/malicious/i);
        });

        it('should detect nested data URI (inception attack)', () => {
            const nested = Buffer.from('data:text/html,<h1>Nested</h1>').toString('base64');
            const result = validateBase64Data(nested);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('NESTED_DATA_URI');
            expect(result.reason).toMatch(/nested/i);
        });

        it('should detect command injection in decoded content', () => {
            const injection = Buffer.from('$(rm -rf /)').toString('base64');
            const result = validateBase64Data(injection);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('BASE64_INJECTION');
        });

        it('should detect SQL injection in decoded content', () => {
            const sqli = Buffer.from("'; DROP TABLE users; --").toString('base64');
            const result = validateBase64Data(sqli);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('BASE64_INJECTION');
        });

        it('should handle binary content (latin1 fallback)', () => {
            // Create content with replacement character that triggers latin1 fallback
            const binaryData = Buffer.from([0x80, 0x81, 0x82, 0x83]).toString('base64');
            const result = validateBase64Data(binaryData);
            expect(result.passed).toBe(true);
        });

        it('should pass simple path strings (path traversal detected at Layer 2 level)', () => {
            // Simple path strings pass base64 validation - path traversal
            // detection happens at the content layer level, not within base64 decode
            const traversal = Buffer.from('../../../etc/passwd').toString('base64');
            const result = validateBase64Data(traversal);
            // This passes because containsMaliciousPatterns focuses on injection patterns
            // Path traversal is detected by the full Layer 2 content validation
            expect(result.passed).toBe(true);
        });

        it('should detect script injection in base64 with path', () => {
            // But if it contains actual injection patterns, it fails
            const injection = Buffer.from('file:///../../../etc/passwd<script>').toString('base64');
            const result = validateBase64Data(injection);
            expect(result.passed).toBe(false);
        });
    });

    describe('validateCSSContent', () => {
        it('should pass for safe CSS', () => {
            const css = 'body { background-color: #fff; color: #000; }';
            const result = validateCSSContent(css);
            expect(result.passed).toBe(true);
        });

        it('should detect expression() in CSS', () => {
            const maliciousCss = 'div { width: expression(alert(1)); }';
            const result = validateCSSContent(maliciousCss);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('CSS_INJECTION');
        });

        it('should detect javascript: URL in CSS', () => {
            const maliciousCss = 'a { background: url(javascript:alert(1)); }';
            const result = validateCSSContent(maliciousCss);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('CSS_INJECTION');
        });

        it('should detect behavior: in CSS', () => {
            const maliciousCss = 'body { behavior: url(malicious.htc); }';
            const result = validateCSSContent(maliciousCss);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('CSS_INJECTION');
        });

        it('should detect -moz-binding in CSS', () => {
            const maliciousCss = 'div { -moz-binding: url("chrome://xbl/malicious.xml"); }';
            const result = validateCSSContent(maliciousCss);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('CSS_INJECTION');
        });

        it('should pass for CSS with safe url()', () => {
            const safeCss = 'div { background: url(https://example.com/image.png); }';
            const result = validateCSSContent(safeCss);
            expect(result.passed).toBe(true);
        });

        it('should handle empty content', () => {
            const result = validateCSSContent('');
            expect(result.passed).toBe(true);
        });

        it('should detect vbscript: URL in CSS', () => {
            const maliciousCss = 'a { background: url(vbscript:msgbox("xss")); }';
            const result = validateCSSContent(maliciousCss);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('CSS_INJECTION');
        });
    });
});
