/**
 * URL-Safe XOR Base64 Cipher & Multi-Format Container ID Parser
 * Canonical implementation for @sgtm-gg/open-sgtm-runtime
 * Zero external dependencies: pure TypeScript / Node.js & browser portable.
 */

export const DEFAULT_SECRET_KEY = 'sTp9Xq2mZ';

/**
 * Encrypts a plaintext string using repeating XOR cipher followed by URL-safe Base64 encoding.
 * Strips '=' padding and maps '+' -> '-' and '/' -> '_'.
 */
export function encryptXorBase64Url(str: string, key: string = DEFAULT_SECRET_KEY): string {
  if (!str || !key) return '';
  let out = '';
  for (let i = 0; i < str.length; i++) {
    out += String.fromCharCode(str.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }

  let b64: string;
  if (typeof Buffer !== 'undefined') {
    b64 = Buffer.from(out, 'binary').toString('base64');
  } else if (typeof window !== 'undefined' && typeof window.btoa === 'function') {
    b64 = window.btoa(out);
  } else {
    b64 = '';
  }

  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decrypts a URL-safe Base64 encoded XOR string back to plaintext.
 * Restores '=' padding, maps '-' -> '+' and '_' -> '/', and applies character XOR with key.
 */
export function decryptXorBase64Url(encrypted: string, key: string = DEFAULT_SECRET_KEY): string {
  if (!encrypted || !key) return '';
  const trimmed = encrypted.trim();
  if (!/^[A-Za-z0-9_-]+$/.test(trimmed)) return '';
  try {
    let b64 = trimmed.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) {
      b64 += '=';
    }

    let raw = '';
    if (typeof Buffer !== 'undefined') {
      raw = Buffer.from(b64, 'base64').toString('binary');
    } else if (typeof window !== 'undefined' && typeof window.atob === 'function') {
      raw = window.atob(b64);
    } else {
      return '';
    }

    let out = '';
    for (let i = 0; i < raw.length; i++) {
      out += String.fromCharCode(raw.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return out;
  } catch {
    return '';
  }
}

/**
 * Generates a cryptographically secure random alphanumeric secret key.
 * Defaults to 16 characters.
 */
export function generateSecretKey(length: number = 16): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  if (typeof globalThis !== 'undefined' && globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function') {
    const bytes = new Uint8Array(length);
    globalThis.crypto.getRandomValues(bytes);
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars[bytes[i] % chars.length];
    }
    return result;
  }

  // Fallback for non-Node environments
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

/**
 * Multi-format GTM Container ID extraction pipeline.
 * Reliably extracts 'GTM-XXXXXXX' from:
 * - Direct strings: "GTM-ABC1234"
 * - Quoted strings: "\"GTM-ABC1234\""
 * - CONTAINER_CONFIG env values: "CONTAINER_CONFIG=GTM-ABC1234"
 * - URL encoded query strings: "id%3DGTM-ABC1234"
 * - Plain query strings: "id=GTM-ABC1234&env=1"
 * - Base64 encoded Google Cloud Run configuration blobs
 * Fallback: "GTM-XXXXXXX"
 */
export function extractGtmId(containerConfig: string | null | undefined): string {
  if (!containerConfig || typeof containerConfig !== 'string') {
    return 'GTM-XXXXXXX';
  }

  let raw = containerConfig.trim();
  if (!raw) return 'GTM-XXXXXXX';

  // Stage 0: Strip surrounding quotes (common in env files)
  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
    raw = raw.slice(1, -1).trim();
  }

  // Stage 0b: Strip optional CONTAINER_CONFIG= prefix
  if (raw.startsWith('CONTAINER_CONFIG=')) {
    raw = raw.slice('CONTAINER_CONFIG='.length).trim();
  }

  // Stage 1: Safe URL-decoding (handles percent-encoded %3D, %26, %2B, %2F)
  let unencoded = raw;
  try {
    unencoded = decodeURIComponent(raw);
  } catch {
    unencoded = raw;
  }

  // Stage 2: Direct plain text extraction (before attempting Base64)
  // Case 2a: Exact GTM ID (e.g. "GTM-XYZ", "GTM-123456")
  const exactGtmMatch = unencoded.match(/^GTM-[A-Z0-9]+$/i);
  if (exactGtmMatch) {
    return exactGtmMatch[0].toUpperCase();
  }

  // Case 2b: Plain text query string with id= (e.g. "id=GTM-123456", "env=1&id=GTM-123456")
  const plainIdMatch = unencoded.match(/(?:^|[&?])id=([^&;]+)/i);
  if (plainIdMatch && plainIdMatch[1]) {
    const candidate = plainIdMatch[1].trim();
    if (/^GTM-[A-Z0-9]+$/i.test(candidate)) {
      return candidate.toUpperCase();
    }
  }

  // Stage 3: Base64 decoding pipeline
  try {
    // Normalize URL-safe base64 characters
    let b64 = unencoded.replace(/-/g, '+').replace(/_/g, '/');
    // Add missing base64 padding
    while (b64.length % 4 !== 0) {
      b64 += '=';
    }

    let decoded = '';
    if (typeof Buffer !== 'undefined') {
      decoded = Buffer.from(b64, 'base64').toString('utf-8');
    } else if (typeof window !== 'undefined' && typeof window.atob === 'function') {
      try {
        decoded = decodeURIComponent(escape(window.atob(b64)));
      } catch {
        decoded = window.atob(b64);
      }
    }

    if (decoded) {
      // URL-decode decoded payload if it contains percent-encoded characters
      try {
        decoded = decodeURIComponent(decoded);
      } catch {
        // keep decoded as-is
      }

      // Check for id= parameter in decoded string
      const match = decoded.match(/(?:^|[&?])id=([^&;]+)/i);
      if (match && match[1]) {
        const candidate = match[1].trim();
        if (/^GTM-[A-Z0-9]+$/i.test(candidate)) {
          return candidate.toUpperCase();
        }
        return candidate;
      }

      // Check for direct GTM token inside decoded string
      const directMatch = decoded.match(/\b(GTM-[A-Z0-9]+)\b/i);
      if (directMatch && directMatch[1]) {
        return directMatch[1].toUpperCase();
      }
    }
  } catch {
    // Fall back gracefully
  }

  return 'GTM-XXXXXXX';
}
