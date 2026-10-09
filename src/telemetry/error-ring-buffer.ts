/**
 * Downstream Error Diagnostics & Rolling LRU Ring Buffer
 * Canonical implementation for @sgtm-gg/open-sgtm-runtime
 * Captures downstream HTTP 4xx/5xx rejections and vendor error messages.
 * Enforces a rolling LRU ring buffer strictly storing the latest 5 distinct errors
 * per (serverId, tagName, eventName) tuple with error signature deduplication.
 * Includes recursive PII scrubbing with operational ID preservation.
 *
 * Zero database dependencies: pure TypeScript / Node.js & browser portable.
 */

import crypto from 'crypto';

export interface DownstreamErrorRecord {
  id: string;
  statusCode: number; // 400, 401, 403, 429, 500, 502, 504
  occurrenceCount: number;
  vendorError: string; // Exact vendor rejection string
  remediation: string; // Actionable developer guidance
  sanitizedPayload: Record<string, unknown>; // Copyable JSON with all PII redacted
  firstSeenAt: string; // ISO 8601
  lastSeenAt: string; // ISO 8601
}

export interface IngestErrorInput {
  statusCode: number;
  vendorError: string;
  payload?: Record<string, unknown>;
  occurrenceCount?: number;
}

const MAX_ERRORS_PER_TUPLE = 5;

// In-memory LRU store: Map<tupleKey, DownstreamErrorRecord[]>
// tupleKey = `${serverId}:${tagName}:${eventName}`
const errorBufferStore = new Map<string, DownstreamErrorRecord[]>();

// ==============================================================================
// 1. DEDUPLICATION SIGNATURE HELPER & CANONICALIZATION
// ==============================================================================

/**
 * Canonicalizes an error message by stripping volatile dynamic segments:
 * - UUIDs
 * - ISO timestamps and Epoch timestamps
 * - Trace IDs, request IDs, fbtrace_id
 * - Dynamic order/transaction/event IDs
 * Strips dynamic runtime tokens before computing an MD5 hash.
 */
export function canonicalizeErrorSignature(statusCode: number, vendorMessage: string): string {
  if (!vendorMessage) return `${statusCode}:unknown`;

  let cleaned = (vendorMessage || '').trim().toLowerCase();

  // 1. Strip standard UUIDs (8-4-4-4-12 hex)
  cleaned = cleaned.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '<uuid>');

  // 2. Strip ISO timestamps (e.g. 2026-09-20T15:30:42.123Z)
  cleaned = cleaned.replace(/\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}(?:\.\d+)?z?/gi, '<timestamp>');

  // 3. Strip Unix Epoch timestamps (10 to 13 digits starting with 1...)
  cleaned = cleaned.replace(/\b1[5-9]\d{8,11}\b/g, '<timestamp>');

  // 4. Strip trace IDs, request IDs, fbtrace_id
  cleaned = cleaned.replace(/(?:fbtrace_id|trace_id|request_id|req_id|x-request-id)[\s:=]+[a-z0-9_-]+/gi, '<trace_id>');

  // 5. Strip dynamic IDs (order_id, transaction_id, event_id, customer_id)
  cleaned = cleaned.replace(/(?:order_id|transaction_id|event_id|customer_id)[\s:=]+[a-z0-9_-]+/gi, '<id>');

  // Normalize multiple spaces
  cleaned = cleaned.replace(/\s+/g, ' ').trim();

  let hash = '';
  if (typeof crypto !== 'undefined' && crypto.createHash) {
    hash = crypto.createHash('md5').update(cleaned).digest('hex').slice(0, 16);
  } else {
    // Simple deterministic fallback hash for browser environments
    let h = 0;
    for (let i = 0; i < cleaned.length; i++) {
      h = (Math.imul(31, h) + cleaned.charCodeAt(i)) | 0;
    }
    hash = Math.abs(h).toString(16).padStart(8, '0');
  }

  return `${statusCode}:${hash}`;
}

export function createErrorSignature(statusCode: number, vendorMessage: string): string {
  return canonicalizeErrorSignature(statusCode, vendorMessage);
}

// ==============================================================================
// 2. DOWNSTREAM RESPONSE BODY INSPECTION (HTTP 200 MASKED ERRORS)
// ==============================================================================

export interface DownstreamInspectionResult {
  isError: boolean;
  statusCode?: number;
  vendorError?: string;
  remediation?: string;
}

/**
 * Inspects downstream response bodies (specifically on HTTP 200 responses)
 * to catch ad platform errors masked behind transport-level 200 OK statuses:
 * - Meta CAPI: json.error or json.events_received === 0 with json.messages
 * - TikTok Events API: json.code !== 0
 * - Google Ads: json.partial_failure_error
 */
export function inspectDownstreamResponseBody(
  vendorId: string,
  transportStatusCode: number,
  responseBody: unknown
): DownstreamInspectionResult {
  if (!responseBody) return { isError: false };

  try {
    let json: any = responseBody;

    if (typeof responseBody === 'string') {
      const trimmed = responseBody.trim();
      if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
        try {
          json = JSON.parse(trimmed);
        } catch {
          json = responseBody;
        }
      }
    }

    if (!json || typeof json !== 'object') {
      return { isError: false };
    }

    const normVendor = (vendorId || '').toLowerCase();

    // 1. Meta Conversions API (Graph API returns 200 OK with error messages)
    if (normVendor.includes('meta') || normVendor.includes('facebook') || normVendor.includes('capi')) {
      if (json.error) {
        const code = json.error.code;
        const status = code === 190 ? 401 : 400;
        return {
          isError: true,
          statusCode: status,
          vendorError: `Meta CAPI: ${json.error.message || 'Unknown error'} (Code: ${code || 'none'})`,
          remediation: code === 190
            ? 'Regenerate your Meta System User Access Token in Facebook Business Manager.'
            : 'Review payload parameters in GTM: ensure currency, value, and event_name are formatted correctly.',
        };
      }
      if (Array.isArray(json.messages) && json.events_received === 0) {
        return {
          isError: true,
          statusCode: 400,
          vendorError: `Meta CAPI: ${json.messages.join('; ')}`,
          remediation: 'Meta rejected events due to schema formatting. Check hashed email formatting.',
        };
      }
    }

    // 2. TikTok Events API (Returns 200 OK with code !== 0)
    if (normVendor.includes('tiktok')) {
      if (json.code !== undefined && json.code !== 0) {
        const code = json.code;
        const status = code === 40001 ? 401 : 400;
        return {
          isError: true,
          statusCode: status,
          vendorError: `TikTok CAPI [${code}]: ${json.message || 'Unknown TikTok error'}`,
          remediation: code === 40001
            ? 'TikTok Access Token expired. Re-authenticate your TikTok Business Center account.'
            : 'Verify pixel_code and event parameters against TikTok Events API specification.',
        };
      }
    }

    // 3. Google Ads Enhanced Conversions (Returns 200 OK with partial_failure_error)
    if (normVendor.includes('google') || normVendor.includes('gads') || normVendor.includes('ad')) {
      if (json.partial_failure_error) {
        return {
          isError: true,
          statusCode: 400,
          vendorError: `Google Ads Partial Failure: ${json.partial_failure_error.message || JSON.stringify(json.partial_failure_error)}`,
          remediation: 'Verify conversion action ID and customer user identifier hashing rules.',
        };
      }
    }

    // Generic fallback for any JSON containing top-level error: string
    if (json.error && typeof json.error === 'string') {
      return {
        isError: true,
        statusCode: transportStatusCode >= 400 ? transportStatusCode : 400,
        vendorError: json.error,
        remediation: getRemediationGuidance(transportStatusCode >= 400 ? transportStatusCode : 400, json.error, vendorId),
      };
    }

    return { isError: false };
  } catch {
    return { isError: false };
  }
}

// ==============================================================================
// 3. RECURSIVE PII SANITIZATION ENGINE
// ==============================================================================

const CLICK_ID_KEYS = new Set([
  'gclid',
  'fbclid',
  'ttclid',
  'msclkid',
  'wbraid',
  'gbraid',
  'twclid',
  'li_fat_id',
  'mc_eid',
  'srsltid',
  'irclickid',
  'click_id',
  'clickid',
  'dclid',
  'yclid',
  'rdt_cid',
]);

const USER_ID_KEYS = new Set([
  'user_id',
  'userid',
  'uid',
  'customer_id',
  'customerid',
  'external_id',
  'externalid',
  'visitor_id',
  'visitorid',
  'client_id',
  'clientid',
  'account_id',
  'accountid',
]);

const URL_FIELDS = new Set([
  'page_location',
  'event_source_url',
  'dl',
  'url',
  'referrer',
  'dr',
  'page_path',
]);

const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g;

function stripUrlQueryParams(rawUrl: string): string {
  if (!rawUrl || typeof rawUrl !== 'string') return rawUrl;
  return rawUrl.trim().split('?')[0];
}

/**
 * Sanitizes arbitrary JSON payload objects:
 * - Advertising click IDs: masked as [REDACTED_CLICK_ID]
 * - User identifiers: masked as [REDACTED_USER_ID] (strictly preserving event_id and device_id)
 * - URL fields: query parameters stripped
 * - Hashed emails/phones: displayed as sha256:abc12345...89ef
 * - Raw emails: masked as ***@domain.com
 * - Raw phones: masked as +1***-***-1234
 * - IP addresses: host bits masked
 * - API keys, tokens, secrets: completely redacted
 */
export function sanitizePayload(input: unknown): any {
  if (input === null || input === undefined) return input;

  if (typeof input !== 'object') {
    if (typeof input === 'string') {
      return input.replace(EMAIL_REGEX, '***@$1');
    }
    return input;
  }

  if (Array.isArray(input)) {
    return input.map(item => sanitizePayload(item));
  }

  const output: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    const lowerKey = key.toLowerCase();

    // 1. Secrets / API keys / Bearer tokens / Master auth keys
    if (
      lowerKey.includes('secret') ||
      lowerKey.includes('token') ||
      lowerKey.includes('api_key') ||
      lowerKey.includes('apikey') ||
      lowerKey.includes('authorization') ||
      lowerKey.includes('password') ||
      lowerKey === 'w'
    ) {
      output[key] = '[REDACTED_SECRET]';
      continue;
    }

    // 2. Advertising Click Identifiers
    if (
      CLICK_ID_KEYS.has(lowerKey) ||
      lowerKey.endsWith('clid') ||
      lowerKey.includes('click_id') ||
      lowerKey.includes('clickid')
    ) {
      output[key] = '[REDACTED_CLICK_ID]';
      continue;
    }

    // 3. User Identifiers (strictly preserving operational IDs: event_id, device_id, tag_id, server_id, incident_id, container_id, id)
    if (
      lowerKey !== 'event_id' &&
      lowerKey !== 'device_id' &&
      lowerKey !== 'tag_id' &&
      lowerKey !== 'server_id' &&
      lowerKey !== 'incident_id' &&
      lowerKey !== 'container_id' &&
      lowerKey !== 'id' &&
      USER_ID_KEYS.has(lowerKey)
    ) {
      output[key] = '[REDACTED_USER_ID]';
      continue;
    }

    // 4. URL fields with query parameter stripping
    if (URL_FIELDS.has(lowerKey) && typeof value === 'string') {
      output[key] = stripUrlQueryParams(value);
      continue;
    }

    // 5. String-specific sanitization (Email, Phone, IP, Free-text PII)
    if (typeof value === 'string') {
      const trimmed = value.trim();

      // Email fields
      if (
        lowerKey.includes('email') ||
        lowerKey.includes('mail') ||
        lowerKey === 'em' ||
        lowerKey.startsWith('em_') ||
        lowerKey.endsWith('_em') ||
        lowerKey.includes('_em_')
      ) {
        if (/^[a-f0-9]{64}$/i.test(trimmed)) {
          output[key] = `sha256:${trimmed.slice(0, 8)}...${trimmed.slice(-4)}`;
        } else if (trimmed.includes('@')) {
          const parts = trimmed.split('@');
          output[key] = `***@${parts[1] || 'domain.com'}`;
        } else {
          output[key] = '[REDACTED_PII]';
        }
        continue;
      }

      // Phone fields
      if (
        lowerKey.includes('phone') ||
        lowerKey.includes('cell') ||
        lowerKey === 'ph' ||
        lowerKey.startsWith('ph_') ||
        lowerKey.endsWith('_ph') ||
        lowerKey.includes('_ph_') ||
        lowerKey === 'tel' ||
        lowerKey.includes('mobile')
      ) {
        if (/^[a-f0-9]{64}$/i.test(trimmed)) {
          output[key] = `sha256:${trimmed.slice(0, 8)}...${trimmed.slice(-4)}`;
        } else if (trimmed.length >= 4) {
          output[key] = `+1***-***-${trimmed.slice(-4)}`;
        } else {
          output[key] = '[REDACTED_PII]';
        }
        continue;
      }

      // IP addresses
      if (
        lowerKey.includes('ip') ||
        lowerKey.includes('address')
      ) {
        // IPv4 masking
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) {
          const octets = trimmed.split('.');
          output[key] = `${octets[0]}.${octets[1]}.***.***`;
          continue;
        }
        // IPv6 masking
        if (trimmed.includes(':') && /^[0-9a-fA-F:]+$/.test(trimmed)) {
          const colons = trimmed.split(':');
          output[key] = `${colons.slice(0, 2).join(':')}:***`;
          continue;
        }
      }

      // Free-text string scanning for raw emails
      let sanitizedStr = trimmed.replace(EMAIL_REGEX, '***@$1');

      // If string is an embedded URL containing query parameters with click IDs or PII
      if (/^https?:\/\//i.test(sanitizedStr) && sanitizedStr.includes('?')) {
        if (
          sanitizedStr.includes('gclid') ||
          sanitizedStr.includes('fbclid') ||
          sanitizedStr.includes('ttclid') ||
          sanitizedStr.includes('msclkid') ||
          sanitizedStr.includes('wbraid') ||
          sanitizedStr.includes('gbraid') ||
          sanitizedStr.includes('twclid') ||
          sanitizedStr.includes('clid') ||
          sanitizedStr.includes('email') ||
          sanitizedStr.includes('@')
        ) {
          sanitizedStr = stripUrlQueryParams(sanitizedStr);
        }
      }

      output[key] = sanitizedStr;
    } else if (typeof value === 'object' && value !== null) {
      output[key] = sanitizePayload(value);
    } else {
      output[key] = value;
    }
  }

  return output;
}

// ==============================================================================
// 4. REMEDIATION GUIDANCE KNOWLEDGE BASE
// ==============================================================================

export function getRemediationGuidance(
  statusCode: number,
  vendorError: string,
  platformOrTag: string = ''
): string {
  const normError = (vendorError || '').toLowerCase();
  const normTag = (platformOrTag || '').toLowerCase();

  // HTTP 400 Bad Request
  if (statusCode === 400) {
    if (normError.includes('em') || normError.includes('email') || normError.includes('hash')) {
      return "Ensure user_data.em is trimmed, converted to lowercase, and hashed with SHA-256 (64 hex characters) before passing to destination tag.";
    }
    if (normError.includes('currency') || normError.includes('value')) {
      return "The 'purchase' event requires a 3-letter ISO-4217 currency code (e.g. 'USD', 'EUR') and positive numeric value. Check dataLayer currency mapping.";
    }
    if (normError.includes('transaction_id') || normError.includes('order_id')) {
      return "Missing unique transaction_id required for conversion deduplication. Check purchase event payload.";
    }
    if (normTag.includes('meta') || normError.includes('capi') || normError.includes('facebook')) {
      return "Invalid parameter formatting in Meta CAPI payload. Inspect parameter schema for unnormalized email/phone or missing event_source_url.";
    }
    if (normTag.includes('google') || normError.includes('gads')) {
      return "Invalid conversion adjustment or missing gclid/user_identifiers. Validate payload formatting in Google Ads tag.";
    }
    if (normTag.includes('tiktok')) {
      return "Malformed TikTok Events API request. Verify event_id and user properties in TikTok tag configuration.";
    }
    if (normTag.includes('linkedin')) {
      return "Malformed LinkedIn Conversions API request. Verify li_fat_id or hashed user identifier in LinkedIn tag configuration.";
    }
    return "Malformed request payload or missing required parameters. Inspect schema inventory and validate field types.";
  }

  // HTTP 401 Unauthorized
  if (statusCode === 401) {
    if (normTag.includes('google') || normError.includes('unauthenticated')) {
      return "Cloud Run service account or OAuth refresh token for Google Ads API is invalid or expired. Re-authenticate Google Ads connection in destination settings.";
    }
    if (normTag.includes('meta') || normError.includes('access token')) {
      return "The CAPI System User access token is missing or invalid. Verify access token in Meta Business Manager and container environment variables.";
    }
    return "Authentication failed. Destination API key or bearer token has expired or is invalid. Verify credentials in server settings.";
  }

  // HTTP 403 Forbidden
  if (statusCode === 403) {
    if (normTag.includes('meta') || normError.includes('permission') || normError.includes('ads_management')) {
      return "The CAPI System User access token lacks 'ads_management' permission or dataset access has been revoked. Re-generate token in Meta Business Manager.";
    }
    if (normTag.includes('tiktok')) {
      return "Advertiser account ID mismatch or unauthorized access token. Check TikTok Events API permissions.";
    }
    return "Forbidden. Destination server rejected credentials due to insufficient permissions or IP restrictions.";
  }

  // HTTP 429 Too Many Requests
  if (statusCode === 429) {
    return "Downstream vendor rate limit exceeded. Enable sGTM batching queue or request API quota increase in vendor developer console.";
  }

  // HTTP 500 Internal Server Error
  if (statusCode === 500) {
    return "Downstream vendor internal server error. Temporary vendor outage; runtime container hook will automatically retry with exponential backoff.";
  }

  // HTTP 502 Bad Gateway
  if (statusCode === 502) {
    return "Bad Gateway received from downstream platform endpoint. The destination gateway is temporarily unreachable or returning invalid HTTP responses.";
  }

  // HTTP 504 Gateway Timeout
  if (statusCode === 504) {
    if (normTag.includes('tiktok')) {
      return "TikTok Events API endpoint exceeded response timeout. Check TikTok platform status; runtime hook attempted 1 retry.";
    }
    return "Downstream vendor request timed out (>800ms). Check downstream endpoint status or network connectivity.";
  }

  return `Downstream vendor returned HTTP ${statusCode}. Inspect sanitized error payload and vendor documentation for error details.`;
}

// ==============================================================================
// 5. ROLLING LRU RING BUFFER IMPLEMENTATION
// ==============================================================================

/**
 * Records a downstream error into the rolling LRU ring buffer.
 * Strictly caps at 5 distinct errors per (serverId, tagName, eventName) tuple.
 * Deduplicates by signature `${statusCode}:${hash(vendorMessage)}`.
 */
export function recordDownstreamError(
  serverId: number | string,
  tagName: string,
  eventName: string,
  errorInput: IngestErrorInput
): DownstreamErrorRecord {
  const tupleKey = `${serverId}:${tagName}:${eventName}`;
  const now = new Date().toISOString();
  const count = errorInput.occurrenceCount || 1;

  if (!errorBufferStore.has(tupleKey)) {
    errorBufferStore.set(tupleKey, []);
  }

  const buffer = errorBufferStore.get(tupleKey)!;
  const signature = createErrorSignature(errorInput.statusCode, errorInput.vendorError);

  // Check if signature already exists in buffer (deduplication)
  const existingIndex = buffer.findIndex(
    item => createErrorSignature(item.statusCode, item.vendorError) === signature
  );

  if (existingIndex !== -1) {
    const existing = buffer[existingIndex];
    existing.occurrenceCount += count;
    existing.lastSeenAt = now;
    if (errorInput.payload) {
      existing.sanitizedPayload = sanitizePayload(errorInput.payload);
    }
    // Move to front (head of LRU queue)
    buffer.splice(existingIndex, 1);
    buffer.unshift(existing);
    return existing;
  }

  // New distinct error: if buffer full (>= 5), evict oldest at tail
  if (buffer.length >= MAX_ERRORS_PER_TUPLE) {
    buffer.pop();
  }

  const remediation = getRemediationGuidance(
    errorInput.statusCode,
    errorInput.vendorError,
    tagName
  );

  const newRecord: DownstreamErrorRecord = {
    id: `err_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    statusCode: errorInput.statusCode,
    occurrenceCount: count,
    vendorError: errorInput.vendorError,
    remediation,
    sanitizedPayload: sanitizePayload(errorInput.payload || {}),
    firstSeenAt: now,
    lastSeenAt: now
  };

  buffer.unshift(newRecord);
  return newRecord;
}

/**
 * Retrieves the latest distinct errors for a specific server, tag, and event.
 * Strictly returns at most 5 items per tuple.
 */
export function getRecentErrors(
  serverId: number | string,
  tagName?: string,
  eventName?: string
): DownstreamErrorRecord[] {
  if (tagName && eventName) {
    const tupleKey = `${serverId}:${tagName}:${eventName}`;
    return errorBufferStore.get(tupleKey) || [];
  }

  const results: DownstreamErrorRecord[] = [];
  const prefix = `${serverId}:`;

  for (const [key, records] of errorBufferStore.entries()) {
    if (key.startsWith(prefix)) {
      if (!tagName || key.split(':')[1] === tagName) {
        results.push(...records);
      }
    }
  }

  return results
    .sort((a, b) => new Date(b.lastSeenAt).getTime() - new Date(a.lastSeenAt).getTime())
    .slice(0, 10);
}

/**
 * Clears error buffer (used in tests or on telemetry reset).
 */
export function clearRecentErrors(serverId?: number | string): void {
  if (serverId !== undefined) {
    const prefix = `${serverId}:`;
    for (const key of Array.from(errorBufferStore.keys())) {
      if (key.startsWith(prefix)) {
        errorBufferStore.delete(key);
      }
    }
  } else {
    errorBufferStore.clear();
  }
}

/**
 * Returns diagnostic stats about the in-memory ring buffer.
 */
export function getErrorRingBufferStats(): { totalEntries: number; totalTuples: number } {
  let totalEntries = 0;
  for (const records of errorBufferStore.values()) {
    totalEntries += records.length;
  }
  return {
    totalEntries,
    totalTuples: errorBufferStore.size
  };
}
