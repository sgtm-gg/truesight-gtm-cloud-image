/**
 * Canonical Marketing Vendor Schemas & Format Validators
 * Canonical definitions for all 7 major server-side advertising and analytics platforms:
 * 1. Meta CAPI (Conversions API)
 * 2. Google Ads Enhanced Conversions
 * 3. TikTok Events API
 * 4. Google Analytics 4 (GA4) Server
 * 5. Snapchat Conversions API
 * 6. Pinterest API for Conversions
 * 7. LinkedIn Conversions API
 *
 * Zero external dependencies: pure TypeScript / Node.js & browser portable.
 */

export type StandardizedVendorId =
  | 'meta_capi'
  | 'google_enhanced_conversions'
  | 'tiktok_events_api'
  | 'ga4_server'
  | 'snapchat_conversions_api'
  | 'pinterest_api_for_conversions'
  | 'linkedin_conversions_api'
  | 'generic';

export interface CanonicalVendorParameter {
  name: string;
  category: 'user_signal' | 'event_context' | 'identifier';
  type: 'SHA-256' | 'Cookie' | 'Click ID' | 'IP' | 'User Agent' | 'UUID' | 'string' | 'object' | 'number';
  description: string;
  isCore?: boolean;
}

export interface VendorSchemaDefinition {
  vendorId: StandardizedVendorId;
  name: string;
  domains: string[];
  canonicalParameters: string[];
  parameterDetails?: CanonicalVendorParameter[];
  aliases?: Record<string, string>;
  validators?: Record<string, (val: unknown) => boolean>;
}

// ==============================================================================
// REGEX & FORMAT VALIDATION HELPERS
// ==============================================================================

/**
 * Validates whether a value is a valid lowercase 64-character SHA-256 hash.
 */
export function isValidSha256(val: unknown): boolean {
  if (typeof val !== 'string') return false;
  return /^[a-f0-9]{64}$/.test(val.trim());
}

/**
 * Validates Meta browser ID (_fbp): fb.1.<timestamp>.<random>
 */
export function isValidFbp(val: unknown): boolean {
  if (typeof val !== 'string') return false;
  return /^fb\.1\.\d+\.\d+$/.test(val.trim());
}

/**
 * Validates Meta click ID (_fbc): fb.1.<timestamp>.<click_id>
 */
export function isValidFbc(val: unknown): boolean {
  if (typeof val !== 'string') return false;
  return /^fb\.1\.\d+\.[A-Za-z0-9_-]+$/.test(val.trim());
}

/**
 * Validates TikTok click ID (ttclid)
 */
export function isValidTtclid(val: unknown): boolean {
  if (typeof val !== 'string') return false;
  const trimmed = val.trim();
  return trimmed.length >= 5 && /^[A-Za-z0-9_.-]+$/.test(trimmed);
}

/**
 * Validates TikTok cookie (_ttp)
 */
export function isValidTtp(val: unknown): boolean {
  if (typeof val !== 'string') return false;
  const trimmed = val.trim();
  return trimmed.length >= 5;
}

/**
 * Validates Snapchat cookie (_scid)
 */
export function isValidScid(val: unknown): boolean {
  if (typeof val !== 'string') return false;
  const trimmed = val.trim();
  return trimmed.length >= 5;
}

/**
 * Validates Pinterest cookie (_epik)
 */
export function isValidEpik(val: unknown): boolean {
  if (typeof val !== 'string') return false;
  const trimmed = val.trim();
  return trimmed.length >= 5;
}

/**
 * Validates Google Click ID (gclid, wbraid, gbraid)
 */
export function isValidGclid(val: unknown): boolean {
  if (typeof val !== 'string') return false;
  const trimmed = val.trim();
  return trimmed.length >= 8 && /^[A-Za-z0-9_.-]+$/.test(trimmed);
}

/**
 * Validates LinkedIn First-Party Ad Tracking ID (li_fat_id)
 */
export function isValidLiFatId(val: unknown): boolean {
  if (typeof val !== 'string') return false;
  const trimmed = val.trim();
  return trimmed.length >= 8 && /^[A-Za-z0-9_.-]+$/.test(trimmed);
}

/**
 * Validates IPv4 or IPv6 format
 */
export function isValidIp(val: unknown): boolean {
  if (typeof val !== 'string') return false;
  const trimmed = val.trim();
  const ipv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4.test(trimmed)) return true;
  const ipv6 = /^[0-9a-fA-F:]+$/;
  return trimmed.includes(':') && ipv6.test(trimmed) && trimmed.length >= 3;
}

/**
 * Validates non-empty user-agent string (> 10 chars)
 */
export function isValidUserAgent(val: unknown): boolean {
  if (typeof val !== 'string') return false;
  return val.trim().length > 10;
}

// ==============================================================================
// CANONICAL VENDOR SCHEMAS (7 PLATFORMS)
// ==============================================================================

export const CANONICAL_VENDOR_SCHEMAS: Record<StandardizedVendorId, VendorSchemaDefinition> = {
  meta_capi: {
    vendorId: 'meta_capi',
    name: 'Meta CAPI',
    domains: ['graph.facebook.com', 'facebook.com'],
    canonicalParameters: [
      'em',
      'ph',
      'fbp',
      'fbc',
      'client_ip_address',
      'client_user_agent',
      'event_id',
      'external_id',
      'fn',
      'ln',
      'ct',
      'st',
      'zp',
      'country'
    ],
    parameterDetails: [
      { name: 'em', category: 'user_signal', type: 'SHA-256', description: 'Hashed email address', isCore: true },
      { name: 'ph', category: 'user_signal', type: 'SHA-256', description: 'Hashed phone number' },
      { name: 'fbp', category: 'identifier', type: 'Cookie', description: 'Meta browser ID cookie (_fbp)', isCore: true },
      { name: 'fbc', category: 'identifier', type: 'Click ID', description: 'Meta click ID cookie (_fbc)' },
      { name: 'client_ip_address', category: 'event_context', type: 'IP', description: 'Client IP address' },
      { name: 'client_user_agent', category: 'event_context', type: 'User Agent', description: 'Client User Agent string' },
      { name: 'event_id', category: 'identifier', type: 'UUID', description: 'Conversion deduplication ID', isCore: true },
      { name: 'external_id', category: 'identifier', type: 'string', description: 'Customer CRM or unique user ID' }
    ],
    aliases: {
      email: 'em',
      hashed_email: 'em',
      phone: 'ph',
      _fbp: 'fbp',
      _fbc: 'fbc',
      ip: 'client_ip_address',
      user_agent: 'client_user_agent',
      eventId: 'event_id'
    },
    validators: {
      em: isValidSha256,
      ph: isValidSha256,
      fbp: isValidFbp,
      fbc: isValidFbc,
      client_ip_address: isValidIp,
      client_user_agent: isValidUserAgent
    }
  },

  google_enhanced_conversions: {
    vendorId: 'google_enhanced_conversions',
    name: 'Google Enhanced Conversions',
    domains: ['googleadservices.com', 'www.googleadservices.com'],
    canonicalParameters: [
      'email',
      'phone_number',
      'address',
      'gclid',
      'wbraid',
      'gbraid',
      'conversion_action_id',
      'conversion_value',
      'currency_code',
      'order_id'
    ],
    parameterDetails: [
      { name: 'email', category: 'user_signal', type: 'SHA-256', description: 'Normalized, SHA-256 hashed customer email', isCore: true },
      { name: 'phone_number', category: 'user_signal', type: 'SHA-256', description: 'E.164 formatted, SHA-256 hashed customer phone' },
      { name: 'address', category: 'user_signal', type: 'object', description: 'Customer postal address details' },
      { name: 'gclid', category: 'identifier', type: 'Click ID', description: 'Google Click Identifier', isCore: true },
      { name: 'conversion_action_id', category: 'identifier', type: 'string', description: 'Google Ads conversion action identifier' },
      { name: 'order_id', category: 'identifier', type: 'string', description: 'Transaction deduplication ID' }
    ],
    aliases: {
      em: 'email',
      hashed_email: 'email',
      user_identifiers_email: 'email',
      phone: 'phone_number',
      transaction_id: 'order_id'
    },
    validators: {
      email: isValidSha256,
      phone_number: isValidSha256,
      gclid: isValidGclid
    }
  },

  tiktok_events_api: {
    vendorId: 'tiktok_events_api',
    name: 'TikTok Events API',
    domains: ['business-api.tiktok.com', 'analytics.tiktok.com'],
    canonicalParameters: [
      'email',
      'phone',
      'ttp',
      'ttclid',
      'client_ip_address',
      'client_user_agent',
      'event_id',
      'external_id'
    ],
    parameterDetails: [
      { name: 'email', category: 'user_signal', type: 'SHA-256', description: 'Hashed email address', isCore: true },
      { name: 'phone', category: 'user_signal', type: 'SHA-256', description: 'Hashed phone number' },
      { name: 'ttp', category: 'identifier', type: 'Cookie', description: 'TikTok browser cookie (_ttp)', isCore: true },
      { name: 'ttclid', category: 'identifier', type: 'Click ID', description: 'TikTok click identifier' },
      { name: 'client_ip_address', category: 'event_context', type: 'IP', description: 'Client IP address' },
      { name: 'client_user_agent', category: 'event_context', type: 'User Agent', description: 'Client User Agent' },
      { name: 'event_id', category: 'identifier', type: 'UUID', description: 'Deduplication identifier', isCore: true }
    ],
    aliases: {
      em: 'email',
      ph: 'phone',
      _ttp: 'ttp',
      ip: 'client_ip_address',
      ua: 'client_user_agent',
      eventId: 'event_id'
    },
    validators: {
      email: isValidSha256,
      phone: isValidSha256,
      ttp: isValidTtp,
      ttclid: isValidTtclid,
      client_ip_address: isValidIp,
      client_user_agent: isValidUserAgent
    }
  },

  ga4_server: {
    vendorId: 'ga4_server',
    name: 'GA4 Server',
    domains: ['google-analytics.com', 'analytics.google.com'],
    canonicalParameters: [
      'client_id',
      'session_id',
      'user_id',
      'ip_override',
      'user_agent',
      'user_identifiers_email'
    ],
    parameterDetails: [
      { name: 'client_id', category: 'identifier', type: 'Cookie', description: 'Google Analytics client ID', isCore: true },
      { name: 'session_id', category: 'identifier', type: 'string', description: 'GA4 session identifier', isCore: true },
      { name: 'user_id', category: 'identifier', type: 'string', description: 'Known authenticated user ID' },
      { name: 'ip_override', category: 'event_context', type: 'IP', description: 'Client IP address override' },
      { name: 'user_identifiers_email', category: 'user_signal', type: 'SHA-256', description: 'Hashed email for Enhanced Conversions' }
    ],
    aliases: {
      cid: 'client_id',
      _ga: 'client_id',
      sid: 'session_id',
      _ga_session: 'session_id',
      uid: 'user_id',
      ip: 'ip_override',
      email: 'user_identifiers_email'
    },
    validators: {
      ip_override: isValidIp,
      user_identifiers_email: isValidSha256
    }
  },

  snapchat_conversions_api: {
    vendorId: 'snapchat_conversions_api',
    name: 'Snapchat Conversions API',
    domains: ['tr.snapchat.com'],
    canonicalParameters: [
      'email',
      'phone_number',
      'scid',
      'sccid',
      'client_ip_address',
      'client_user_agent',
      'event_id',
      'uuid_c1'
    ],
    parameterDetails: [
      { name: 'email', category: 'user_signal', type: 'SHA-256', description: 'Hashed customer email', isCore: true },
      { name: 'phone_number', category: 'user_signal', type: 'SHA-256', description: 'Hashed phone number' },
      { name: 'scid', category: 'identifier', type: 'Cookie', description: 'Snapchat browser cookie (_scid)', isCore: true },
      { name: 'sccid', category: 'identifier', type: 'Click ID', description: 'Snapchat click identifier' },
      { name: 'client_ip_address', category: 'event_context', type: 'IP', description: 'Client IP address' },
      { name: 'client_user_agent', category: 'event_context', type: 'User Agent', description: 'Client user agent' },
      { name: 'event_id', category: 'identifier', type: 'UUID', description: 'Deduplication identifier', isCore: true }
    ],
    aliases: {
      em: 'email',
      phone: 'phone_number',
      ph: 'phone_number',
      _scid: 'scid',
      ip: 'client_ip_address',
      ua: 'client_user_agent',
      eventId: 'event_id'
    },
    validators: {
      email: isValidSha256,
      phone_number: isValidSha256,
      scid: isValidScid,
      client_ip_address: isValidIp,
      client_user_agent: isValidUserAgent
    }
  },

  pinterest_api_for_conversions: {
    vendorId: 'pinterest_api_for_conversions',
    name: 'Pinterest API for Conversions',
    domains: ['ct.pinterest.com', 'api.pinterest.com'],
    canonicalParameters: [
      'em',
      'ph',
      'epik',
      'epclid',
      'client_ip_address',
      'client_user_agent',
      'event_id',
      'external_id'
    ],
    parameterDetails: [
      { name: 'em', category: 'user_signal', type: 'SHA-256', description: 'Hashed email address', isCore: true },
      { name: 'ph', category: 'user_signal', type: 'SHA-256', description: 'Hashed phone number' },
      { name: 'epik', category: 'identifier', type: 'Cookie', description: 'Pinterest browser cookie (_epik)', isCore: true },
      { name: 'epclid', category: 'identifier', type: 'Click ID', description: 'Pinterest click identifier' },
      { name: 'client_ip_address', category: 'event_context', type: 'IP', description: 'Client IP address' },
      { name: 'client_user_agent', category: 'event_context', type: 'User Agent', description: 'Client user agent' },
      { name: 'event_id', category: 'identifier', type: 'UUID', description: 'Deduplication identifier', isCore: true }
    ],
    aliases: {
      email: 'em',
      phone: 'ph',
      _epik: 'epik',
      ip: 'client_ip_address',
      ua: 'client_user_agent',
      eventId: 'event_id'
    },
    validators: {
      em: isValidSha256,
      ph: isValidSha256,
      epik: isValidEpik,
      client_ip_address: isValidIp,
      client_user_agent: isValidUserAgent
    }
  },

  linkedin_conversions_api: {
    vendorId: 'linkedin_conversions_api',
    name: 'LinkedIn Conversions API',
    domains: ['api.linkedin.com'],
    canonicalParameters: [
      'email',
      'li_fat_id',
      'first_name',
      'last_name',
      'company_name',
      'title',
      'country_code',
      'client_ip_address',
      'client_user_agent',
      'event_id',
      'external_id'
    ],
    parameterDetails: [
      { name: 'email', category: 'user_signal', type: 'SHA-256', description: 'Hashed email address (SHA-256)', isCore: true },
      { name: 'li_fat_id', category: 'identifier', type: 'Click ID', description: 'LinkedIn First-Party Ad Tracking ID (li_fat_id)', isCore: true },
      { name: 'first_name', category: 'user_signal', type: 'SHA-256', description: 'Hashed first name' },
      { name: 'last_name', category: 'user_signal', type: 'SHA-256', description: 'Hashed last name' },
      { name: 'company_name', category: 'user_signal', type: 'string', description: 'Company name' },
      { name: 'title', category: 'user_signal', type: 'string', description: 'Job title' },
      { name: 'country_code', category: 'user_signal', type: 'string', description: '2-letter ISO country code' },
      { name: 'client_ip_address', category: 'event_context', type: 'IP', description: 'Client IP address' },
      { name: 'client_user_agent', category: 'event_context', type: 'User Agent', description: 'Client user agent' },
      { name: 'event_id', category: 'identifier', type: 'UUID', description: 'Conversion deduplication ID', isCore: true }
    ],
    aliases: {
      em: 'email',
      fat_id: 'li_fat_id',
      linkedin_click_id: 'li_fat_id',
      fn: 'first_name',
      ln: 'last_name',
      ip: 'client_ip_address',
      ua: 'client_user_agent',
      eventId: 'event_id'
    },
    validators: {
      email: isValidSha256,
      li_fat_id: isValidLiFatId,
      first_name: isValidSha256,
      last_name: isValidSha256,
      client_ip_address: isValidIp,
      client_user_agent: isValidUserAgent
    }
  },

  generic: {
    vendorId: 'generic',
    name: 'Generic Tag Destination',
    domains: [],
    canonicalParameters: [
      'email',
      'event_id',
      'client_id',
      'ip',
      'user_agent'
    ],
    parameterDetails: [
      { name: 'email', category: 'user_signal', type: 'SHA-256', description: 'Hashed user email' },
      { name: 'event_id', category: 'identifier', type: 'UUID', description: 'Deduplication identifier' },
      { name: 'client_id', category: 'identifier', type: 'string', description: 'Client identifier' }
    ]
  }
};

export const VENDOR_SCHEMAS = CANONICAL_VENDOR_SCHEMAS;

/**
 * Returns canonical parameter list for a given vendor
 */
export function getVendorCanonicalParameters(vendorId: string): string[] {
  const norm = vendorId.toLowerCase().replace(/[^a-z0-9_]/g, '_');
  const found = CANONICAL_VENDOR_SCHEMAS[norm as StandardizedVendorId];
  return found ? found.canonicalParameters : CANONICAL_VENDOR_SCHEMAS.generic.canonicalParameters;
}
