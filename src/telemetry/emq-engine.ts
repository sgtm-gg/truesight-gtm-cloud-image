/**
 * Algorithmic Event Match Quality (EMQ) Engine
 * Canonical scoring models for server-side tag destinations across all 7 platforms:
 * 1. Meta CAPI (0.0 - 10.0 scale)
 * 2. Google Enhanced Conversions (0 - 100% scale, Active/Inactive)
 * 3. TikTok Events API (0.0 - 10.0 scale)
 * 4. GA4 Server (0.0 - 10.0 scale)
 * 5. Snapchat Conversions API (0.0 - 10.0 scale)
 * 6. Pinterest API for Conversions (0.0 - 10.0 scale)
 * 7. LinkedIn Conversions API (0.0 - 10.0 scale)
 *
 * Implements mathematical cliff guarding (100x ratio clamp, IEEE 754 guards, safe division).
 * Zero external dependencies: pure TypeScript / Node.js & browser portable.
 */

import {
  isValidSha256,
  isValidFbp,
  isValidFbc,
  isValidTtclid,
  isValidTtp,
  isValidScid,
  isValidEpik,
  isValidGclid,
  isValidLiFatId,
  isValidIp,
  isValidUserAgent
} from './vendor-schemas';

export type EmqPlatform =
  | 'Meta CAPI'
  | 'Google Enhanced Conversions'
  | 'TikTok Events API'
  | 'GA4 Server'
  | 'Snapchat Conversions API'
  | 'Pinterest API for Conversions'
  | 'LinkedIn Conversions API'
  | 'Generic';

export type EmqTier = 'Excellent' | 'Good' | 'Needs Attention' | 'Great' | 'Fair' | 'Poor';
export type EmqGrade = 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR';

export function getEmqTierLabel(score: number): 'Great' | 'Good' | 'Fair' | 'Poor' {
  if (score >= 8.0) return 'Great';
  if (score >= 6.0) return 'Good';
  if (score >= 3.5) return 'Fair';
  return 'Poor';
}

export function getEmqGrade(score: number): EmqGrade {
  if (score >= 8.0) return 'EXCELLENT';
  if (score >= 6.0) return 'GOOD';
  if (score >= 3.5) return 'FAIR';
  return 'POOR';
}

export interface IdentitySignal {
  key: string;
  name: string;
  coverage: number; // 0.0 - 1.0
  verified: boolean;
  weight: number;
  status: 'verified' | 'unnormalized' | 'missing';
  remediation?: string;
}

export interface EmqScoreResult {
  score: number;
  formattedScore: string;
  tier: EmqTier;
  grade: EmqGrade;
  platform: string;
  signals: IdentitySignal[];
  observedParameters: string[];
  missingCoreParameters: string[];
  deduplicationActive: boolean;
  dedupPenaltyApplied: boolean;
  dedupPenalty: number;
  ecStatus?: 'Active' | 'Inactive';
}

// EmqResult is an alias for EmqScoreResult
export type EmqResult = EmqScoreResult;

export interface ParameterInventoryItem {
  name: string;
  type: string;
  fillRate: number; // 0.0 - 1.0
  isValidFormat: boolean;
  isPiiMasked: boolean;
}

export interface SchemaInventorySummary {
  totalParameters: number;
  missingCoreParameters: string[];
  parameterInventory: ParameterInventoryItem[];
}

// ==============================================================================
// MATHEMATICAL CLIFF GUARDING & NORMALIZATION
// ==============================================================================

/**
 * Normalizes any count or ratio value into a [0.0, 1.0] coverage ratio.
 * Eliminates the 100x cliff where ratios between 1.0 and 1.5 were erroneously divided by 100.
 */
export function normalizeCoverageRatio(val: unknown, totalIngress: number = 1): number {
  if (typeof val !== 'number' || !Number.isFinite(val) || Number.isNaN(val)) {
    return 0.0;
  }

  const safeIngress = Math.max(1, typeof totalIngress === 'number' && Number.isFinite(totalIngress) ? totalIngress : 1);

  // If value is already in standard unit interval [0.0, 1.0]
  if (val >= 0.0 && val <= 1.0) {
    return Math.max(0.0, Math.min(1.0, val));
  }

  // Cliff Guarding: Ratios between 1.0 and 1.5 (due to clock skew or batch timing) clamp to 1.0 (100%)
  if (val > 1.0 && val <= 1.5) {
    return 1.0;
  }

  // Legacy percentage inputs (1.5 < val <= 100)
  if (val > 1.5 && val <= 100.0) {
    return Math.max(0.0, Math.min(1.0, val / 100.0));
  }

  // Raw count inputs (val > 100)
  return Math.max(0.0, Math.min(1.0, val / safeIngress));
}

export function isConversionEvent(eventName: string): boolean {
  const norm = (eventName || '').toLowerCase().trim();
  return (
    norm === 'purchase' ||
    norm === 'begin_checkout' ||
    norm === 'add_to_cart' ||
    norm === 'conversion' ||
    norm === 'lead' ||
    norm === 'subscribe' ||
    norm === 'complete_registration' ||
    norm === 'submit_application'
  );
}

interface SignalExtraction {
  coverage: number;
  verified: boolean;
  observedKey?: string;
  rawValue?: any;
}

function extractSignalCoverage(
  rawSignals: Record<string, any> = {},
  candidateKeys: string[],
  validator?: (val: unknown) => boolean,
  totalIngress: number = 1
): SignalExtraction {
  for (const key of candidateKeys) {
    if (key in rawSignals && rawSignals[key] !== undefined && rawSignals[key] !== null) {
      const signalData = rawSignals[key];
      let coverage = 0.0;
      let verified = false;
      let rawVal = signalData;

      if (typeof signalData === 'object' && signalData !== null) {
        rawVal = signalData.value !== undefined ? signalData.value : signalData;
        const count = typeof signalData.ok === 'number' ? signalData.ok : signalData.count;
        if (typeof signalData.fillRate === 'number') {
          coverage = normalizeCoverageRatio(signalData.fillRate, totalIngress);
        } else if (typeof count === 'number') {
          coverage = normalizeCoverageRatio(count, totalIngress);
        } else {
          coverage = 1.0;
        }

        if (signalData.err !== undefined) {
          verified = signalData.err === 0 && coverage > 0;
        } else if (validator && rawVal !== undefined) {
          verified = validator(rawVal);
        } else {
          verified = coverage > 0;
        }
      } else {
        coverage = normalizeCoverageRatio(signalData, totalIngress);
        verified = validator ? validator(rawVal) : coverage > 0;
      }

      return {
        coverage,
        verified,
        observedKey: key,
        rawValue: rawVal
      };
    }
  }

  return {
    coverage: 0.0,
    verified: false
  };
}

// ==============================================================================
// 1. META CAPI SCORING ENGINE (0.0 - 10.0)
// ==============================================================================

export function calculateMetaEmq(
  eventName: string,
  rawSignals: Record<string, any> = {},
  totalIngress: number = 1
): EmqScoreResult {
  const cEm = extractSignalCoverage(rawSignals, ['em', 'email', 'hashed_email'], isValidSha256, totalIngress);
  const cPh = extractSignalCoverage(rawSignals, ['ph', 'phone', 'hashed_phone'], isValidSha256, totalIngress);
  const cFbp = extractSignalCoverage(rawSignals, ['fbp', '_fbp'], isValidFbp, totalIngress);
  const cFbc = extractSignalCoverage(rawSignals, ['fbc', '_fbc'], isValidFbc, totalIngress);
  const cIp = extractSignalCoverage(rawSignals, ['ip', 'client_ip_address'], isValidIp, totalIngress);
  const cUa = extractSignalCoverage(rawSignals, ['ua', 'client_user_agent', 'user_agent'], isValidUserAgent, totalIngress);
  const cExt = extractSignalCoverage(rawSignals, ['ext', 'external_id', 'user_id'], undefined, totalIngress);
  const cDemo = extractSignalCoverage(rawSignals, ['fn', 'ln', 'ct', 'st', 'zp', 'country'], undefined, totalIngress);
  const cEventId = extractSignalCoverage(rawSignals, ['event_id', 'eventId', 'dedup_id'], undefined, totalIngress);

  const cIpUa = Math.min(cIp.coverage, cUa.coverage);
  const isConversion = isConversionEvent(eventName);
  const isMissingEventId = cEventId.coverage < 0.5;
  const dedupPenalty = isConversion && isMissingEventId ? 1.5 : 0.0;
  const dedupPenaltyApplied = dedupPenalty > 0;

  const rawScore =
    3.0 * cEm.coverage +
    1.8 * cPh.coverage +
    1.8 * cFbp.coverage +
    0.8 * cFbc.coverage +
    0.6 * cIp.coverage +
    0.5 * cUa.coverage +
    0.5 * cExt.coverage +
    0.4 * cDemo.coverage +
    0.9 * cEventId.coverage -
    dedupPenalty;

  const score = Math.max(0.0, Math.min(10.0, Math.round(rawScore * 10) / 10));
  const formattedScore = score.toFixed(1);

  const signals: IdentitySignal[] = [
    {
      key: 'em',
      name: 'Customer Email (em)',
      coverage: cEm.coverage,
      verified: cEm.verified,
      weight: 3.0,
      status: cEm.coverage >= 0.8 ? 'verified' : cEm.coverage > 0 ? 'unnormalized' : 'missing',
      remediation: cEm.coverage < 0.8 ? 'Ensure email is SHA-256 hashed and lowercase before passing to Meta.' : undefined
    },
    {
      key: 'ph',
      name: 'Customer Phone (ph)',
      coverage: cPh.coverage,
      verified: cPh.verified,
      weight: 1.8,
      status: cPh.coverage >= 0.8 ? 'verified' : cPh.coverage > 0 ? 'unnormalized' : 'missing'
    },
    {
      key: 'fbp',
      name: 'Browser ID (_fbp)',
      coverage: cFbp.coverage,
      verified: cFbp.verified,
      weight: 1.8,
      status: cFbp.coverage >= 0.8 ? 'verified' : 'missing'
    },
    {
      key: 'fbc',
      name: 'Click ID (_fbc)',
      coverage: cFbc.coverage,
      verified: cFbc.verified,
      weight: 0.8,
      status: cFbc.coverage >= 0.5 ? 'verified' : 'missing'
    },
    {
      key: 'ip_ua',
      name: 'Client IP & User Agent',
      coverage: cIpUa,
      verified: cIp.verified && cUa.verified,
      weight: 1.1,
      status: cIpUa >= 0.8 ? 'verified' : 'missing'
    },
    {
      key: 'event_id',
      name: 'Event ID Deduplication',
      coverage: cEventId.coverage,
      verified: !isMissingEventId,
      weight: 0.9,
      status: !isMissingEventId ? 'verified' : isConversion ? 'missing' : 'verified',
      remediation: dedupPenaltyApplied ? 'Missing event_id on conversion event: -1.5 deduplication penalty applied.' : undefined
    }
  ];

  const observedParameters = Object.keys(rawSignals);
  const coreParameters = ['em', 'fbp', 'event_id'];
  const missingCoreParameters = coreParameters.filter(p => !rawSignals[p]);

  return {
    score,
    formattedScore,
    tier: score >= 8.0 ? 'Excellent' : score >= 6.0 ? 'Good' : 'Needs Attention',
    grade: getEmqGrade(score),
    platform: 'Meta CAPI',
    signals,
    observedParameters,
    missingCoreParameters,
    deduplicationActive: !isMissingEventId,
    dedupPenaltyApplied,
    dedupPenalty
  };
}

export const computeMetaCapiScore = calculateMetaEmq;

// ==============================================================================
// 2. GOOGLE ENHANCED CONVERSIONS (0 - 100%)
// ==============================================================================

export function calculateGoogleEmq(
  _eventName: string,
  rawSignals: Record<string, any> = {},
  totalIngress: number = 1
): EmqScoreResult {
  const cEmail = extractSignalCoverage(rawSignals, ['email', 'em', 'hashed_email', 'user_identifiers_email'], isValidSha256, totalIngress);
  const cPhone = extractSignalCoverage(rawSignals, ['phone', 'phone_number', 'ph'], isValidSha256, totalIngress);
  const cAddress = extractSignalCoverage(rawSignals, ['address', 'postal_code', 'zp'], undefined, totalIngress);
  const cGclid = extractSignalCoverage(rawSignals, ['gclid', 'wbraid', 'gbraid'], isValidGclid, totalIngress);

  let score = 0;
  let ecStatus: 'Active' | 'Inactive' = 'Inactive';

  if (cEmail.coverage >= 0.80) {
    score = 100;
    ecStatus = 'Active';
  } else if (cEmail.coverage >= 0.50) {
    score = Math.round(50 + (cEmail.coverage - 0.50) * 100);
    ecStatus = 'Active';
  } else {
    score = Math.round(cEmail.coverage * 98);
    ecStatus = 'Inactive';
  }

  const signals: IdentitySignal[] = [
    {
      key: 'email',
      name: 'Hashed Customer Email (Decisive Signal)',
      coverage: cEmail.coverage,
      verified: cEmail.verified,
      weight: 100,
      status: cEmail.coverage >= 0.80 ? 'verified' : cEmail.coverage > 0 ? 'unnormalized' : 'missing',
      remediation: cEmail.coverage < 0.50 ? 'Google Enhanced Conversions requires >= 50% normalized SHA-256 hashed emails to remain Active.' : undefined
    },
    {
      key: 'phone',
      name: 'Hashed Phone Number',
      coverage: cPhone.coverage,
      verified: cPhone.verified,
      weight: 0,
      status: cPhone.coverage >= 0.80 ? 'verified' : 'missing'
    },
    {
      key: 'gclid',
      name: 'Google Click ID (gclid)',
      coverage: cGclid.coverage,
      verified: cGclid.verified,
      weight: 0,
      status: cGclid.coverage >= 0.50 ? 'verified' : 'missing'
    },
    {
      key: 'address',
      name: 'Customer Postal Address',
      coverage: cAddress.coverage,
      verified: cAddress.verified,
      weight: 0,
      status: cAddress.coverage >= 0.50 ? 'verified' : 'missing'
    }
  ];

  const formattedScore = `${score}%`;
  const observedParameters = Object.keys(rawSignals);
  const missingCoreParameters = cEmail.coverage >= 0.5 ? [] : ['email'];

  return {
    score,
    formattedScore,
    tier: score >= 80 ? 'Excellent' : score >= 50 ? 'Good' : 'Needs Attention',
    grade: score >= 80 ? 'EXCELLENT' : score >= 50 ? 'GOOD' : 'POOR',
    platform: 'Google Enhanced Conversions',
    signals,
    observedParameters,
    missingCoreParameters,
    deduplicationActive: true,
    dedupPenaltyApplied: false,
    dedupPenalty: 0.0,
    ecStatus
  };
}

export const computeGoogleAdsEcScore = calculateGoogleEmq;

// ==============================================================================
// 3. TIKTOK EVENTS API SCORING (0.0 - 10.0)
// ==============================================================================

export function calculateTikTokEmq(
  eventName: string,
  rawSignals: Record<string, any> = {},
  totalIngress: number = 1
): EmqScoreResult {
  const cEmail = extractSignalCoverage(rawSignals, ['email', 'em', 'hashed_email'], isValidSha256, totalIngress);
  const cPhone = extractSignalCoverage(rawSignals, ['phone', 'ph', 'hashed_phone'], isValidSha256, totalIngress);
  const cTtp = extractSignalCoverage(rawSignals, ['ttp', '_ttp'], isValidTtp, totalIngress);
  const cTtclid = extractSignalCoverage(rawSignals, ['ttclid'], isValidTtclid, totalIngress);
  const cIp = extractSignalCoverage(rawSignals, ['ip', 'client_ip_address'], isValidIp, totalIngress);
  const cUa = extractSignalCoverage(rawSignals, ['ua', 'client_user_agent', 'user_agent'], isValidUserAgent, totalIngress);
  const cExt = extractSignalCoverage(rawSignals, ['ext', 'external_id', 'user_id'], undefined, totalIngress);
  const cEventId = extractSignalCoverage(rawSignals, ['event_id', 'eventId', 'dedup_id'], undefined, totalIngress);

  const cIpUa = Math.min(cIp.coverage, cUa.coverage);
  const isConversion = isConversionEvent(eventName);
  const isMissingEventId = cEventId.coverage < 0.5;
  const dedupPenalty = isConversion && isMissingEventId ? 1.5 : 0.0;
  const dedupPenaltyApplied = dedupPenalty > 0;

  const rawScore =
    3.0 * cEmail.coverage +
    1.8 * cPhone.coverage +
    1.8 * cTtp.coverage +
    1.1 * cIpUa +
    0.8 * cTtclid.coverage +
    0.6 * cExt.coverage +
    0.9 * cEventId.coverage -
    dedupPenalty;

  const score = Math.max(0.0, Math.min(10.0, Math.round(rawScore * 10) / 10));
  const formattedScore = score.toFixed(1);

  const signals: IdentitySignal[] = [
    {
      key: 'email',
      name: 'Customer Email',
      coverage: cEmail.coverage,
      verified: cEmail.verified,
      weight: 3.0,
      status: cEmail.coverage >= 0.8 ? 'verified' : 'missing'
    },
    {
      key: 'ttp',
      name: 'TikTok Cookie (_ttp)',
      coverage: cTtp.coverage,
      verified: cTtp.verified,
      weight: 1.8,
      status: cTtp.coverage >= 0.8 ? 'verified' : 'missing'
    },
    {
      key: 'ttclid',
      name: 'TikTok Click ID (ttclid)',
      coverage: cTtclid.coverage,
      verified: cTtclid.verified,
      weight: 0.8,
      status: cTtclid.coverage >= 0.5 ? 'verified' : 'missing'
    },
    {
      key: 'ip_ua',
      name: 'Client IP & User Agent',
      coverage: cIpUa,
      verified: cIp.verified && cUa.verified,
      weight: 1.1,
      status: cIpUa >= 0.8 ? 'verified' : 'missing'
    },
    {
      key: 'event_id',
      name: 'Event ID Deduplication',
      coverage: cEventId.coverage,
      verified: !isMissingEventId,
      weight: 0.9,
      status: !isMissingEventId ? 'verified' : 'missing'
    }
  ];

  return {
    score,
    formattedScore,
    tier: score >= 8.0 ? 'Excellent' : score >= 6.0 ? 'Good' : 'Needs Attention',
    grade: getEmqGrade(score),
    platform: 'TikTok Events API',
    signals,
    observedParameters: Object.keys(rawSignals),
    missingCoreParameters: cEmail.coverage < 0.5 ? ['email'] : [],
    deduplicationActive: !isMissingEventId,
    dedupPenaltyApplied,
    dedupPenalty
  };
}

export const computeTikTokScore = calculateTikTokEmq;

// ==============================================================================
// 4. GA4 SERVER SCORING (0.0 - 10.0)
// ==============================================================================

export function calculateGa4Emq(
  _eventName: string,
  rawSignals: Record<string, any> = {},
  totalIngress: number = 1
): EmqScoreResult {
  const cEmail = extractSignalCoverage(rawSignals, ['email', 'em', 'hashed_email', 'user_identifiers_email'], isValidSha256, totalIngress);
  const cClientId = extractSignalCoverage(rawSignals, ['client_id', 'cid', '_ga'], undefined, totalIngress);
  const cUserId = extractSignalCoverage(rawSignals, ['user_id', 'uid'], undefined, totalIngress);
  const cSessionId = extractSignalCoverage(rawSignals, ['session_id', 'sid', '_ga_session'], undefined, totalIngress);
  const cIp = extractSignalCoverage(rawSignals, ['ip', 'client_ip_address', 'ip_override'], isValidIp, totalIngress);

  const rawScore =
    4.0 * cClientId.coverage +
    3.0 * cUserId.coverage +
    2.0 * cSessionId.coverage +
    1.0 * cIp.coverage;

  const score = Math.max(0.0, Math.min(10.0, Math.round(rawScore * 10) / 10));
  const formattedScore = score.toFixed(1);
  const isEmailActive = cEmail.coverage > 0 && cEmail.verified;

  const signals: IdentitySignal[] = [
    {
      key: 'client_id',
      name: 'GA4 Client ID (client_id)',
      coverage: cClientId.coverage,
      verified: cClientId.verified,
      weight: 4.0,
      status: cClientId.coverage >= 0.8 ? 'verified' : 'missing'
    },
    {
      key: 'session_id',
      name: 'GA4 Session ID (session_id)',
      coverage: cSessionId.coverage,
      verified: cSessionId.verified,
      weight: 2.0,
      status: cSessionId.coverage >= 0.8 ? 'verified' : 'missing'
    },
    {
      key: 'user_id',
      name: 'Authenticated User ID (user_id)',
      coverage: cUserId.coverage,
      verified: cUserId.verified,
      weight: 3.0,
      status: cUserId.coverage >= 0.5 ? 'verified' : 'missing'
    }
  ];

  return {
    score,
    formattedScore,
    tier: score >= 8.0 ? 'Excellent' : score >= 6.0 ? 'Good' : 'Needs Attention',
    grade: getEmqGrade(score),
    platform: 'GA4 Server',
    signals,
    observedParameters: Object.keys(rawSignals),
    missingCoreParameters: cClientId.coverage < 0.5 ? ['client_id'] : [],
    deduplicationActive: true,
    dedupPenaltyApplied: false,
    dedupPenalty: 0.0,
    ecStatus: isEmailActive ? 'Active' : 'Inactive'
  };
}

export const computeGA4Score = calculateGa4Emq;

// ==============================================================================
// 5. SNAPCHAT CONVERSIONS API SCORING (0.0 - 10.0)
// ==============================================================================

export function calculateSnapchatEmq(
  eventName: string,
  rawSignals: Record<string, any> = {},
  totalIngress: number = 1
): EmqScoreResult {
  const cEmail = extractSignalCoverage(rawSignals, ['email', 'em', 'hashed_email'], isValidSha256, totalIngress);
  const cPhone = extractSignalCoverage(rawSignals, ['phone', 'ph', 'phone_number'], isValidSha256, totalIngress);
  const cScid = extractSignalCoverage(rawSignals, ['scid', '_scid'], isValidScid, totalIngress);
  const cSccid = extractSignalCoverage(rawSignals, ['sccid'], undefined, totalIngress);
  const cIp = extractSignalCoverage(rawSignals, ['ip', 'client_ip_address'], isValidIp, totalIngress);
  const cUa = extractSignalCoverage(rawSignals, ['ua', 'client_user_agent', 'user_agent'], isValidUserAgent, totalIngress);
  const cExt = extractSignalCoverage(rawSignals, ['ext', 'external_id', 'user_id'], undefined, totalIngress);
  const cEventId = extractSignalCoverage(rawSignals, ['event_id', 'eventId', 'dedup_id'], undefined, totalIngress);

  const cIpUa = Math.min(cIp.coverage, cUa.coverage);
  const isConversion = isConversionEvent(eventName);
  const isMissingEventId = cEventId.coverage < 0.5;
  const dedupPenalty = isConversion && isMissingEventId ? 1.5 : 0.0;
  const dedupPenaltyApplied = dedupPenalty > 0;

  const rawScore =
    3.0 * cEmail.coverage +
    1.8 * cPhone.coverage +
    1.8 * cScid.coverage +
    1.1 * cIpUa +
    0.8 * cSccid.coverage +
    0.6 * cExt.coverage +
    0.9 * cEventId.coverage -
    dedupPenalty;

  const score = Math.max(0.0, Math.min(10.0, Math.round(rawScore * 10) / 10));
  const formattedScore = score.toFixed(1);

  return {
    score,
    formattedScore,
    tier: score >= 8.0 ? 'Excellent' : score >= 6.0 ? 'Good' : 'Needs Attention',
    grade: getEmqGrade(score),
    platform: 'Snapchat Conversions API',
    signals: [],
    observedParameters: Object.keys(rawSignals),
    missingCoreParameters: cEmail.coverage < 0.5 ? ['email'] : [],
    deduplicationActive: !isMissingEventId,
    dedupPenaltyApplied,
    dedupPenalty
  };
}

export const computeSnapchatScore = calculateSnapchatEmq;

// ==============================================================================
// 6. PINTEREST API FOR CONVERSIONS SCORING (0.0 - 10.0)
// ==============================================================================

export function calculatePinterestEmq(
  eventName: string,
  rawSignals: Record<string, any> = {},
  totalIngress: number = 1
): EmqScoreResult {
  const cEmail = extractSignalCoverage(rawSignals, ['em', 'email', 'hashed_email'], isValidSha256, totalIngress);
  const cPhone = extractSignalCoverage(rawSignals, ['ph', 'phone'], isValidSha256, totalIngress);
  const cEpik = extractSignalCoverage(rawSignals, ['epik', '_epik'], isValidEpik, totalIngress);
  const cEpclid = extractSignalCoverage(rawSignals, ['epclid'], undefined, totalIngress);
  const cIp = extractSignalCoverage(rawSignals, ['ip', 'client_ip_address'], isValidIp, totalIngress);
  const cUa = extractSignalCoverage(rawSignals, ['ua', 'client_user_agent', 'user_agent'], isValidUserAgent, totalIngress);
  const cExt = extractSignalCoverage(rawSignals, ['ext', 'external_id', 'user_id'], undefined, totalIngress);
  const cEventId = extractSignalCoverage(rawSignals, ['event_id', 'eventId', 'dedup_id'], undefined, totalIngress);

  const cIpUa = Math.min(cIp.coverage, cUa.coverage);
  const isConversion = isConversionEvent(eventName);
  const isMissingEventId = cEventId.coverage < 0.5;
  const dedupPenalty = isConversion && isMissingEventId ? 1.5 : 0.0;
  const dedupPenaltyApplied = dedupPenalty > 0;

  const rawScore =
    3.0 * cEmail.coverage +
    1.8 * cPhone.coverage +
    1.8 * cEpik.coverage +
    1.1 * cIpUa +
    0.8 * cEpclid.coverage +
    0.5 * cExt.coverage +
    0.9 * cEventId.coverage -
    dedupPenalty;

  const score = Math.max(0.0, Math.min(10.0, Math.round(rawScore * 10) / 10));
  const formattedScore = score.toFixed(1);

  return {
    score,
    formattedScore,
    tier: score >= 8.0 ? 'Excellent' : score >= 6.0 ? 'Good' : 'Needs Attention',
    grade: getEmqGrade(score),
    platform: 'Pinterest API for Conversions',
    signals: [],
    observedParameters: Object.keys(rawSignals),
    missingCoreParameters: cEmail.coverage < 0.5 ? ['em'] : [],
    deduplicationActive: !isMissingEventId,
    dedupPenaltyApplied,
    dedupPenalty
  };
}

export const computePinterestScore = calculatePinterestEmq;

// ==============================================================================
// 7. LINKEDIN CONVERSIONS API SCORING (0.0 - 10.0)
// ==============================================================================

/**
 * LinkedIn Conversions API EMQ Formula:
 * Score = min(10.0, max(0.0, 3.0*C_em + 2.5*C_li_fat_id + 1.5*C_user_data + 1.1*C_ip_ua + 1.0*C_ext + 0.9*C_event_id - P_dedup))
 * Deduplication penalty P_dedup = 1.5 if event_id is missing on conversion events.
 */
export function calculateLinkedInEmq(
  eventName: string,
  rawSignals: Record<string, any> = {},
  totalIngress: number = 1
): EmqScoreResult {
  const cEmail = extractSignalCoverage(rawSignals, ['email', 'em', 'hashed_email'], isValidSha256, totalIngress);
  const cLiFatId = extractSignalCoverage(rawSignals, ['li_fat_id', 'fat_id', 'linkedin_click_id'], isValidLiFatId, totalIngress);
  const cUserData = extractSignalCoverage(rawSignals, ['first_name', 'last_name', 'company_name', 'title'], undefined, totalIngress);
  const cIp = extractSignalCoverage(rawSignals, ['ip', 'client_ip_address'], isValidIp, totalIngress);
  const cUa = extractSignalCoverage(rawSignals, ['ua', 'client_user_agent', 'user_agent'], isValidUserAgent, totalIngress);
  const cExt = extractSignalCoverage(rawSignals, ['ext', 'user_id', 'external_id'], undefined, totalIngress);
  const cEventId = extractSignalCoverage(rawSignals, ['event_id', 'eventId', 'dedup_id'], undefined, totalIngress);

  const cIpUa = Math.min(cIp.coverage, cUa.coverage);
  const isConversion = isConversionEvent(eventName);
  const isMissingEventId = cEventId.coverage < 0.5;
  const dedupPenalty = isConversion && isMissingEventId ? 1.5 : 0.0;
  const dedupPenaltyApplied = dedupPenalty > 0;

  const rawScore =
    3.0 * cEmail.coverage +
    2.5 * cLiFatId.coverage +
    1.5 * cUserData.coverage +
    1.1 * cIpUa +
    1.0 * cExt.coverage +
    0.9 * cEventId.coverage -
    dedupPenalty;

  const score = Math.max(0.0, Math.min(10.0, Math.round(rawScore * 10) / 10));
  const formattedScore = score.toFixed(1);

  const signals: IdentitySignal[] = [
    {
      key: 'email',
      name: 'Customer Email (SHA-256)',
      coverage: cEmail.coverage,
      verified: cEmail.verified,
      weight: 3.0,
      status: cEmail.coverage >= 0.8 ? 'verified' : cEmail.coverage > 0 ? 'unnormalized' : 'missing',
      remediation: cEmail.coverage < 0.8 ? 'Pass SHA-256 hashed lowercase email to LinkedIn CAPI.' : undefined
    },
    {
      key: 'li_fat_id',
      name: 'LinkedIn Click Tracking ID (li_fat_id)',
      coverage: cLiFatId.coverage,
      verified: cLiFatId.verified,
      weight: 2.5,
      status: cLiFatId.coverage >= 0.5 ? 'verified' : 'missing'
    },
    {
      key: 'ip_ua',
      name: 'Client IP & User Agent',
      coverage: cIpUa,
      verified: cIp.verified && cUa.verified,
      weight: 1.1,
      status: cIpUa >= 0.8 ? 'verified' : 'missing'
    },
    {
      key: 'event_id',
      name: 'Conversion Deduplication ID',
      coverage: cEventId.coverage,
      verified: !isMissingEventId,
      weight: 0.9,
      status: !isMissingEventId ? 'verified' : 'missing'
    }
  ];

  return {
    score,
    formattedScore,
    tier: score >= 8.0 ? 'Excellent' : score >= 6.0 ? 'Good' : 'Needs Attention',
    grade: getEmqGrade(score),
    platform: 'LinkedIn Conversions API',
    signals,
    observedParameters: Object.keys(rawSignals),
    missingCoreParameters: cEmail.coverage < 0.5 ? ['email'] : [],
    deduplicationActive: !isMissingEventId,
    dedupPenaltyApplied,
    dedupPenalty
  };
}

export const computeLinkedInScore = calculateLinkedInEmq;

// ==============================================================================
// 8. GENERIC SCORING & UNIVERSAL DISPATCHER
// ==============================================================================

export function computeGenericScore(
  eventName: string,
  rawSignals: Record<string, any> = {},
  totalIngress: number = 1
): EmqScoreResult {
  const res = calculateMetaEmq(eventName, rawSignals, totalIngress);
  return {
    ...res,
    platform: 'Generic'
  };
}

export function detectPlatformFromTag(platformOrTagName: string): EmqPlatform {
  const norm = (platformOrTagName || '').toLowerCase();
  if (norm.includes('meta') || norm.includes('facebook') || norm.includes('capi')) {
    return 'Meta CAPI';
  }
  if (norm.includes('enhanced') || norm.includes('gads') || (norm.includes('google') && !norm.includes('analytics') && !norm.includes('ga4'))) {
    return 'Google Enhanced Conversions';
  }
  if (norm.includes('tiktok')) {
    return 'TikTok Events API';
  }
  if (norm.includes('ga4') || norm.includes('analytics')) {
    return 'GA4 Server';
  }
  if (norm.includes('snap') || norm.includes('snapchat')) {
    return 'Snapchat Conversions API';
  }
  if (norm.includes('pin') || norm.includes('pinterest')) {
    return 'Pinterest API for Conversions';
  }
  if (norm.includes('linkedin') || norm.includes('li_')) {
    return 'LinkedIn Conversions API';
  }
  return 'Generic';
}

export function calculatePlatformEmq(
  platformOrTagName: string,
  eventName: string,
  signals: Record<string, any> = {},
  totalIngress: number = 1
): EmqScoreResult {
  const platform = detectPlatformFromTag(platformOrTagName);

  switch (platform) {
    case 'Meta CAPI':
      return calculateMetaEmq(eventName, signals, totalIngress);
    case 'Google Enhanced Conversions':
      return calculateGoogleEmq(eventName, signals, totalIngress);
    case 'TikTok Events API':
      return calculateTikTokEmq(eventName, signals, totalIngress);
    case 'GA4 Server':
      return calculateGa4Emq(eventName, signals, totalIngress);
    case 'Snapchat Conversions API':
      return calculateSnapchatEmq(eventName, signals, totalIngress);
    case 'Pinterest API for Conversions':
      return calculatePinterestEmq(eventName, signals, totalIngress);
    case 'LinkedIn Conversions API':
      return calculateLinkedInEmq(eventName, signals, totalIngress);
    default:
      return computeGenericScore(eventName, signals, totalIngress);
  }
}

// ==============================================================================
// 9. SCHEMA INVENTORY ANALYZER
// ==============================================================================

export function analyzeSchemaInventory(
  eventName: string,
  parameters: Record<string, any> = {}
): SchemaInventorySummary {
  const inventory: ParameterInventoryItem[] = [];
  const lowerEvent = (eventName || '').toLowerCase();

  const coreParametersMap: Record<string, string[]> = {
    purchase: ['currency', 'value', 'transaction_id', 'items'],
    begin_checkout: ['currency', 'value', 'items'],
    add_to_cart: ['currency', 'value', 'items'],
    view_item: ['currency', 'value', 'items']
  };

  const coreParams = coreParametersMap[lowerEvent] || [];
  const missingCoreParameters: string[] = [];

  for (const [name, rawInfo] of Object.entries(parameters)) {
    let type = 'string';
    let fillRate = 1.0;
    let isValidFormat = true;
    let isPiiMasked = false;

    if (rawInfo && typeof rawInfo === 'object') {
      type = rawInfo.type || (typeof rawInfo.value) || 'string';
      fillRate = typeof rawInfo.fillRate === 'number' ? rawInfo.fillRate : (rawInfo.count ? Math.min(1.0, rawInfo.count / 100) : 1.0);
      isValidFormat = rawInfo.isValidFormat !== undefined ? Boolean(rawInfo.isValidFormat) : (rawInfo.err === 0);
      isPiiMasked = rawInfo.isPiiMasked !== undefined ? Boolean(rawInfo.isPiiMasked) : false;
    }

    const lowerName = name.toLowerCase();
    if (lowerName.includes('email') || lowerName.includes('em') || lowerName.includes('phone') || lowerName.includes('ph')) {
      isPiiMasked = true;
      if (typeof rawInfo === 'string') {
        isValidFormat = isValidSha256(rawInfo);
      }
    }

    inventory.push({
      name,
      type,
      fillRate,
      isValidFormat,
      isPiiMasked
    });
  }

  for (const cp of coreParams) {
    const found = inventory.find(i => i.name.toLowerCase() === cp.toLowerCase());
    if (!found || found.fillRate <= 0) {
      missingCoreParameters.push(cp);
    }
  }

  return {
    totalParameters: inventory.length,
    missingCoreParameters,
    parameterInventory: inventory
  };
}
