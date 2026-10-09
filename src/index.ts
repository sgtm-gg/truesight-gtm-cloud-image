/**
 * @sgtm-gg/truesight-gtm-cloud-image
 * Hardened, auditable server-side Google Tag Manager container runtime
 * Consolidates AdBlock Shield (reverse proxy & cipher) and TrueSight Telemetry (interceptor & EMQ engine)
 * Zero external dependencies: pure TypeScript / Node.js & browser portable.
 */

// Proxy & Cipher
export {
  encryptXorBase64Url,
  decryptXorBase64Url,
  generateSecretKey,
  extractGtmId,
  DEFAULT_SECRET_KEY
} from './proxy/cipher';

// Client Loader Generators
export {
  generateClientLoaderSnippet,
  generateDeclarativeSnippet
} from './proxy/client-loader';

// Vendor Schemas & Format Validators
export {
  CANONICAL_VENDOR_SCHEMAS,
  VENDOR_SCHEMAS,
  getVendorCanonicalParameters,
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
  isValidUserAgent,
  type StandardizedVendorId,
  type CanonicalVendorParameter,
  type VendorSchemaDefinition
} from './telemetry/vendor-schemas';

// Algorithmic EMQ Engine & Schema Inventory
export {
  calculateMetaEmq,
  computeMetaCapiScore,
  calculateGoogleEmq,
  computeGoogleAdsEcScore,
  calculateTikTokEmq,
  computeTikTokScore,
  calculateGa4Emq,
  computeGA4Score,
  calculateSnapchatEmq,
  computeSnapchatScore,
  calculatePinterestEmq,
  computePinterestScore,
  calculateLinkedInEmq,
  computeLinkedInScore,
  computeGenericScore,
  calculatePlatformEmq,
  detectPlatformFromTag,
  getEmqTierLabel,
  getEmqGrade,
  analyzeSchemaInventory,
  normalizeCoverageRatio,
  isConversionEvent,
  type EmqPlatform,
  type EmqTier,
  type EmqGrade,
  type IdentitySignal,
  type EmqScoreResult,
  type EmqResult,
  type ParameterInventoryItem,
  type SchemaInventorySummary
} from './telemetry/emq-engine';

// Decoupled Error Ring Buffer & PII Sanitizer
export {
  canonicalizeErrorSignature,
  createErrorSignature,
  inspectDownstreamResponseBody,
  sanitizePayload,
  getRemediationGuidance,
  recordDownstreamError,
  getRecentErrors,
  clearRecentErrors,
  getErrorRingBufferStats,
  type DownstreamErrorRecord,
  type IngestErrorInput,
  type DownstreamInspectionResult
} from './telemetry/error-ring-buffer';
