# TrueSight sGTM Cloud Container (`@sgtm-gg/truesight-gtm-cloud-image`)

> **Repository**: [https://github.com/sgtm-gg/truesight-gtm-cloud-image](https://github.com/sgtm-gg/truesight-gtm-cloud-image)  
> **Canonical Image**: `ghcr.io/sgtm-gg/truesight-gtm-cloud-image:stable`  
> **Base Image**: `gcr.io/cloud-tagging-10302018/gtm-cloud-image:stable` (Google's official sGTM runtime)  
> **Version**: 1.0.0  
> **Classification**: Public / Auditable TrueSight Container Architecture  
> **Compliance Profile**: GDPR (Art. 25 & 32), SOC 2 Type II (Trust Services Criteria), HIPAA Safe Harbor (45 CFR § 164.514(b))  
> **License**: Apache-2.0  

---

## 1. Executive Summary & Philosophy

`@sgtm-gg/truesight-gtm-cloud-image` is an open-source, auditable, zero-dependency server-side Google Tag Manager (sGTM) container runtime and utility engine. It consolidates both sgtm.gg Power-Ups into a single, hardened execution layer:

1. **AdBlock Shield**: First-party reverse proxy, obfuscated client loader, XOR transport cipher, and same-origin ingress tunnel.
2. **TrueSight Telemetry & Data Quality**: Zero-touch outbound hook for all 7 advertising platforms, in-memory error ring buffer, recursive PII sanitizer, and algorithmic Event Match Quality (EMQ) engine.

### Zero-SaaS Dependency Guarantee
Unlike proprietary black-box tagging SaaS platforms that route your customer web traffic through multi-tenant intermediary proxy servers, **the TrueSight container runs 100% within your own Google Cloud Platform (GCP) project on Google Cloud Run.**

- **Zero dependencies** on Next.js, NextAuth, Drizzle ORM, Turso DB, SQLite, or proprietary SaaS routes.
- **Zero raw event storage**: Customer event data flows directly from the visitor's browser to your Cloud Run container, and onward directly to downstream ad networks (Meta, Google, TikTok, GA4, Snapchat, Pinterest, LinkedIn).
- **Pure Node.js built-ins**: The runtime relies exclusively on standard Node.js libraries (`http`, `https`, `crypto`, `url`, `perf_hooks`), eliminating third-party npm supply-chain CVE vulnerabilities.

---

## 2. Infrastructure Architecture & Inside-Out Data Lifecycle

```
+---------------------------------------------------------------------------------------------------+
|                                     CUSTOMER GCP CLOUD INFRASTRUCTURE                             |
|                                                                                                   |
|  [ Visitor Browser ]                                                                              |
|         │                                                                                         |
|         │ 1. Ingress: HTTPS (/fps or /g/collect)                                                  |
|         ▼                                                                                         |
|  +─────────────────────────────────────────────────────────────────────────────────────────────+  |
|  | Google Cloud Run Service (Customer's Own Dedicated GCP Project)                            |  |
|  |                                                                                             |  |
|  |   ┌────────────────────────┐         ┌──────────────────────────────────────────────────┐   |  |
|  |   │ Official sGTM Base     │         │ TrueSight Outbound Interceptor                   │   |  |
|  |   │ (Google Cloud Tagging) │◄────────┤ - Intercepts outbound HTTP/HTTPS/fetch to 7 nets │   |  |
|  |   │ Tag Execution Engine   │         │ - Measures status codes & latency (ms)           │   |  |
|  |   │ (Port 8081 - Internal) │         │ - Zero value buffering (Schema keys only)        │   |  |
|  |   └───────────┬────────────┘         └────────────────────────┬─────────────────────────┘   |  |
|  |               │                                               │                             |  |
|  |               │                                               │ Local Batch Queue (10s)     |  |
|  |               │                                               ▼                             |  |
|  |               │                      ┌──────────────────────────────────────────────────┐   |  |
|  |               │                      │ Ingress Reverse Proxy (Port 8080 - Public)       │   |  |
|  |               │                      │ - /fps/loader.js & /metrics/t/:id XOR tunnel     │   |  |
|  |               │                      │ - In-memory rolling ring buffer (max 5/tuple)    │   |  |
|  |               │                      │ - Recursive PII scrubbing & dead-man flush       │   |  |
|  |               │                      └────────────────────────┬─────────────────────────┘   |  |
|  |   ┌───────────┴────────────────────────┐                      │                             |  |
|  |   │ entrypoint.js (Process Supervisor) │                      │                             |  |
|  |   │ - Spawns sGTM + Proxy co-term      │                      │                             |  |
|  |   │ - Injects NODE_OPTIONS into sGTM   │                      │                             |  |
|  |   │ - Scrubs NODE_OPTIONS from proxy   │                      │                             |  |
|  |   └────────────────────────────────────┘                      │                             |  |
|  +───────────────┼───────────────────────────────────────────────┼─────────────────────────────+  |
|                  │                                               │                                |
|                  ▼ 2. Direct Marketing Egress Tag Calls          ▼ 3. Telemetry Stream            |
|          (Direct to Advertising Platforms)                 (Aggregated Statistical Counts Only)   |
|         +────────┴───────────────────────────+           +───────┴─────────────────────────────+  |
|         ▼                                    ▼           ▼                                     ▼  |
|  [ Meta Graph API ]                [ Google Ads EC ]              [ Operational Dashboard ]       |
+---------------------------------------------------------------------------------------------------+
```

---

## 3. Component Inventory & Specification

### 3.1 Container Infrastructure
- **`Dockerfile`**: Hardened multi-stage container build layering runtime assets over Google's official stable image:
  ```dockerfile
  FROM gcr.io/cloud-tagging-10302018/gtm-cloud-image:stable AS production
  ```
  Runs as non-root `USER node` and provides native `/healthz` container health checking.
- **`entrypoint.js`**: Pure Node.js process supervisor managing Cloud Run container lifecycle. Spawns upstream sGTM on internal port 8081 and reverse proxy on public port 8080. Dynamically injects `--require ./src/telemetry/interceptor.js` into sGTM upstream `NODE_OPTIONS` while scrubbing `NODE_OPTIONS` from proxy to prevent circular interception loops. Enforces process co-termination and graceful signal forwarding.

### 3.2 AdBlock Shield (Proxy & Cipher)
- **`src/proxy/server.js`**: Pure Node.js reverse proxy handling:
  - `/healthz`: Liveness probe.
  - `/fps/loader.js` (and legacy `/icefall/loader.js`): Dynamic client bootstrapper with encrypted GTM ID.
  - `/fps/asset` (and legacy `/icefall/asset`): Dependency proxy for Google Tag Manager scripts with origin header stripping.
  - `/fps/gtm.js` (and legacy `/icefall/gtm.js`): Standard and debug Tag Assistant pass-through.
  - `*/sw.js`: Custom service worker serving client-side tunnel encryption.
  - `/metrics/t/:id` (and legacy `/fps/t/:id`, `/sherpa/t/:id`): Ingress decryption, event name extraction with prototype defense, and upstream sGTM forwarding.
  - `/__ts_local_ingest`: Ingress-egress telemetry fusion endpoint.
- **`src/proxy/cipher.ts`**: URL-Safe Base64 XOR cipher and 4-stage GTM container ID parser handling direct tokens, URL-encoded values, query strings, and Base64 environment configurations.
- **`src/proxy/client-loader.ts`**: Client snippet generator for:
  - **Mode A (Obfuscated Shield)**: XOR transport encryption, fetch/sendBeacon traps, and HTMLScriptElement descriptor rewrites.
  - **Mode B (Declarative Mode)**: Standard non-monkey-patching GTM `transport_url` mode for high-security environments.

### 3.3 TrueSight Telemetry & PII Sanitizer
- **`src/telemetry/interceptor.js`**: Zero-touch outbound hook monkey-patching `http.request`, `https.request`, and `global.fetch`. Automatically detects dispatches to Meta CAPI, Google Ads, TikTok Events API, GA4, Pinterest CAPI, Snapchat CAPI, and LinkedIn CAPI. Extracts latency and parameter presence without buffering body content.
- **`src/telemetry/error-ring-buffer.ts`**: In-memory rolling LRU ring buffer capped at 5 distinct errors per tuple. Deduplicates errors via normalized MD5 signatures (`${statusCode}:${md5}`) and strips volatile dynamic IDs (UUIDs, timestamps, trace IDs). Contains recursive PII scrubber (`sanitizePayload`).
- **`src/telemetry/vendor-schemas.ts`**: Canonical schema definitions and format validators (`isValidSha256`, `isValidFbp`, `isValidFbc`, `isValidTtclid`, `isValidTtp`, `isValidScid`, `isValidEpik`, `isValidGclid`, `isValidLiFatId`, `isValidIp`, `isValidUserAgent`) across all 7 marketing platforms.
- **`src/telemetry/emq-engine.ts`**: Algorithmic EMQ scoring functions for all 7 platforms with mathematical cliff guarding (100x ratio clamp, IEEE 754 bounds, and safe division).

---

## 4. Zero-PII Guarantees & Privacy Safeguards (Zero-PII Guarantee)

The TrueSight Runtime container enforces zero Personally Identifiable Information (PII) retention across all operational layers:

1. **Zero Raw Value Buffering**: Outbound hooks inspect only structural parameter presence (e.g. `has 'em'`, `has 'ph'`) and validity booleans (`{ ok: 1, err: 0 }`). Parameter values are never copied into memory stores.
2. **Deterministic PII Scrubbing**: When downstream vendor rejections (HTTP 4xx/5xx) are diagnosed in the ring buffer, `sanitizePayload` traverses the JSON tree and redacts:
   - Advertising Click IDs: `gclid`, `fbclid`, `ttclid`, `li_fat_id`, `msclkid`, `wbraid`, etc. -> `[REDACTED_CLICK_ID]`
   - User Identifiers: `user_id`, `customer_id`, `client_id`, `visitor_id` -> `[REDACTED_USER_ID]`
   - Operational Identifiers (Preserved): `event_id`, `device_id`, `tag_id`, `server_id` are strictly preserved for deduplication auditability.
   - Hashed Contact Signals: Valid 64-char SHA-256 hashes are truncated as `sha256:abc12345...89ef` to demonstrate format validity without leaking full hash strings.
   - Raw Contact Signals: Cleartext emails masked as `***@domain.com`, phones masked as `+1***-***-1234`.
   - URL Query Strings: Parameters on `page_location` and `event_source_url` are stripped at the first `?`.
3. **Ephemeral Volatile Lifecycle**: Ring buffers reside strictly in transient process memory (capped at 5 entries per tuple). No files, databases, SQLite instances, or logs are written to the container filesystem.
4. **Cloud Run Auto-Recycling**: Container memory is immediately wiped when Cloud Run instances scale down to zero.

---

## 5. Regulatory Compliance Mapping

| Standard | Clause / Article | How TrueSight Container Runtime Complies |
| :--- | :--- | :--- |
| **GDPR** | **Article 25**<br>*Data Protection by Design & Default* | Deployments run within customer's chosen regional cloud boundary (e.g., `europe-west3` Frankfurt). Customer web traffic never leaves the customer's cloud boundary or transits multi-tenant vendor clusters. Telemetry consists solely of aggregated statistical counters. |
| **GDPR** | **Article 32**<br>*Security of Processing* | XOR transport encryption for browser-to-server ingress, non-root container execution (`USER node`), process co-termination, automated health monitoring (`/healthz`), and zero credential storage in containers. |
| **SOC 2 Type II** | **Trust Services Criteria**<br>*Security, Processing Integrity, Confidentiality* | Complete open-source transparency: zero proprietary binaries, zero hidden telemetry channels. Outbound requests are directed solely to authorized vendor endpoints and customer monitoring targets. |
| **HIPAA** | **Safe Harbor Method**<br>*(45 CFR § 164.514(b))* | Comprehensive redaction of all 18 HIPAA identifiers: names, dates, phone numbers, email addresses, IP addresses, URLs, device identifiers, and account IDs are stripped before error diagnostic recording. |

---

## 6. Verification & Auditing Commands

### Standalone Repository Commands (from cloned repository root)
```bash
# Install development dependencies
npm install

# Validate TypeScript compilation
npm run build
# or: npx tsc --noEmit

# Execute standalone test suite (22 unit assertions)
npm test
# or: npx tsx tests/test-runtime.ts
```
*Expected output: Exits with code 0 (zero errors, 100% assertions pass).*

### Monorepo Integration Commands (from sgtm-manager root)
```bash
# Standalone TypeScript check
npx tsc --project packages/open-sgtm-runtime/tsconfig.json --noEmit

# Standalone test execution
npx tsx packages/open-sgtm-runtime/tests/test-runtime.ts

# CI drift prevention & zero-leakage AST scan (19 gate assertions)
npm run powerups:verify
```
*Verifies 0 imports of `@/db`, `@/auth`, `next-auth`, `drizzle-orm`, or internal SaaS routes.*
