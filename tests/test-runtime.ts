/**
 * Standalone Independent Test Suite for @sgtm-gg/truesight-gtm-cloud-image
 * Exercises proxy routing, cipher roundtrips, snippet generation,
 * PII sanitization, ring buffer LRU eviction, and EMQ scoring across all 7 platforms.
 *
 * Runs in 100% process isolation: zero external dependencies, zero database, zero Next.js.
 */

import assert from 'node:assert';
import http from 'node:http';
import {
  encryptXorBase64Url,
  decryptXorBase64Url,
  generateSecretKey,
  extractGtmId,
  DEFAULT_SECRET_KEY
} from '../src/proxy/cipher';
import {
  generateClientLoaderSnippet,
  generateDeclarativeSnippet
} from '../src/proxy/client-loader';
import {
  CANONICAL_VENDOR_SCHEMAS,
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
} from '../src/telemetry/vendor-schemas';
import {
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
  calculatePlatformEmq,
  getEmqTierLabel,
  getEmqGrade,
  analyzeSchemaInventory,
  normalizeCoverageRatio
} from '../src/telemetry/emq-engine';
import {
  canonicalizeErrorSignature,
  createErrorSignature,
  inspectDownstreamResponseBody,
  sanitizePayload,
  getRemediationGuidance,
  recordDownstreamError,
  getRecentErrors,
  clearRecentErrors,
  getErrorRingBufferStats
} from '../src/telemetry/error-ring-buffer';

// Require proxy server & interceptor modules
const proxyModule = require('../src/proxy/server');
const interceptor = require('../src/telemetry/interceptor');

// ANSI Colors for test reporter
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const CYAN = '\x1b[36m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function test(name: string, fn: () => void | Promise<void>) {
  try {
    const res = fn();
    if (res && typeof res.then === 'function') {
      return res
        .then(() => {
          console.log(`  ${GREEN}✓${RESET} ${name}`);
          passed++;
        })
        .catch((err: any) => {
          console.error(`  ${RED}✗${RESET} ${name}`);
          console.error(`    ${RED}${err.message || err}${RESET}`);
          failed++;
          failures.push(`${name}: ${err.message || err}`);
        });
    } else {
      console.log(`  ${GREEN}✓${RESET} ${name}`);
      passed++;
    }
  } catch (err: any) {
    console.error(`  ${RED}✗${RESET} ${name}`);
    console.error(`    ${RED}${err.message || err}${RESET}`);
    failed++;
    failures.push(`${name}: ${err.message || err}`);
  }
}

async function runAllTests() {
  console.log(`\n${BOLD}${CYAN}================================================================${RESET}`);
  console.log(`${BOLD}${CYAN}  @sgtm-gg/truesight-gtm-cloud-image — Standalone Test Suite${RESET}`);
  console.log(`${BOLD}${CYAN}================================================================${RESET}\n`);

  // ============================================================================
  // GROUP 1: CIPHER UTILITIES & GTM CONTAINER ID EXTRACTION
  // ============================================================================
  console.log(`${BOLD}Group 1: Cipher Utilities & GTM ID Extraction${RESET}`);

  test('1.1 XOR Base64Url encryption and decryption roundtrip', () => {
    const secret = 'customSecretKey1';
    const plaintexts = [
      'GTM-ABC1234',
      '/g/collect?v=2&en=purchase|||item=123',
      'special-chars-~!@#$%^&*()_+={}:"<>?',
      'a'.repeat(200)
    ];

    for (const text of plaintexts) {
      const encrypted = encryptXorBase64Url(text, secret);
      assert.ok(encrypted.length > 0);
      assert.strictEqual(encrypted.includes('+'), false, 'URL-safe: no +');
      assert.strictEqual(encrypted.includes('/'), false, 'URL-safe: no /');
      assert.strictEqual(encrypted.includes('='), false, 'URL-safe: no =');
      const decrypted = decryptXorBase64Url(encrypted, secret);
      assert.strictEqual(decrypted, text, `Roundtrip failed for: ${text}`);
    }
  });

  test('1.2 Cipher handles empty and invalid inputs gracefully', () => {
    assert.strictEqual(encryptXorBase64Url('', 'key'), '');
    assert.strictEqual(decryptXorBase64Url('', 'key'), '');
    assert.strictEqual(decryptXorBase64Url('invalid-base64!', 'key'), '');
  });

  test('1.3 generateSecretKey creates cryptographically secure 16-char keys', () => {
    const key1 = generateSecretKey();
    const key2 = generateSecretKey(32);
    assert.strictEqual(key1.length, 16);
    assert.strictEqual(key2.length, 32);
    assert.notStrictEqual(key1, key2);
    assert.ok(/^[a-zA-Z0-9]+$/.test(key1));
  });

  test('1.4 extractGtmId parses all multi-format container configurations', () => {
    // Direct plain format
    assert.strictEqual(extractGtmId('GTM-ABC1234'), 'GTM-ABC1234');
    assert.strictEqual(extractGtmId('gtm-lowercase'), 'GTM-LOWERCASE');

    // Quoted strings
    assert.strictEqual(extractGtmId('"GTM-QUOTED1"'), 'GTM-QUOTED1');
    assert.strictEqual(extractGtmId("'GTM-QUOTED2'"), 'GTM-QUOTED2');

    // CONTAINER_CONFIG= prefix
    assert.strictEqual(extractGtmId('CONTAINER_CONFIG=GTM-PREFIX1'), 'GTM-PREFIX1');
    assert.strictEqual(extractGtmId('"CONTAINER_CONFIG=GTM-PREFIX2"'), 'GTM-PREFIX2');

    // Query strings
    assert.strictEqual(extractGtmId('id=GTM-QUERY1&env=1'), 'GTM-QUERY1');
    assert.strictEqual(extractGtmId('https://example.com?env=1&id=GTM-QUERY2'), 'GTM-QUERY2');

    // URL-encoded strings
    assert.strictEqual(extractGtmId('id%3DGTM-URLENC1'), 'GTM-URLENC1');

    // Base64 encoded payload
    const b64Payload = Buffer.from('id=GTM-BASE64TEST&env=2').toString('base64');
    assert.strictEqual(extractGtmId(b64Payload), 'GTM-BASE64TEST');

    // Fallbacks
    assert.strictEqual(extractGtmId(''), 'GTM-XXXXXXX');
    assert.strictEqual(extractGtmId(null), 'GTM-XXXXXXX');
    assert.strictEqual(extractGtmId(undefined), 'GTM-XXXXXXX');
    assert.strictEqual(extractGtmId('invalid_random_string'), 'GTM-XXXXXXX');
  });

  // ============================================================================
  // GROUP 2: CLIENT LOADER SNIPPET GENERATORS
  // ============================================================================
  console.log(`\n${BOLD}Group 2: Client Loader Snippet Generators${RESET}`);

  test('2.1 generateClientLoaderSnippet produces valid Obfuscated Shield snippet', () => {
    const snippetPath = generateClientLoaderSnippet('/fps', 'GTM-TEST123', 'testKeySecret123', '/metrics');
    assert.ok(snippetPath.includes('<!-- Google Tag Manager (Icefall Adblock Shield) -->'));
    assert.ok(snippetPath.includes("var L='/fps/loader.js';"));
    assert.ok(snippetPath.includes("s.src=L+'?data='+D;"));
    assert.ok(snippetPath.includes('/metrics/t/'));
    assert.ok(snippetPath.includes('HTMLScriptElement.prototype'));
    assert.ok(snippetPath.includes('window.fetch'));
    assert.ok(snippetPath.includes('navigator.sendBeacon'));
    assert.ok(snippetPath.includes('<iframe src="/fps/ns.html?id=GTM-TEST123"'));

    const snippetUrl = generateClientLoaderSnippet('https://sst.brand.com', 'GTM-TEST456', 'testKeySecret123');
    assert.ok(snippetUrl.includes("var L='https://sst.brand.com/icefall/loader.js';"));
    assert.ok(snippetUrl.includes("var T='https://sst.brand.com/icefall/t/'+Math.random()"));
  });

  test('2.2 generateDeclarativeSnippet produces clean standard transport_url snippet', () => {
    const snippet = generateDeclarativeSnippet('https://sst.brand.com', 'GTM-STANDARD');
    assert.ok(snippet.includes('<!-- Google Tag Manager (Declarative sGTM Mode - Non-Invasive) -->'));
    assert.ok(snippet.includes("gtag('set', 'transport_url', 'https://sst.brand.com');"));
    assert.ok(snippet.includes("https://sst.brand.com/gtm.js?id='+i"));
    assert.ok(snippet.includes("'GTM-STANDARD'"));
    assert.strictEqual(snippet.includes('HTMLScriptElement.prototype'), false, 'Zero monkey-patching in declarative mode');
  });

  // ============================================================================
  // GROUP 3: PROXY SERVER & INGRESS TALLYING
  // ============================================================================
  console.log(`\n${BOLD}Group 3: Pure Node.js Reverse Proxy & Ingress Tallying${RESET}`);

  test('3.1 Ingress Event Extraction and Prototype Defense', () => {
    const { extractEventNames, sanitizeEventName } = proxyModule;

    // GA4 query string
    assert.deepStrictEqual(extractEventNames('v=2&en=Purchase&tid=G-123', null), ['purchase']);
    // Form encoded
    assert.deepStrictEqual(extractEventNames('', 'v=2&en=add_to_cart'), ['add_to_cart']);
    // JSON single
    assert.deepStrictEqual(extractEventNames('', JSON.stringify({ name: 'sign_up' })), ['sign_up']);
    assert.deepStrictEqual(extractEventNames('', JSON.stringify({ eventName: 'begin_checkout' })), ['begin_checkout']);
    // Measurement Protocol v2 batch
    assert.deepStrictEqual(extractEventNames('', JSON.stringify({
      events: [{ name: 'item1' }, { eventName: 'item2' }, { en: 'item3' }]
    })), ['item1', 'item2', 'item3']);
    // Bare token
    assert.deepStrictEqual(extractEventNames('', 'custom_lead_event'), ['custom_lead_event']);
    // Empty fallback
    assert.deepStrictEqual(extractEventNames('', ''), ['page_view']);
    assert.deepStrictEqual(extractEventNames(null, undefined), ['page_view']);

    // Prototype pollution defense
    assert.deepStrictEqual(extractEventNames('en=__proto__', null), ['page_view']);
    assert.deepStrictEqual(extractEventNames('en=constructor', null), ['page_view']);
    assert.deepStrictEqual(extractEventNames('en=prototype', null), ['page_view']);
    assert.strictEqual(sanitizeEventName('__proto__'), 'page_view');
    assert.strictEqual(sanitizeEventName('constructor'), 'page_view');

    // Injection & length clamping
    assert.strictEqual(sanitizeEventName('<script>alert(1)</script>'), 'page_view');
    assert.strictEqual(sanitizeEventName("'; DROP TABLE--"), 'page_view');
    assert.strictEqual(sanitizeEventName('a'.repeat(100)).length, 64);
  });

  test('3.2 In-Memory Ingress Buffer Cardinality & Atomic Draining', () => {
    const { recordIngress, getPendingIngress, drainPendingIngress, resetIngressBuffer } = proxyModule;

    resetIngressBuffer();
    recordIngress('purchase', 2);
    recordIngress('view_item', 1);

    const pending = getPendingIngress();
    assert.deepStrictEqual(pending, { purchase: 2, view_item: 1 });

    // Atomic drain
    const drained = drainPendingIngress();
    assert.deepStrictEqual(drained, { purchase: 2, view_item: 1 });
    assert.strictEqual(drainPendingIngress(), null, 'Drain on empty returns null');
    assert.deepStrictEqual(getPendingIngress(), {});

    // Cardinality bounding (100 distinct keys + other_events)
    resetIngressBuffer();
    for (let i = 0; i < 150; i++) {
      recordIngress(`distinct_event_${i}`, 1);
    }
    const bounded = getPendingIngress();
    const keys = Object.keys(bounded);
    assert.ok(keys.length <= 101, 'Keys capped at 100 + other_events');
    assert.strictEqual(bounded['other_events'], 50, 'Excess 50 events accumulate in other_events');
    resetIngressBuffer();
  });

  await test('3.3 Live HTTP Reverse Proxy Endpoints', async () => {
    const { app, resetIngressBuffer, getPendingIngress } = proxyModule;
    resetIngressBuffer();

    const PROXY_TEST_PORT = 19580;
    const SGTM_TEST_PORT = 19581;

    // Spin up mock upstream sGTM
    const upstreamRequests: any[] = [];
    const mockSgtm = http.createServer((req, res) => {
      let b = '';
      req.on('data', c => { b += c; });
      req.on('end', () => {
        upstreamRequests.push({ url: req.url, method: req.method, body: b, headers: req.headers });
        res.writeHead(204, { 'content-type': 'text/plain' });
        res.end();
      });
    });

    await new Promise(r => mockSgtm.listen(SGTM_TEST_PORT, '127.0.0.1', () => r(null)));

    process.env.SGTM_INTERNAL_PORT = String(SGTM_TEST_PORT);
    process.env.SGTM_UPSTREAM_URL = `http://127.0.0.1:${SGTM_TEST_PORT}`;
    process.env.SECRET_KEY = DEFAULT_SECRET_KEY;

    const proxyServer: any = await new Promise(r => {
      const s = app.listen(PROXY_TEST_PORT, '127.0.0.1', () => r(s));
    });

    try {
      // Helper for HTTP requests
      const request = (path: string, options: any = {}, body?: string) => {
        return new Promise<any>((resolve, reject) => {
          const req = http.request({
            hostname: '127.0.0.1',
            port: PROXY_TEST_PORT,
            path,
            ...options
          }, res => {
            let data = '';
            res.on('data', c => { data += c; });
            res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body: data }));
          });
          req.on('error', reject);
          if (body) req.write(body);
          req.end();
        });
      };

      // 1. /healthz
      const healthRes = await request('/healthz');
      assert.strictEqual(healthRes.statusCode, 200);
      assert.ok(healthRes.body.includes('"status":"ok"'));

      // 2. /fps/loader.js with valid encrypted GTM ID
      const encId = encryptXorBase64Url('GTM-LIVE001', DEFAULT_SECRET_KEY);
      const loaderRes = await request(`/fps/loader.js?data=${encId}`);
      assert.strictEqual(loaderRes.statusCode, 200);
      assert.ok(loaderRes.body.includes('/fps/gtm.js?id=GTM-LIVE001'));

      // 3. /fps/loader.js with bad ID
      const badLoaderRes = await request('/fps/loader.js?data=invalid_crypto');
      assert.strictEqual(badLoaderRes.statusCode, 400);

      // 4. Encrypted tunnel /metrics/t/test_tunnel
      const tunnelPayload = '/g/collect?v=2&en=purchase|||item_sku=999';
      const encTunnel = encryptXorBase64Url(tunnelPayload, DEFAULT_SECRET_KEY);
      const tunnelRes = await request(`/metrics/t/session123?${encTunnel}`);
      assert.strictEqual(tunnelRes.statusCode, 204);

      // Verify upstream sGTM received proxied hit
      assert.strictEqual(upstreamRequests.length, 1);
      assert.strictEqual(upstreamRequests[0].body, 'item_sku=999');
      assert.strictEqual(upstreamRequests[0].method, 'POST');

      // Verify ingress count was tallied
      const pending = getPendingIngress();
      assert.strictEqual(pending['purchase'], 1);

      // 5. /__ts_local_ingest (fuses with pending ingress)
      const ingestPayload = JSON.stringify({ w: 'test_api_key', e: 'purchase', tags: { 'Meta CAPI': { s: 1, f: 0 } } });
      const ingestRes = await request('/__ts_local_ingest', {
        method: 'POST',
        headers: { 'content-type': 'application/json' }
      }, ingestPayload);
      assert.strictEqual(ingestRes.statusCode, 204);

      // Buffer was drained into ingest
      assert.deepStrictEqual(getPendingIngress(), {});
    } finally {
      await new Promise(r => proxyServer.close(r));
      await new Promise(r => mockSgtm.close(r));
    }
  });

  // ============================================================================
  // GROUP 4: TRUESIGHT TELEMETRY INTERCEPTOR & VENDOR IDENTIFICATION
  // ============================================================================
  console.log(`\n${BOLD}Group 4: TrueSight Telemetry Interceptor Hook${RESET}`);

  test('4.1 Vendor Matching across all 7 platforms', () => {
    const { matchVendor, isInternalTraffic } = interceptor;

    assert.strictEqual(matchVendor('graph.facebook.com', '/v18.0/events'), 'Meta CAPI');
    assert.strictEqual(matchVendor('googleadservices.com', '/pagead/conversion'), 'Google Ads');
    assert.strictEqual(matchVendor('business-api.tiktok.com', '/open_api/v1.3/event/track'), 'TikTok');
    assert.strictEqual(matchVendor('analytics.google.com', '/g/collect'), 'GA4 Server');
    assert.strictEqual(matchVendor('tr.snapchat.com', '/v2/conversion'), 'Snapchat Conversions API');
    assert.strictEqual(matchVendor('api.pinterest.com', '/v5/ad_accounts/123/events'), 'Pinterest API for Conversions');
    assert.strictEqual(matchVendor('api.linkedin.com', '/rest/conversionEvents'), 'LinkedIn Conversions API');
    assert.strictEqual(matchVendor('unknown-site.org', '/test'), null);

    // Mock header overrides
    assert.strictEqual(matchVendor('127.0.0.1', '/', { 'x-mock-vendor': 'Meta CAPI' }), 'Meta CAPI');

    // Loop prevention & internal traffic
    assert.strictEqual(isInternalTraffic('127.0.0.1', '/test'), true);
    assert.strictEqual(isInternalTraffic('remote.com', '/__ts_local_ingest'), true);
    assert.strictEqual(isInternalTraffic('remote.com', '/healthz'), true);
    assert.strictEqual(isInternalTraffic('remote.com', '/test', { 'x-truesight-internal': '1' }), true);
    assert.strictEqual(isInternalTraffic('graph.facebook.com', '/events'), false);
  });

  test('4.2 Interceptor Validation Helpers', () => {
    const { validateNumeric, validateString, validateStringOrArray } = interceptor;

    // Numeric
    assert.strictEqual(validateNumeric(100).ok, 1);
    assert.strictEqual(validateNumeric('49.99').ok, 1);
    assert.strictEqual(validateNumeric(0).ok, 1);
    assert.strictEqual(validateNumeric(null).err, 1);
    assert.strictEqual(validateNumeric('NaN').err, 1);
    assert.strictEqual(validateNumeric(true).err, 1);
    assert.strictEqual(validateNumeric([]).err, 1);

    // String
    assert.strictEqual(validateString('USD').ok, 1);
    assert.strictEqual(validateString('').err, 1);
    assert.strictEqual(validateString('   ').err, 1);
    assert.strictEqual(validateString(null).err, 1);

    // String or Array
    assert.strictEqual(validateStringOrArray(['hash1', 'hash2']).ok, 1);
    assert.strictEqual(validateStringOrArray('single_hash').ok, 1);
    assert.strictEqual(validateStringOrArray([]).err, 1);
    assert.strictEqual(validateStringOrArray(['   ']).err, 1);
  });

  test('4.3 Outbound Interceptor Payload Parsers', () => {
    const { parseMetaPayload, parseTikTokPayload, parseGA4Payload, parseGoogleAdsPayload, parseLinkedInPayload } = interceptor;

    // Meta
    const metaBuf = Buffer.from(JSON.stringify({
      data: [{ event_name: 'Purchase', custom_data: { value: 120, currency: 'USD', order_id: 'ORD-1' } }]
    }));
    const meta = parseMetaPayload(metaBuf);
    assert.strictEqual(meta.eventName, 'purchase');
    assert.strictEqual(meta.vars.value.ok, 1);
    assert.strictEqual(meta.vars.currency.ok, 1);
    assert.strictEqual(meta.vars.order_id.ok, 1);

    // TikTok
    const ttBuf = Buffer.from(JSON.stringify({ event: 'CompletePayment', properties: { value: 80, currency: 'EUR' } }));
    const tt = parseTikTokPayload(ttBuf);
    assert.strictEqual(tt.eventName, 'completepayment');
    assert.strictEqual(tt.vars.value.ok, 1);

    // GA4
    const ga4 = parseGA4Payload({ search: '?en=purchase&ep.value=50&ep.currency=USD' }, Buffer.alloc(0));
    assert.strictEqual(ga4.eventName, 'purchase');
    assert.strictEqual(ga4.vars.value.ok, 1);

    // Google Ads
    const gads = parseGoogleAdsPayload({ search: '?value=200&currency_code=USD' }, Buffer.alloc(0));
    assert.strictEqual(gads.eventName, 'conversion');
    assert.strictEqual(gads.vars.value.ok, 1);

    // LinkedIn
    const liBuf = Buffer.from(JSON.stringify({ elements: [{ conversionHappenedAt: 123456, totalBudget: 500, currencyCode: 'USD' }] }));
    const li = parseLinkedInPayload(liBuf);
    assert.strictEqual(li.eventName, 'conversion');
    assert.strictEqual(li.vars.value.ok, 1);
  });

  // ============================================================================
  // GROUP 5: ERROR RING BUFFER & RECURSIVE PII SANITIZATION
  // ============================================================================
  console.log(`\n${BOLD}Group 5: Error Ring Buffer & Recursive PII Sanitization${RESET}`);

  test('5.1 canonicalizeErrorSignature deduplicates dynamic tokens', () => {
    const err1 = 'Meta CAPI: Order ID order_id: 1234-abcd with trace fbtrace_id: xyz987 at 2026-09-20T10:00:00Z failed';
    const err2 = 'Meta CAPI: Order ID order_id: 5678-efgh with trace fbtrace_id: abc123 at 2026-09-20T10:05:00Z failed';

    const sig1 = canonicalizeErrorSignature(400, err1);
    const sig2 = canonicalizeErrorSignature(400, err2);
    assert.strictEqual(sig1, sig2, 'Dynamic IDs and timestamps must normalize to identical signature');
    assert.ok(sig1.startsWith('400:'));
  });

  test('5.2 recordDownstreamError enforces 5-item rolling LRU cap per tuple', () => {
    clearRecentErrors();

    const serverId = 'srv_test_1';
    const tag = 'Meta CAPI';
    const event = 'purchase';

    // Record 8 distinct errors
    for (let i = 1; i <= 8; i++) {
      recordDownstreamError(serverId, tag, event, {
        statusCode: 400,
        vendorError: `Unique Rejection #${i}`,
        payload: { attempt: i }
      });
    }

    const errors = getRecentErrors(serverId, tag, event);
    assert.strictEqual(errors.length, 5, 'Ring buffer strictly capped at 5 distinct errors per tuple');
    // Most recent is at head
    assert.strictEqual(errors[0].vendorError, 'Unique Rejection #8');
    assert.strictEqual(errors[4].vendorError, 'Unique Rejection #4');

    clearRecentErrors();
  });

  test('5.3 sanitizePayload recursively strips PII while strictly preserving operational IDs', () => {
    const rawPayload = {
      event_id: 'evt_preserve_123',
      device_id: 'dev_preserve_456',
      tag_id: 'tag_789',
      server_id: 'srv_999',
      id: 'op_id_111',
      // PII to redact:
      email: 'john.doe@example.com',
      phone: '+1-555-123-4567',
      user_id: 'crm_user_secret',
      gclid: 'Cj0KCQjw_ClickId12345',
      fbclid: 'IwAR2ClickId67890',
      li_fat_id: 'li_click_secret_id',
      token: 'bearer_token_super_secret',
      apiKey: 'master_api_key',
      page_location: 'https://example.com/checkout?gclid=leak123&email=leak@domain.com',
      nested: {
        customer_id: 'nested_cust_123',
        ip: '192.168.1.100',
        text: 'Customer email is alice@test.org in comment'
      }
    };

    const sanitized = sanitizePayload(rawPayload);

    // Operational IDs preserved
    assert.strictEqual(sanitized.event_id, 'evt_preserve_123');
    assert.strictEqual(sanitized.device_id, 'dev_preserve_456');
    assert.strictEqual(sanitized.tag_id, 'tag_789');
    assert.strictEqual(sanitized.server_id, 'srv_999');
    assert.strictEqual(sanitized.id, 'op_id_111');

    // Click IDs redacted
    assert.strictEqual(sanitized.gclid, '[REDACTED_CLICK_ID]');
    assert.strictEqual(sanitized.fbclid, '[REDACTED_CLICK_ID]');
    assert.strictEqual(sanitized.li_fat_id, '[REDACTED_CLICK_ID]');

    // User identifiers redacted
    assert.strictEqual(sanitized.user_id, '[REDACTED_USER_ID]');
    assert.strictEqual(sanitized.nested.customer_id, '[REDACTED_USER_ID]');

    // Secrets redacted
    assert.strictEqual(sanitized.token, '[REDACTED_SECRET]');
    assert.strictEqual(sanitized.apiKey, '[REDACTED_SECRET]');

    // Email & phone masked
    assert.strictEqual(sanitized.email, '***@example.com');
    assert.strictEqual(sanitized.phone, '+1***-***-4567');

    // IP subnet masked
    assert.strictEqual(sanitized.nested.ip, '192.168.***.***');

    // URL querystring stripped
    assert.strictEqual(sanitized.page_location, 'https://example.com/checkout');

    // Free text email masked
    assert.strictEqual(sanitized.nested.text, 'Customer email is ***@test.org in comment');
  });

  test('5.4 inspectDownstreamResponseBody detects masked errors behind HTTP 200', () => {
    // Meta CAPI code 190
    const metaRes = inspectDownstreamResponseBody('Meta CAPI', 200, { error: { message: 'Token expired', code: 190 } });
    assert.strictEqual(metaRes.isError, true);
    assert.strictEqual(metaRes.statusCode, 401);

    // TikTok code 40001
    const ttRes = inspectDownstreamResponseBody('TikTok', 200, { code: 40001, message: 'Invalid token' });
    assert.strictEqual(ttRes.isError, true);
    assert.strictEqual(ttRes.statusCode, 401);

    // Google Ads partial failure
    const gadsRes = inspectDownstreamResponseBody('Google Ads', 200, { partial_failure_error: { message: 'Action not found' } });
    assert.strictEqual(gadsRes.isError, true);
    assert.strictEqual(gadsRes.statusCode, 400);

    // Clean HTTP 200
    const cleanRes = inspectDownstreamResponseBody('Meta CAPI', 200, { events_received: 1 });
    assert.strictEqual(cleanRes.isError, false);
  });

  // ============================================================================
  // GROUP 6: CANONICAL SCHEMAS & ALGORITHMIC EMQ SCORING (7 PLATFORMS)
  // ============================================================================
  console.log(`\n${BOLD}Group 6: Algorithmic EMQ Engine & Canonical Schemas (7 Platforms)${RESET}`);

  test('6.1 Canonical Format Validators', () => {
    const validSha = 'a'.repeat(64);
    assert.strictEqual(isValidSha256(validSha), true);
    assert.strictEqual(isValidSha256('not-sha'), false);
    assert.strictEqual(isValidSha256(validSha.toUpperCase()), false, 'Must be lowercase');

    assert.strictEqual(isValidFbp('fb.1.12345678.987654321'), true);
    assert.strictEqual(isValidFbp('bad_fbp'), false);

    assert.strictEqual(isValidFbc('fb.1.12345678.AbCdEf123'), true);
    assert.strictEqual(isValidFbc('bad_fbc'), false);

    assert.strictEqual(isValidGclid('Cj0KCQjw_ClickId12345'), true);
    assert.strictEqual(isValidLiFatId('li_fat_id_valid_token'), true);
    assert.strictEqual(isValidTtclid('ttclid_valid_token'), true);
    assert.strictEqual(isValidTtp('ttp_cookie_val'), true);
    assert.strictEqual(isValidScid('scid_cookie_val'), true);
    assert.strictEqual(isValidEpik('epik_cookie_val'), true);

    assert.strictEqual(isValidIp('203.0.113.195'), true);
    assert.strictEqual(isValidIp('2001:db8::1'), true);
    assert.strictEqual(isValidIp('not_an_ip'), false);

    assert.strictEqual(isValidUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64)'), true);
    assert.strictEqual(isValidUserAgent('short'), false);
  });

  test('6.2 Meta CAPI EMQ Scoring with deduplication penalty', () => {
    const sha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    // Healthy conversion event with all signals
    const goodMeta = calculateMetaEmq('purchase', {
      em: { value: sha, ok: 100, err: 0 },
      ph: { value: sha, ok: 100, err: 0 },
      fbp: { value: 'fb.1.123.456', ok: 100, err: 0 },
      fbc: { value: 'fb.1.123.abc', ok: 100, err: 0 },
      ip: { value: '203.0.113.1', ok: 100, err: 0 },
      ua: { value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', ok: 100, err: 0 },
      event_id: { value: 'evt_123', ok: 100, err: 0 }
    }, 100);

    assert.ok(goodMeta.score >= 8.0, `Meta score should be Excellent (got ${goodMeta.score})`);
    assert.strictEqual(goodMeta.tier, 'Excellent');
    assert.strictEqual(goodMeta.dedupPenaltyApplied, false);

    // Missing event_id on purchase incurs -1.5 penalty
    const missingDedup = calculateMetaEmq('purchase', {
      em: { value: sha, ok: 100, err: 0 },
      fbp: { value: 'fb.1.123.456', ok: 100, err: 0 }
    }, 100);

    assert.strictEqual(missingDedup.dedupPenaltyApplied, true);
    assert.strictEqual(missingDedup.dedupPenalty, 1.5);
  });

  test('6.3 Google Enhanced Conversions Scoring (Active / Inactive)', () => {
    const sha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    // >= 80% email coverage -> 100% Active
    const gActive = calculateGoogleEmq('purchase', {
      email: { value: sha, ok: 85, err: 0 }
    }, 100);
    assert.strictEqual(gActive.score, 100);
    assert.strictEqual(gActive.ecStatus, 'Active');

    // < 50% email coverage -> Inactive
    const gInactive = calculateGoogleEmq('purchase', {
      email: { value: sha, ok: 40, err: 0 }
    }, 100);
    assert.ok(gInactive.score < 50);
    assert.strictEqual(gInactive.ecStatus, 'Inactive');
  });

  test('6.4 All 7 Advertising Platforms Score Correctly', () => {
    const sha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const mockSignals = {
      em: { value: sha, ok: 100, err: 0 },
      email: { value: sha, ok: 100, err: 0 },
      client_id: { value: 'ga.123.456', ok: 100, err: 0 },
      session_id: { value: 'sid_123', ok: 100, err: 0 },
      ttp: { value: 'ttp_cookie', ok: 100, err: 0 },
      scid: { value: 'scid_cookie', ok: 100, err: 0 },
      epik: { value: 'epik_cookie', ok: 100, err: 0 },
      li_fat_id: { value: 'li_fat_12345678', ok: 100, err: 0 },
      event_id: { value: 'evt_123', ok: 100, err: 0 }
    };

    const meta = computeMetaCapiScore('purchase', mockSignals, 100);
    const google = computeGoogleAdsEcScore('purchase', mockSignals, 100);
    const tiktok = computeTikTokScore('purchase', mockSignals, 100);
    const ga4 = computeGA4Score('purchase', mockSignals, 100);
    const snap = computeSnapchatScore('purchase', mockSignals, 100);
    const pin = computePinterestScore('purchase', mockSignals, 100);
    const linkedin = computeLinkedInScore('purchase', mockSignals, 100);

    assert.ok(meta.score >= 0 && meta.score <= 10.0);
    assert.ok(google.score >= 0 && google.score <= 100);
    assert.ok(tiktok.score >= 0 && tiktok.score <= 10.0);
    assert.ok(ga4.score >= 0 && ga4.score <= 10.0);
    assert.ok(snap.score >= 0 && snap.score <= 10.0);
    assert.ok(pin.score >= 0 && pin.score <= 10.0);
    assert.ok(linkedin.score >= 0 && linkedin.score <= 10.0);
  });

  test('6.5 Mathematical Cliff Guarding (100x clamp & safe division)', () => {
    // A fill rate of 1.05 (105% due to timing) must clamp to 1.0 (100%), NOT divide by 100 into 0.0105
    assert.strictEqual(normalizeCoverageRatio(1.05, 100), 1.0);
    assert.strictEqual(normalizeCoverageRatio(1.0, 100), 1.0);
    assert.strictEqual(normalizeCoverageRatio(0.5, 100), 0.5);
    // Legacy percentage 50.0 divides by 100 -> 0.5
    assert.strictEqual(normalizeCoverageRatio(50.0, 100), 0.5);
    // Safe handling of NaN, null, undefined
    assert.strictEqual(normalizeCoverageRatio(NaN, 100), 0.0);
    assert.strictEqual(normalizeCoverageRatio(null, 100), 0.0);
  });

  test('6.6 analyzeSchemaInventory verifies missing core parameters', () => {
    const summary = analyzeSchemaInventory('purchase', {
      currency: { value: 'USD', fillRate: 1.0 },
      value: { value: 99.00, fillRate: 1.0 }
      // transaction_id and items omitted
    });

    assert.strictEqual(summary.totalParameters, 2);
    assert.ok(summary.missingCoreParameters.includes('transaction_id'));
    assert.ok(summary.missingCoreParameters.includes('items'));
  });

  console.log(`\n${BOLD}${CYAN}================================================================${RESET}`);
  console.log(`${BOLD}${CYAN}  SUMMARY: ${passed} Passed, ${failed} Failed${RESET}`);
  console.log(`${BOLD}${CYAN}================================================================${RESET}\n`);

  if (failed > 0) {
    console.error(`${RED}Test suite failed with ${failed} error(s):${RESET}`);
    for (const f of failures) {
      console.error(`  - ${f}`);
    }
    process.exit(1);
  } else {
    console.log(`${GREEN}${BOLD}✓ ALL STANDALONE TESTS PASSED AT 100%!${RESET}\n`);
    process.exit(0);
  }
}

runAllTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
