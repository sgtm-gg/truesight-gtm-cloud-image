/**
 * TrueSight sGTM Reverse Proxy & AdBlock Shield
 * Canonical pure Node.js reverse proxy with zero external dependencies.
 * Handles /healthz, /fps/loader.js, /fps/asset, /fps/gtm.js, /metrics/t/:id XOR ingress,
 * Service Worker (*\/sw.js), and legacy aliases (/icefall/*, /sherpa/t/*).
 * Performs in-memory event ingress tallying with prototype defense and cardinality bounds.
 */

'use strict';

const http = require('node:http');
const https = require('node:https');
const url = require('node:url');
const crypto = require('node:crypto');

// ==============================================================================
// CONFIGURATION
// ==============================================================================
const CONFIG = {
  get PORT() { return parseInt(process.env.PORT || '8080', 10); },
  get SGTM_INTERNAL_PORT() { return parseInt(process.env.SGTM_INTERNAL_PORT || '8081', 10); },
  get SGTM_UPSTREAM_URL() { return process.env.SGTM_UPSTREAM_URL || `http://127.0.0.1:${this.SGTM_INTERNAL_PORT}`; },
  get SECRET_KEY() {
    if (process.env.SECRET_KEY) return process.env.SECRET_KEY;
    if (this.TRUESIGHT_API_KEY) {
      return crypto.createHash('sha256').update(this.TRUESIGHT_API_KEY).digest('hex').slice(0, 16);
    }
    return '';
  },
  get TRUESIGHT_INGEST_URL() { return process.env.TRUESIGHT_INGEST_URL || 'https://app.sgtm.gg/api/truesight/ingest'; },
  get TRUESIGHT_API_KEY() { return process.env.TRUESIGHT_API_KEY || ''; },
  MAX_DISTINCT_EVENTS: 100,
  MAX_EVENT_NAME_LENGTH: 64,
  INGRESS_FLUSH_INTERVAL_MS: 5000
};

// ==============================================================================
// CIPHER UTILITIES
// ==============================================================================
function decrypt(encoded, key = CONFIG.SECRET_KEY) {
  if (!encoded || !key) return null;
  try {
    let b64 = String(encoded).replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) {
      b64 += '=';
    }
    const raw = Buffer.from(b64, 'base64').toString('binary');
    let out = '';
    for (let i = 0; i < raw.length; i++) {
      out += String.fromCharCode(raw.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return out;
  } catch {
    return null;
  }
}

function encrypt(str, key = CONFIG.SECRET_KEY) {
  if (!str || !key) return '';
  let out = '';
  for (let i = 0; i < str.length; i++) {
    out += String.fromCharCode(str.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return Buffer.from(out, 'binary')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function extractGtmId(containerConfig) {
  if (!containerConfig || typeof containerConfig !== 'string') {
    return 'GTM-XXXXXXX';
  }

  let raw = containerConfig.trim();
  if (!raw) return 'GTM-XXXXXXX';

  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
    raw = raw.slice(1, -1).trim();
  }

  if (raw.startsWith('CONTAINER_CONFIG=')) {
    raw = raw.slice('CONTAINER_CONFIG='.length).trim();
  }

  let unencoded = raw;
  try {
    unencoded = decodeURIComponent(raw);
  } catch {
    unencoded = raw;
  }

  const exactGtmMatch = unencoded.match(/^GTM-[A-Z0-9]+$/i);
  if (exactGtmMatch) {
    return exactGtmMatch[0].toUpperCase();
  }

  const plainIdMatch = unencoded.match(/(?:^|[&?])id=([^&;]+)/i);
  if (plainIdMatch && plainIdMatch[1]) {
    const candidate = plainIdMatch[1].trim();
    if (/^GTM-[A-Z0-9]+$/i.test(candidate)) {
      return candidate.toUpperCase();
    }
  }

  try {
    let b64 = unencoded.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) {
      b64 += '=';
    }

    let decoded = '';
    if (typeof Buffer !== 'undefined') {
      decoded = Buffer.from(b64, 'base64').toString('utf-8');
    }

    if (decoded) {
      try {
        decoded = decodeURIComponent(decoded);
      } catch {}

      const match = decoded.match(/(?:^|[&?])id=([^&;]+)/i);
      if (match && match[1]) {
        const candidate = match[1].trim();
        if (/^GTM-[A-Z0-9]+$/i.test(candidate)) {
          return candidate.toUpperCase();
        }
        return candidate;
      }

      const directMatch = decoded.match(/\b(GTM-[A-Z0-9]+)\b/i);
      if (directMatch && directMatch[1]) {
        return directMatch[1].toUpperCase();
      }
    }
  } catch {}

  return 'GTM-XXXXXXX';
}


// ==============================================================================
// EVENT EXTRACTION, PROTOTYPE DEFENSE & SANITIZATION
// ==============================================================================
const PROTOTYPE_KEYWORDS = new Set([
  '__proto__',
  'constructor',
  'prototype',
  'tostring',
  'valueof',
  'hasownproperty',
  'isprototypeof',
  'propertyisenumerable'
]);

const VALID_EVENT_REGEX = /^[a-zA-Z0-9_\-\.]{1,64}$/;

function sanitizeEventName(name) {
  if (!name || typeof name !== 'string') return 'page_view';
  let trimmed = name.trim().toLowerCase();
  if (!trimmed) return 'page_view';

  if (trimmed.length > CONFIG.MAX_EVENT_NAME_LENGTH) {
    trimmed = trimmed.slice(0, CONFIG.MAX_EVENT_NAME_LENGTH);
  }

  if (PROTOTYPE_KEYWORDS.has(trimmed)) {
    return 'page_view';
  }

  if (!VALID_EVENT_REGEX.test(trimmed)) {
    return 'page_view';
  }

  return trimmed;
}

function extractEventNames(queryOrUrl, body) {
  const events = [];

  // 1. Inspect Query String / URL
  if (queryOrUrl && typeof queryOrUrl === 'string') {
    try {
      const qIndex = queryOrUrl.indexOf('?');
      const qs = qIndex !== -1 ? queryOrUrl.slice(qIndex + 1) : queryOrUrl;
      const params = new URLSearchParams(qs);
      const en = params.get('en') || params.get('event') || params.get('eventName');
      if (en) {
        events.push(sanitizeEventName(en));
      }
    } catch {}
  }

  // 2. Inspect Body
  if (body) {
    let bodyStr = '';
    if (typeof body === 'string') {
      bodyStr = body.trim();
    } else if (Buffer.isBuffer(body)) {
      bodyStr = body.toString('utf8').trim();
    }

    if (bodyStr) {
      // 2a. JSON parsing
      if ((bodyStr.startsWith('{') && bodyStr.endsWith('}')) || (bodyStr.startsWith('[') && bodyStr.endsWith(']'))) {
        try {
          const parsed = JSON.parse(bodyStr);
          if (Array.isArray(parsed)) {
            for (const item of parsed) {
              const name = item.eventName || item.name || item.event || item.en;
              if (name) events.push(sanitizeEventName(String(name)));
            }
          } else if (parsed && typeof parsed === 'object') {
            // Check GA4 Measurement Protocol v2 batch
            if (Array.isArray(parsed.events)) {
              for (const item of parsed.events) {
                const name = item.eventName || item.name || item.event || item.en;
                if (name) events.push(sanitizeEventName(String(name)));
              }
            } else {
              const name = parsed.eventName || parsed.name || parsed.event || parsed.en;
              if (name) events.push(sanitizeEventName(String(name)));
            }
          }
        } catch {}
      }

      // 2b. Form URL-encoded or Newline-delimited (only if no JSON events found)
      if (events.length === 0) {
        const lines = bodyStr.split(/[\r\n]+/);
        for (const line of lines) {
          const trimmedLine = line.trim();
          if (!trimmedLine) continue;

          if (trimmedLine.includes('&') || trimmedLine.includes('=')) {
            try {
              const params = new URLSearchParams(trimmedLine);
              const en = params.get('en') || params.get('event') || params.get('eventName') || params.get('name');
              if (en) {
                events.push(sanitizeEventName(en));
              }
            } catch {}
          } else if (VALID_EVENT_REGEX.test(trimmedLine) && !PROTOTYPE_KEYWORDS.has(trimmedLine.toLowerCase())) {
            // Bare token
            events.push(sanitizeEventName(trimmedLine));
          }
        }
      }
    }
  }

  if (events.length === 0) {
    return ['page_view'];
  }

  return events;
}

function extractEventName(queryOrUrl, body) {
  const names = extractEventNames(queryOrUrl, body);
  return names[0] || 'page_view';
}

// ==============================================================================
// INGRESS ROLLING BUFFER & CARDINALITY DEFENSE
// ==============================================================================
let ingressBuffer = Object.create(null);
let ingressTimer = null;

function recordIngress(eventName, count = 1) {
  const sanitized = sanitizeEventName(eventName);
  const keys = Object.keys(ingressBuffer);

  if (sanitized in ingressBuffer) {
    ingressBuffer[sanitized] += count;
    return;
  }

  if (keys.length < CONFIG.MAX_DISTINCT_EVENTS) {
    ingressBuffer[sanitized] = count;
  } else {
    ingressBuffer['other_events'] = (ingressBuffer['other_events'] || 0) + count;
  }
}

function getPendingIngress() {
  return { ...ingressBuffer };
}

function drainPendingIngress() {
  const keys = Object.keys(ingressBuffer);
  if (keys.length === 0) {
    return null;
  }
  const snapshot = { ...ingressBuffer };
  ingressBuffer = Object.create(null);
  return snapshot;
}

function resetIngressBuffer() {
  ingressBuffer = Object.create(null);
}

async function flushPendingIngressStandalone() {
  const drained = drainPendingIngress();
  if (!drained || !CONFIG.TRUESIGHT_INGEST_URL) {
    return;
  }

  const payload = {
    w: CONFIG.TRUESIGHT_API_KEY,
    ingress: drained
  };

  try {
    const postBody = JSON.stringify(payload);
    const targetUrl = new URL(CONFIG.TRUESIGHT_INGEST_URL);
    const isHttps = targetUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    await new Promise((resolve, reject) => {
      const req = client.request({
        hostname: targetUrl.hostname,
        port: targetUrl.port || (isHttps ? 443 : 80),
        path: targetUrl.pathname + targetUrl.search,
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(postBody),
          'x-truesight-internal': '1'
        }
      }, (res) => {
        res.resume();
        res.on('end', resolve);
      });
      req.on('error', reject);
      req.write(postBody);
      req.end();
    });
  } catch (err) {
    // Non-blocking telemetry delivery
  }
}

function startIngressTimer(intervalMs = CONFIG.INGRESS_FLUSH_INTERVAL_MS) {
  if (ingressTimer) clearInterval(ingressTimer);
  ingressTimer = setInterval(() => {
    flushPendingIngressStandalone().catch(() => {});
  }, intervalMs);
  if (ingressTimer.unref) ingressTimer.unref();
}

function stopIngressTimer() {
  if (ingressTimer) {
    clearInterval(ingressTimer);
    ingressTimer = null;
  }
}

// ==============================================================================
// TELEMETRY HEARTBEAT (BOOT & PERIODIC)
// ==============================================================================
let heartbeatTimer = null;
let bootHeartbeatTimer = null;

function sendHeartbeat() {
  if (!CONFIG.TRUESIGHT_API_KEY || !CONFIG.TRUESIGHT_INGEST_URL) {
    return;
  }

  const identity = {
    service: process.env.K_SERVICE || '',
    revision: process.env.K_REVISION || '',
    region: process.env.CLOUD_RUN_REGION || process.env.K_LOCATION || process.env.REGION || '',
    gtmId: extractGtmId(process.env.CONTAINER_CONFIG)
  };

  const payload = {
    w: CONFIG.TRUESIGHT_API_KEY,
    type: 'HEARTBEAT',
    identity
  };

  try {
    const postBody = JSON.stringify(payload);
    const targetUrl = new URL(CONFIG.TRUESIGHT_INGEST_URL);
    const isHttps = targetUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    const req = client.request({
      hostname: targetUrl.hostname,
      port: targetUrl.port || (isHttps ? 443 : 80),
      path: targetUrl.pathname + targetUrl.search,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(postBody),
        'x-truesight-heartbeat': '1'
      }
    }, (res) => {
      res.resume();
    });

    req.on('error', () => {});
    req.write(postBody);
    req.end();
  } catch {}
}

function startHeartbeatTimer() {
  if (CONFIG.TRUESIGHT_API_KEY) {
    // Dispatch boot heartbeat after 5s
    bootHeartbeatTimer = setTimeout(() => {
      sendHeartbeat();
    }, 5000);
    if (bootHeartbeatTimer && bootHeartbeatTimer.unref) {
      bootHeartbeatTimer.unref();
    }

    // Dispatch periodic heartbeat every 60s
    heartbeatTimer = setInterval(() => {
      sendHeartbeat();
    }, 60000);
    if (heartbeatTimer && heartbeatTimer.unref) {
      heartbeatTimer.unref();
    }
  }
}

function stopHeartbeatTimer() {
  if (bootHeartbeatTimer) {
    clearTimeout(bootHeartbeatTimer);
    bootHeartbeatTimer = null;
  }
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
}


// ==============================================================================
// PURE NODE.JS REVERSE PROXY ROUTING
// ==============================================================================

function fetchAndPipe(targetUrl, clientRes, onError) {
  try {
    const parsed = new URL(targetUrl);
    const client = parsed.protocol === 'https:' ? https : http;

    const proxyReq = client.get(targetUrl, (upstreamRes) => {
      if (upstreamRes.statusCode >= 300 && upstreamRes.statusCode < 400 && onError) {
        upstreamRes.resume();
        return onError();
      }

      const headers = { ...upstreamRes.headers };
      delete headers['x-xss-protection'];
      delete headers['x-content-type-options'];

      clientRes.writeHead(upstreamRes.statusCode || 200, headers);
      upstreamRes.pipe(clientRes);
    });

    proxyReq.on('error', (err) => {
      if (onError) onError(err);
      else {
        if (!clientRes.headersSent) {
          clientRes.writeHead(502, { 'content-type': 'text/plain' });
          clientRes.end('Bad Gateway');
        }
      }
    });
  } catch (err) {
    if (!clientRes.headersSent) {
      clientRes.writeHead(500, { 'content-type': 'text/plain' });
      clientRes.end('Internal Server Error');
    }
  }
}

function forwardToUpstream(req, res, targetPath, bodyBuffer = null) {
  try {
    const upstreamUrl = new URL(targetPath, CONFIG.SGTM_UPSTREAM_URL);
    const isHttps = upstreamUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    const headers = { ...req.headers };
    delete headers.host;

    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    headers['x-forwarded-for'] = clientIp;

    if (bodyBuffer) {
      headers['content-length'] = Buffer.byteLength(bodyBuffer);
    }

    const options = {
      hostname: upstreamUrl.hostname,
      port: upstreamUrl.port || (isHttps ? 443 : 80),
      path: upstreamUrl.pathname + upstreamUrl.search,
      method: req.method,
      headers
    };

    const upstreamReq = client.request(options, (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode || 200, upstreamRes.headers);
      upstreamRes.pipe(res);
    });

    upstreamReq.on('error', () => {
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'text/plain' });
        res.end('Upstream Unavailable');
      }
    });

    if (bodyBuffer) {
      upstreamReq.write(bodyBuffer);
      upstreamReq.end();
    } else {
      req.pipe(upstreamReq);
    }
  } catch (err) {
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'text/plain' });
      res.end('Gateway Error');
    }
  }
}

function handleRequest(req, res) {
  const host = req.headers.host || `127.0.0.1:${CONFIG.PORT}`;
  const parsedUrl = new URL(req.url, `http://${host}`);
  const pathname = parsedUrl.pathname || '/';

  // 1. Healthcheck
  if (pathname === '/healthz') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', uptime: process.uptime() }));
    return;
  }

  // 2. Client Bootstrapper: /fps/loader.js or /icefall/loader.js
  if (pathname === '/fps/loader.js' || pathname === '/icefall/loader.js') {
    const encData = parsedUrl.searchParams.get('data') || '';
    const id = decrypt(encData);
    if (!id || (!id.startsWith('GTM-') && !id.startsWith('G-'))) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('Bad Request');
      return;
    }

    const prefix = pathname.startsWith('/fps') ? '/fps' : '/icefall';
    const scriptPath = id.startsWith('GTM-') ? 'gtm.js' : 'gtag/js';
    res.writeHead(200, {
      'content-type': 'application/javascript',
      'cache-control': 'public, max-age=3600'
    });
    res.end(`(function(){var s=document.createElement('script');s.async=true;s.src='${prefix}/${scriptPath}?id=${id}';document.head.appendChild(s)})();`);
    return;
  }

  // 3. Asset Proxy: /fps/asset or /icefall/asset
  if (pathname === '/fps/asset' || pathname === '/icefall/asset') {
    const encPath = parsedUrl.searchParams.get('b') || '';
    const decoded = decrypt(encPath);
    if (!decoded || !decoded.startsWith('/')) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('Bad Request');
      return;
    }
    fetchAndPipe(`https://www.googletagmanager.com${decoded}`, res);
    return;
  }

  // 4. Standard / Debug GTM Script: /fps/gtm.js or /icefall/gtm.js
  if (pathname === '/fps/gtm.js' || pathname === '/icefall/gtm.js') {
    const id = parsedUrl.searchParams.get('id');
    if (!id || (!id.startsWith('GTM-') && !id.startsWith('G-'))) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('Bad Request');
      return;
    }
    const qs = parsedUrl.search || '';
    fetchAndPipe(`https://www.googletagmanager.com/gtm.js${qs}`, res);
    return;
  }

  // 5. Debug Proxy: /fps/debug/* or /icefall/debug/*
  if (pathname.startsWith('/fps/debug/') || pathname.startsWith('/icefall/debug/')) {
    const cleanPath = pathname.replace(/^\/(fps|icefall)\//, '/');
    const qs = parsedUrl.search || '';
    fetchAndPipe(`https://www.googletagmanager.com${cleanPath}${qs}`, res);
    return;
  }

  // 6. Noscript Fallback: /fps/ns.html or /icefall/ns.html
  if (pathname === '/fps/ns.html' || pathname === '/icefall/ns.html') {
    const id = parsedUrl.searchParams.get('id');
    if (!id || (!id.startsWith('GTM-') && !id.startsWith('G-'))) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('Bad Request');
      return;
    }
    const qs = parsedUrl.search || '';
    fetchAndPipe(`https://www.googletagmanager.com/ns.html${qs}`, res);
    return;
  }

  // 7. Custom Service Worker: */sw.js
  if (pathname.endsWith('/sw.js')) {
    res.writeHead(200, {
      'content-type': 'application/javascript',
      'cache-control': 'public, max-age=86400',
      'service-worker-allowed': '/'
    });
    res.end(`'use strict';
var K='${CONFIG.SECRET_KEY}';
var T='/metrics/t/'+Math.random().toString(36).slice(2,8);
function e(s){var o='';for(var i=0;i<s.length;i++)o+=String.fromCharCode(s.charCodeAt(i)^K.charCodeAt(i%K.length));return btoa(o).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')}
self.addEventListener('install',function(){self.skipWaiting()});
self.addEventListener('activate',function(ev){ev.waitUntil(self.clients.claim())});
self.addEventListener('fetch',function(ev){
var u=ev.request.url;
var idx=u.indexOf('/g/collect');
if(idx===-1)return;
var path=u.substring(idx);
ev.respondWith(
ev.request.text().then(function(body){
var cipher=e(path+'|||'+(body||''));
return fetch(T+'?'+cipher,{method:'GET',keepalive:true}).catch(function(){return new Response(null,{status:204})});
}).catch(function(){return new Response(null,{status:204})})
);
});`);
    return;
  }

  // 8. Encrypted Ingress Forwarding: /metrics/t/:id, /fps/t/:id, /icefall/t/:id, /sherpa/t/:id
  if (
    pathname.startsWith('/metrics/t/') ||
    pathname.startsWith('/fps/t/') ||
    pathname.startsWith('/icefall/t/') ||
    pathname.startsWith('/sherpa/t/')
  ) {
    const rawCipher = (parsedUrl.search ? parsedUrl.search.slice(1) : '') || Object.keys(parsedUrl.query)[0] || '';
    const decoded = decrypt(rawCipher);
    if (!decoded) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('Bad Request');
      return;
    }

    // Format: path_and_query|||body
    const sep = decoded.indexOf('|||');
    const pathAndQuery = sep !== -1 ? decoded.substring(0, sep) : decoded;
    const bodyText = sep !== -1 ? decoded.substring(sep + 3) : '';

    // Tally events
    const eventNames = extractEventNames(pathAndQuery, bodyText);
    for (const name of eventNames) {
      recordIngress(name);
    }

    // Forward to sGTM upstream
    try {
      const upstreamUrl = new URL(pathAndQuery, CONFIG.SGTM_UPSTREAM_URL);
      const isHttps = upstreamUrl.protocol === 'https:';
      const client = isHttps ? https : http;

      const proxyHeaders = { ...req.headers };
      delete proxyHeaders.host;
      proxyHeaders['x-forwarded-for'] = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

      if (bodyText) {
        proxyHeaders['content-type'] = 'text/plain;charset=UTF-8';
        proxyHeaders['content-length'] = Buffer.byteLength(bodyText);
      }

      const options = {
        hostname: upstreamUrl.hostname,
        port: upstreamUrl.port || (isHttps ? 443 : 80),
        path: upstreamUrl.pathname + upstreamUrl.search,
        method: bodyText ? 'POST' : 'GET',
        headers: proxyHeaders
      };

      const fwd = client.request(options, (fwdRes) => {
        res.writeHead(fwdRes.statusCode || 204, fwdRes.headers);
        fwdRes.pipe(res);
      });

      fwd.on('error', () => {
        if (!res.headersSent) {
          res.writeHead(502, { 'content-type': 'text/plain' });
          res.end('Upstream Gateway Error');
        }
      });

      if (bodyText) fwd.write(bodyText);
      fwd.end();
    } catch {
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'text/plain' });
        res.end('Invalid Encrypted Path');
      }
    }
    return;
  }

  // 9. Telemetry Ingress Fusion: /__ts_local_ingest
  if (pathname === '/__ts_local_ingest' && req.method === 'POST') {
    let bodyData = '';
    req.on('data', (chunk) => { bodyData += chunk; });
    req.on('end', () => {
      let payload = {};
      if (bodyData && bodyData.trim()) {
        try {
          payload = JSON.parse(bodyData);
        } catch {
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'Malformed JSON' }));
          return;
        }
      }

      // Immediately acknowledge receipt
      res.writeHead(204);
      res.end();

      // Drain in-memory ingress tallies and merge into egress payload
      try {
        const drainedIngress = drainPendingIngress();
        if (drainedIngress) {
          payload.ingress = { ...drainedIngress, ...(payload.ingress || {}) };
        }

        // Forward fused payload to TrueSight Ingest backend
        if (CONFIG.TRUESIGHT_INGEST_URL) {
          const postBody = JSON.stringify(payload);
          const targetUrl = new URL(CONFIG.TRUESIGHT_INGEST_URL);
          const isHttps = targetUrl.protocol === 'https:';
          const client = isHttps ? https : http;

          const fwdReq = client.request({
            hostname: targetUrl.hostname,
            port: targetUrl.port || (isHttps ? 443 : 80),
            path: targetUrl.pathname + targetUrl.search,
            method: 'POST',
            headers: {
              'content-type': 'application/json',
              'content-length': Buffer.byteLength(postBody),
              'x-truesight-internal': '1'
            }
          }, (fwdRes) => {
            fwdRes.resume();
          });
          fwdReq.on('error', () => {});
          fwdReq.write(postBody);
          fwdReq.end();
        }
      } catch {}
    });
    return;
  }

  // 10. Transparent Upstream Proxy (including /g/collect event sniffing)
  if (pathname.includes('/g/collect')) {
    let bodyBuffer = Buffer.alloc(0);
    req.on('data', (chunk) => {
      bodyBuffer = Buffer.concat([bodyBuffer, chunk]);
    });
    req.on('end', () => {
      const names = extractEventNames(req.url, bodyBuffer);
      for (const name of names) {
        recordIngress(name);
      }
      forwardToUpstream(req, res, req.url, bodyBuffer.length > 0 ? bodyBuffer : null);
    });
    return;
  }

  // Fallthrough: Transparent upstream proxy
  forwardToUpstream(req, res, req.url);
}

// ==============================================================================
// SERVER FACTORY & INTERFACE
// ==============================================================================
function createProxyServer() {
  return http.createServer(handleRequest);
}

const server = createProxyServer();

function app(req, res) {
  return handleRequest(req, res);
}

app.listen = function(...args) {
  const srv = http.createServer(handleRequest);
  return srv.listen(...args);
};

// Automatically start if executed as primary process
if (require.main === module) {
  startIngressTimer();
  startHeartbeatTimer();
  server.listen(CONFIG.PORT, '0.0.0.0', () => {
    console.log(`[TrueSight Proxy] Listening on port ${CONFIG.PORT} -> Upstream: ${CONFIG.SGTM_UPSTREAM_URL}`);
  });
}

module.exports = {
  app,
  server,
  createProxyServer,
  handleRequest,
  extractEventNames,
  extractEventName,
  sanitizeEventName,
  recordIngress,
  getPendingIngress,
  drainPendingIngress,
  resetIngressBuffer,
  flushPendingIngressStandalone,
  startIngressTimer,
  stopIngressTimer,
  sendHeartbeat,
  startHeartbeatTimer,
  stopHeartbeatTimer,
  extractGtmId,
  decrypt,
  encrypt,
  CONFIG
};

