/**
 * Open sGTM Container Runtime — Process Supervisor
 * Pure Node.js process supervisor managing Cloud Run container lifecycle.
 * Spawns sGTM upstream on port 8081 and reverse proxy on 8080.
 * Injects telemetry interceptor into sGTM upstream NODE_OPTIONS when enabled.
 * Scrubs NODE_OPTIONS from proxy to prevent circular telemetry loops.
 * Enforces process co-termination and graceful shutdown.
 */

'use strict';

const { spawn } = require('child_process');
const path = require('path');

const SGTM_PORT = process.env.SGTM_INTERNAL_PORT || 8081;
const PROXY_PORT = process.env.PORT || 8080;

// Upstream sGTM server script
const SGTM_BIN = process.env.SGTM_BIN || '/app/server_bin.js';
// Reverse proxy server script
const PROXY_BIN = process.env.PROXY_BIN || path.resolve(__dirname, 'src/proxy/server.js');
// Telemetry interceptor hook
const INTERCEPTOR_PATH = process.env.INTERCEPTOR_PATH || './src/telemetry/interceptor.js';

// Configure sGTM upstream environment
const sgtmEnv = {
  ...process.env,
  PORT: String(SGTM_PORT)
};

// Conditional Telemetry Hook:
// If TRUESIGHT_ENABLED is not explicitly set to 'false' or '0', inject --require into sGTM NODE_OPTIONS
if (process.env.TRUESIGHT_ENABLED !== 'false' && process.env.TRUESIGHT_ENABLED !== '0') {
  const requireFlag = `--require ${INTERCEPTOR_PATH}`;
  sgtmEnv.NODE_OPTIONS = sgtmEnv.NODE_OPTIONS
    ? `${sgtmEnv.NODE_OPTIONS} ${requireFlag}`
    : requireFlag;
}

// Configure reverse proxy environment
const proxyEnv = {
  ...process.env,
  PORT: String(PROXY_PORT),
  SGTM_INTERNAL_PORT: String(SGTM_PORT),
  SGTM_UPSTREAM_URL: process.env.SGTM_UPSTREAM_URL || `http://127.0.0.1:${SGTM_PORT}`
};

// Critical Security / Loop Prevention:
// Explicitly scrub NODE_OPTIONS from proxy environment so proxy requests are NOT intercepted
delete proxyEnv.NODE_OPTIONS;

// Node executable path (use /nodejs/bin/node if available in Google image, else fallback to process.execPath)
const nodeExec = process.env.NODE_PATH_BIN || (process.platform === 'win32' ? process.execPath : '/nodejs/bin/node');

// Spawn Child 1: sGTM Upstream Container Engine
const sgtm = spawn(nodeExec, [SGTM_BIN], {
  env: sgtmEnv,
  stdio: 'inherit'
});

// Spawn Child 2: AdBlock Shield Reverse Proxy
const proxy = spawn(nodeExec, [PROXY_BIN], {
  env: proxyEnv,
  stdio: 'inherit'
});

// Process Co-termination: If either child process terminates, kill the other and exit
sgtm.on('exit', (code, signal) => {
  if (proxy && !proxy.killed) {
    try {
      proxy.kill('SIGTERM');
    } catch {}
  }
  process.exit(code !== null ? code : 1);
});

proxy.on('exit', (code, signal) => {
  if (sgtm && !sgtm.killed) {
    try {
      sgtm.kill('SIGTERM');
    } catch {}
  }
  process.exit(code !== null ? code : 0);
});

// Graceful Signal Handling
function handleShutdown(signal) {
  if (proxy && !proxy.killed) {
    try {
      proxy.kill(signal);
    } catch {}
  }
  if (sgtm && !sgtm.killed) {
    try {
      sgtm.kill(signal);
    } catch {}
  }
}

process.on('SIGTERM', () => handleShutdown('SIGTERM'));
process.on('SIGINT', () => handleShutdown('SIGINT'));

module.exports = {
  sgtm,
  proxy,
  sgtmEnv,
  proxyEnv,
  SGTM_PORT,
  PROXY_PORT
};
