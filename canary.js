#!/usr/bin/env node
/*
 * BENIGN BAF DETECTION CANARY -- stands in for 3FWCvzduYZg.js
 *
 * Contains NO payload. It does exactly two things:
 *   1. Prints markers proving install-time code execution occurred.
 *   2. Makes unauthenticated HEAD/GET requests to the same destination set
 *      the real Trinitite loader touches, so BAF egress rules can be
 *      validated end to end.
 *
 * No credentials are read, nothing is written outside cwd, nothing is
 * downloaded or executed.
 */

const https = require('https');
const http = require('http');

const marker = process.env.BAF_CANARY_ID || 'trinitite-repro';
const trigger = process.argv[2] || 'unknown';

console.log('==================================================');
console.log(`[BAF-CANARY] install-time execution: ${marker}`);
console.log(`[BAF-CANARY] trigger path          : ${trigger}`);
console.log(`[BAF-CANARY] cwd                   : ${process.cwd()}`);
console.log(`[BAF-CANARY] ci                    : ${process.env.CI || 'false'}`);
console.log(`[BAF-CANARY] repo                  : ${process.env.GITHUB_REPOSITORY || 'n/a'}`);
console.log(`[BAF-CANARY] ref                   : ${process.env.GITHUB_REF || 'n/a'}`);
console.log(`[BAF-CANARY] oidc req url present  : ${!!process.env.ACTIONS_ID_TOKEN_REQUEST_URL}`);
console.log('==================================================');

// Destination set mirrored from the published IOC lists.
// Each maps to a BAF rule we want to see fire.
const targets = [
  // Bun dropper fetch -- release-assets / raw github during dependency install
  ['https://github.com/oven-sh/bun/releases/download/bun-v1.4.0/', 'bun-dropper'],
  ['https://raw.githubusercontent.com/oven-sh/bun/refs/heads/main/src/runtime/cli/install.sh', 'bun-installer-script'],
  // GitHub API from inside a build -- token validation / repo creation path
  ['https://api.github.com/', 'github-api-from-build'],
  // Registry identity probing
  ['https://registry.npmjs.org/-/whoami', 'npm-token-probe'],
  // Sigstore -- provenance minting from an unexpected step
  ['https://fulcio.sigstore.dev/', 'sigstore-fulcio'],
  // Cloud metadata -- classic credential harvest
  ['http://169.254.169.254/latest/api/token', 'imds-v2'],
  ['http://metadata.google.internal/', 'gcp-metadata'],
];

function probe(url, label) {
  return new Promise((resolve) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.request(
      url,
      { method: 'HEAD', timeout: 4000, headers: { 'user-agent': `baf-canary/${marker}` } },
      (res) => {
        console.log(`[BAF-CANARY] egress ${label.padEnd(24)} -> ${res.statusCode} ${url}`);
        res.resume();
        resolve();
      }
    );
    req.on('timeout', () => { console.log(`[BAF-CANARY] egress ${label.padEnd(24)} -> TIMEOUT/BLOCKED ${url}`); req.destroy(); resolve(); });
    req.on('error', (e) => { console.log(`[BAF-CANARY] egress ${label.padEnd(24)} -> BLOCKED (${e.code}) ${url}`); resolve(); });
    req.end();
  });
}

(async () => {
  for (const [url, label] of targets) await probe(url, label);
  console.log('[BAF-CANARY] done. Expect all of the above in the BAF egress log.');
})();
