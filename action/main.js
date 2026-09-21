const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');

function saveState(key, value) {
  const statePath = process.env.GITHUB_STATE;
  if (statePath) {
    fs.appendFileSync(statePath, `${key}=${value}\n`);
  } else {
    process.env[`STATE_${key}`] = value;
  }
}

function main() {
  console.log('BuildLens Agent initializing...');
  const actionPath = path.resolve(__dirname, '..');
  saveState('ACTION_PATH', actionPath);

  if (process.platform !== 'linux') {
    console.log('::warning::BuildLens currently requires Linux eBPF. Operating in fail-open mode.');
    saveState('FAIL_OPEN', 'true');
    saveState('FAIL_REASON', `unsupported_platform_${process.platform}`);
    return;
  }

  // Check kernel BTF
  if (!fs.existsSync('/sys/kernel/btf/vmlinux')) {
    console.log('::warning::Kernel BTF (/sys/kernel/btf/vmlinux) not found. Operating in fail-open mode.');
    saveState('FAIL_OPEN', 'true');
    saveState('FAIL_REASON', 'missing_kernel_btf');
    return;
  }

  const runId = process.env.GITHUB_RUN_ID || Date.now();
  const runDir = path.join('/tmp', `buildlens-${runId}`);
  fs.mkdirSync(runDir, { recursive: true });

  const eventsPath = path.join(runDir, 'events.jsonl');
  const statsPath = path.join(runDir, 'agent-stats.json');
  const readyPath = `${eventsPath}.ready`;

  saveState('RUN_DIR', runDir);
  saveState('EVENTS_PATH', eventsPath);
  saveState('STATS_PATH', statsPath);

  // Locate binary: 1. pinned prebuilt binary, 2. workspace bin, 3. compile fallback
  const candidates = [
    path.join(actionPath, 'action', 'bin', 'linux-amd64', 'bl-agent'),
    path.join(actionPath, 'bin', 'bl-agent'),
    path.join(runDir, 'bl-agent'),
  ];

  let agentBin = candidates.find(c => fs.existsSync(c));

  if (!agentBin) {
    agentBin = path.join(runDir, 'bl-agent');
    console.log('::warning::Prebuilt binary not found at action/bin/linux-amd64/bl-agent; falling back to development `go build` compilation...');
    try {
      execSync(`go build -o "${agentBin}" ./cmd/bl-agent`, {
        cwd: actionPath,
        stdio: 'inherit',
      });
    } catch (err) {
      console.log(`::warning::Failed to compile bl-agent: ${err.message}. Operating in fail-open mode.`);
      saveState('FAIL_OPEN', 'true');
      saveState('FAIL_REASON', 'agent_build_failed');
      return;
    }
  }

  saveState('AGENT_BIN', agentBin);

  const debug = (process.env.INPUT_DEBUG === 'true');
  const recordArgs = ['record', '-out', eventsPath, '-stats-out', statsPath];
  if (debug) {
    recordArgs.push('-debug');
  }

  console.log(`Starting BuildLens agent daemon with sudo -n: ${agentBin}`);
  // Spawn in a new process group (detached: true sets new PGID equal to child.pid)
  const child = spawn('sudo', ['-n', agentBin, ...recordArgs], {
    detached: true,
    stdio: 'ignore',
  });

  child.unref();
  saveState('AGENT_PGID', child.pid.toString());

  // Wait for probe readiness marker
  const start = Date.now();
  let isReady = false;
  while (Date.now() - start < 10000) {
    if (fs.existsSync(readyPath)) {
      isReady = true;
      break;
    }
    execSync('sleep 0.1');
  }

  if (isReady) {
    console.log('BuildLens agent attached and active. Monitoring CI build.');
  } else {
    console.log('::warning::BuildLens agent did not signal readiness in 10s. Continuing in fail-open mode.');
    saveState('FAIL_OPEN', 'true');
    saveState('FAIL_REASON', 'probe_readiness_timeout');
  }
}

try {
  main();
} catch (e) {
  console.log(`::warning::BuildLens initialization error: ${e.message}. Failing open.`);
  saveState('FAIL_OPEN', 'true');
  saveState('FAIL_REASON', e.message);
}
