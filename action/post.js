const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

function getState(key) {
  return process.env[`STATE_${key}`] || '';
}

function setOutput(key, value) {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (outputPath) {
    fs.appendFileSync(outputPath, `${key}=${value}\n`);
  }
}

function appendStepSummary(markdown) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    fs.appendFileSync(summaryPath, markdown);
  }
}

function post() {
  console.log('BuildLens Agent post-processing...');

  const actionPath = getState('ACTION_PATH') || path.resolve(__dirname, '..');
  const runDir = getState('RUN_DIR') || '/tmp';
  const eventsPath = getState('EVENTS_PATH');
  const statsPath = getState('STATS_PATH');
  const agentPid = getState('AGENT_PID') || getState('AGENT_PGID');
  const agentBin = getState('AGENT_BIN');
  const failOpen = getState('FAIL_OPEN');
  const failReason = getState('FAIL_REASON');

  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const manifestOut = path.join(workspace, process.env.INPUT_MANIFEST || 'buildlens-manifest.json');
  const sarifOut = path.join(workspace, process.env.INPUT_SARIF || 'buildlens.sarif');
  const lockfileInput = process.env.INPUT_LOCKFILE || 'package-lock.json';
  const lockfilePath = path.isAbsolute(lockfileInput)
    ? lockfileInput
    : path.join(workspace, lockfileInput);

  // Ask the recorded agent process to shut down cleanly. Sending SIGINT to the
  // entire process group first is unsafe on hosted runners: depending on how
  // sudo/detached process groups are created, the group can include the step
  // shell and terminate this post action with exit code 130.
  if (agentPid) {
    console.log(`Stopping BuildLens agent (PID ${agentPid})...`);
    try {
      execSync(`sudo -n kill -SIGINT -- ${agentPid}`, { stdio: 'ignore' });
    } catch (e) {
      // The process may already have exited; continue to collect its output.
      try {
        execSync(`kill -SIGINT -- ${agentPid}`, { stdio: 'ignore' });
      } catch (_) {}
    }

    // Wait for clean shutdown marker (.done)
    if (eventsPath) {
      const donePath = `${eventsPath}.done`;
      const waitStart = Date.now();
      while (Date.now() - waitStart < 5000) {
        if (fs.existsSync(donePath)) {
          console.log('BuildLens agent confirmed clean shutdown.');
          break;
        }
        execSync('sleep 0.1');
      }

      // Only after the graceful window has elapsed, terminate a stale agent.
      // Use the PID again rather than broadcasting to a process group: the
      // agent has no worker tree, and a group broadcast can include the step
      // shell on runners with unusual sudo/session behavior.
      if (!fs.existsSync(donePath)) {
        console.log(`Agent did not write ${donePath}; terminating stale agent ${agentPid}.`);
        try {
          execSync(`sudo -n kill -TERM -- ${agentPid}`, { stdio: 'ignore' });
        } catch (_) {}
      }
    }
  }

  // If failed open during initialization
  if (failOpen === 'true') {
    console.log(`BuildLens operated in fail-open mode: ${failReason}`);
    const degradedManifest = {
      schema_version: '1',
      ruleset_version: '1.3.0',
      status: 'degraded',
      agent_health: {
        degraded: true,
        degraded_reason: failReason || 'unsupported_environment',
      },
      findings: [],
    };
    fs.writeFileSync(manifestOut, JSON.stringify(degradedManifest, null, 2) + '\n');
    setOutput('manifest', manifestOut);
    setOutput('status', 'degraded');
    setOutput('findings_count', '0');

    appendStepSummary(
      `### ⚠️ BuildLens Runtime: DEGRADED\n\n` +
      `**Reason:** \`${failReason || 'unsupported_environment'}\`\n\n` +
      `> BuildLens operated in fail-open mode. Your build completed normally, but runtime event observation was bypassed.\n`
    );
    return;
  }

  // Missing stats must cause degradation; an unmonitored or dropped stream must not report clean
  if (!statsPath || !fs.existsSync(statsPath)) {
    console.log('::warning::BuildLens agent stats file missing; marking run degraded');
    const degradedManifest = {
      schema_version: '1',
      ruleset_version: '1.3.0',
      status: 'degraded',
      agent_health: {
        degraded: true,
        degraded_reason: 'agent_stats_missing: stats file not written by agent',
      },
      findings: [],
    };
    fs.writeFileSync(manifestOut, JSON.stringify(degradedManifest, null, 2) + '\n');
    setOutput('manifest', manifestOut);
    setOutput('status', 'degraded');
    setOutput('findings_count', '0');

    appendStepSummary(
      `### ⚠️ BuildLens Runtime: DEGRADED\n\n` +
      `**Reason:** \`agent_stats_missing: stats file not written by agent\`\n\n` +
      `> BuildLens operated in fail-open mode. Runtime event observation was incomplete.\n`
    );
    return;
  }

  // Score recorded events using bl-agent score
  const scoreBin = agentBin || path.join(actionPath, 'bin', 'bl-agent');
  console.log(`Scoring runtime events from ${eventsPath}...`);

  const mode = (process.env.INPUT_MODE || 'observe').toLowerCase();
  if (mode !== 'observe' && mode !== 'audit') {
    console.log(`::warning::Unknown BuildLens mode '${process.env.INPUT_MODE}', treating as observe.`);
  }

  let manifest = null;
  try {
    const allowHosts = (process.env['INPUT_ALLOW-HOSTS'] || '').replace(/"/g, '');
    const scoreCmd = `"${scoreBin}" score -in "${eventsPath}" -stats "${statsPath}" -out "${manifestOut}" -sarif "${sarifOut}" -lockfile "${lockfilePath}" -allow-hosts "${allowHosts}"`;
    execSync(scoreCmd, { stdio: 'inherit' });

    if (fs.existsSync(manifestOut)) {
      manifest = JSON.parse(fs.readFileSync(manifestOut, 'utf8'));
      setOutput('manifest', manifestOut);
      setOutput('sarif', sarifOut);
      setOutput('status', manifest.status || 'clean');
      setOutput('findings_count', (manifest.findings ? manifest.findings.length : 0).toString());
    }
  } catch (err) {
    console.log(`::warning::Scoring encountered an error: ${err.message}`);
  }

  // Audit mode appends this run's egress observations (host, package, counts
  // only — never argv or paths) to a workspace ledger. Commit it; after 5+
  // clean runs generate the policy with:
  //   bl-agent policy -in .buildlens/observed.jsonl -out .buildlens/policy.yml
  // The ledger is append-only: re-merging ledgers double-counts runs.
  if (mode === 'audit' && manifest && manifest.status === 'clean' && eventsPath && fs.existsSync(eventsPath)) {
    try {
      const ledgerDir = path.join(workspace, '.buildlens');
      fs.mkdirSync(ledgerDir, { recursive: true });
      const tmpObs = path.join(runDir, 'observed.jsonl');
      execSync(`"${scoreBin}" policy -in "${eventsPath}" -format jsonl -out "${tmpObs}" -lockfile "${lockfilePath}"`, { stdio: 'ignore' });
      const lines = fs.existsSync(tmpObs) ? fs.readFileSync(tmpObs, 'utf8') : '';
      if (lines.trim()) {
        fs.appendFileSync(path.join(ledgerDir, 'observed.jsonl'), lines);
        console.log('BuildLens audit: appended egress observations to .buildlens/observed.jsonl');
      } else {
        console.log('BuildLens audit: run contacted nothing new; ledger unchanged.');
      }
    } catch (err) {
      console.log(`::warning::BuildLens audit ledger failed (build unaffected): ${err.message}`);
    }
  }

  if (process.env['INPUT_UPLOAD-SARIF'] === 'true' && fs.existsSync(sarifOut)) {
    uploadSarif(sarifOut).catch((e) => console.log(`::warning::BuildLens SARIF upload failed: ${e.message}`));
  }

  console.log('BuildLens post-processing completed.');
}

// The SARIF only exists once this post step has scored the run, after every
// other step in the job, so a separate upload step can never see it. Upload it
// here instead. Opt-in: nothing leaves the runner unless the user asks.
async function uploadSarif(sarifPath) {
  const token = process.env.INPUT_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  if (!token || !repo) {
    console.log('::warning::BuildLens SARIF upload skipped: no token or repository in the environment');
    return;
  }
  const api = process.env.GITHUB_API_URL || 'https://api.github.com';
  const res = await fetch(`${api}/repos/${repo}/code-scanning/sarifs`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    body: JSON.stringify({
      commit_sha: process.env.GITHUB_SHA,
      ref: process.env.GITHUB_REF,
      sarif: require('zlib').gzipSync(fs.readFileSync(sarifPath)).toString('base64'),
      tool_name: 'BuildLens',
    }),
  });
  if (!res.ok) {
    // 403: the job lacks `security-events: write`, or code scanning is off for this private repo.
    throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  }
  console.log('BuildLens SARIF uploaded to code scanning.');
}

try {
  post();
} catch (e) {
  console.log(`::warning::BuildLens post-run error: ${e.message}`);
}
