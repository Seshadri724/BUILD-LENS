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
      ruleset_version: '1.1.0',
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
      ruleset_version: '1.1.0',
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

  try {
    const scoreCmd = `"${scoreBin}" score -in "${eventsPath}" -stats "${statsPath}" -out "${manifestOut}" -sarif "${sarifOut}" -lockfile "${lockfilePath}"`;
    execSync(scoreCmd, { stdio: 'inherit' });

    if (fs.existsSync(manifestOut)) {
      const manifest = JSON.parse(fs.readFileSync(manifestOut, 'utf8'));
      setOutput('manifest', manifestOut);
      setOutput('sarif', sarifOut);
      setOutput('status', manifest.status || 'clean');
      setOutput('findings_count', (manifest.findings ? manifest.findings.length : 0).toString());
    }
  } catch (err) {
    console.log(`::warning::Scoring encountered an error: ${err.message}`);
  }

  console.log('BuildLens post-processing completed.');
}

try {
  post();
} catch (e) {
  console.log(`::warning::BuildLens post-run error: ${e.message}`);
}
