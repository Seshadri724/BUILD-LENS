#!/usr/bin/env python3
"""
Paired benchmark runner for BuildLens production agent & eBPF probes.
Measures:
  1. No probe (baseline)
  2. Exec probe only
  3. Open probe only (with in-kernel sensitive path filtering)
  4. Connect probe only
  5. Full probe (no JSON output)
  6. Full probe (normal mode)
  7. Full probe (debug JSONL output)

For every configuration, measures paired interleaved runs:
  baseline 1 -> instrumented 1 -> baseline 2 -> instrumented 2 ...
Records runtime, event count, ring-buffer drops, agent CPU time, and file size.
Reports median, p90, absolute overhead (ms), and relative percentage.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


def percentile(vals, p):
    if not vals:
        return 0.0
    sorted_v = sorted(vals)
    k = (len(sorted_v) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_v) - 1)
    d = k - f
    return sorted_v[f] + d * (sorted_v[c] - sorted_v[f])


def median(vals):
    return percentile(vals, 50)


def p90(vals):
    return percentile(vals, 90)


def run_workload(app_dir, workload_cmd):
    node_modules = Path(app_dir) / "node_modules"
    if node_modules.exists():
        shutil.rmtree(node_modules, ignore_errors=True)

    t0 = time.perf_counter()
    res = subprocess.run(
        workload_cmd,
        cwd=app_dir,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    t1 = time.perf_counter()
    if res.returncode != 0:
        print(f"Warning: workload command failed with code {res.returncode}", file=sys.stderr)
    return t1 - t0


def wait_for_ready(ready_path, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(ready_path):
            return True
        time.sleep(0.05)
    return False


def start_probe(agent_bin, args, out_events, stats_out):
    ready_path = out_events + ".ready"
    if os.path.exists(ready_path):
        try:
            os.remove(ready_path)
        except OSError:
            pass

    cmd = [
        "sudo", "-n", str(agent_bin),
        "record",
        "-duration", "600s",
        "-out", out_events,
        "-stats-out", stats_out,
    ] + args

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 10.0
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"Agent exited prematurely with returncode {proc.returncode} before readiness")
        if os.path.exists(ready_path):
            return proc
        time.sleep(0.05)

    stop_probe(proc)
    raise RuntimeError("Agent probe never signaled readiness within 10s")


def stop_probe(proc):
    if proc and proc.poll() is None:
        subprocess.run(["sudo", "-n", "kill", "-SIGINT", str(proc.pid)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            subprocess.run(["sudo", "-n", "kill", "-9", str(proc.pid)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc.wait(timeout=2.0)


def main():
    parser = argparse.ArgumentParser(description="Run BuildLens probe overhead benchmarks")
    parser.add_argument("--app-dir", default="spike/fixtures/realistic-node-app", help="Target app fixture dir")
    parser.add_argument("--workload", default="npm ci --silent && npm run build && npm test", help="Command to benchmark")
    parser.add_argument("--agent-bin", default="bin/bl-agent", help="Path to agent binary")
    parser.add_argument("--pairs", type=int, default=15, help="Number of paired iterations")
    parser.add_argument("--out-dir", default="out", help="Output directory for reports")
    parser.add_argument("--quick", action="store_true", help="Quick mode (fewer pairs)")
    args = parser.parse_args()

    n_pairs = 5 if args.quick else args.pairs
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    agent_bin = args.agent_bin
    is_linux = sys.platform.startswith("linux")
    if is_linux:
        if not Path(agent_bin).exists():
            raise FileNotFoundError(f"Agent binary not found at {agent_bin}. Cannot benchmark on Linux without agent binary.")
        has_agent = True
    else:
        has_agent = False
        print(f"Notice: Platform is not Linux (running in dry simulation mode on {sys.platform})")

    configs = [
        {"name": "exec-only", "flags": ["-probes", "exec"]},
        {"name": "open-only", "flags": ["-probes", "open"]},
        {"name": "connect-only", "flags": ["-probes", "connect"]},
        {"name": "full-no-json", "flags": ["-probes", "all", "-no-json"]},
        {"name": "full-normal", "flags": ["-probes", "all"]},
        {"name": "full-debug", "flags": ["-probes", "all", "-debug"]},
    ]

    summary_results = []
    print(f"\n========================================================")
    print(f" BuildLens Agent Overhead Benchmark: {n_pairs} Paired Iterations")
    print(f" Binary: {agent_bin} | App: {args.app_dir}")
    print(f" Workload: {args.workload}")
    print(f"========================================================\n")

    for cfg in configs:
        cfg_name = cfg["name"]
        print(f"--> Running paired benchmark for configuration: {cfg_name}...")
        baseline_times = []
        instrumented_times = []
        events_totals = []
        drops_totals = []
        file_sizes = []
        cpu_times = []

        out_events = f"/tmp/bench-{cfg_name}-events.jsonl"
        stats_file = f"/tmp/bench-{cfg_name}-stats.json"

        for i in range(1, n_pairs + 1):
            # 1. Baseline run (no probe)
            b_dur = run_workload(args.app_dir, args.workload)
            baseline_times.append(b_dur)

            # 2. Instrumented run
            proc = None
            if has_agent:
                proc = start_probe(agent_bin, cfg["flags"], out_events, stats_file)

            inst_dur = run_workload(args.app_dir, args.workload)
            instrumented_times.append(inst_dur)

            if proc:
                stop_probe(proc)

                if not os.path.exists(stats_file):
                    raise RuntimeError(f"Benchmark error: stats file {stats_file} missing after instrumented run")

                try:
                    with open(stats_file) as f:
                        st = json.load(f)
                except Exception as e:
                    raise RuntimeError(f"Benchmark error: failed to parse stats file {stats_file}: {e}")

                ev_count = st.get("events_total", 0)
                if ev_count == 0 and "-no-json" not in cfg["flags"]:
                    raise RuntimeError(f"Benchmark error: event count is 0 in {stats_file} for config {cfg_name}")

                events_totals.append(ev_count)
                drops_totals.append(st.get("ring_buffer_drops", 0))
                file_sizes.append(st.get("file_size_bytes", 0))
                cpu_times.append(st.get("agent_cpu_time_ms", 0))

                if "-no-json" not in cfg["flags"]:
                    if not os.path.exists(out_events):
                        raise RuntimeError(f"Benchmark error: event file {out_events} missing after instrumented run")
                    if os.path.getsize(out_events) == 0:
                        raise RuntimeError(f"Benchmark error: event file {out_events} is empty after instrumented run")

        b_med = median(baseline_times)
        b_p90 = p90(baseline_times)
        i_med = median(instrumented_times)
        i_p90 = p90(instrumented_times)

        diff_ms = (i_med - b_med) * 1000.0
        overhead_pct = ((i_med - b_med) / b_med * 100.0) if b_med > 0 else 0.0

        avg_events = sum(events_totals) / len(events_totals) if events_totals else 0
        total_drops = sum(drops_totals) if drops_totals else 0
        avg_size = sum(file_sizes) / len(file_sizes) if file_sizes else 0
        avg_cpu = sum(cpu_times) / len(cpu_times) if cpu_times else 0

        res_entry = {
            "configuration": cfg_name,
            "pairs": n_pairs,
            "baseline_median_s": round(b_med, 4),
            "baseline_p90_s": round(b_p90, 4),
            "instrumented_median_s": round(i_med, 4),
            "instrumented_p90_s": round(i_p90, 4),
            "delta_ms": round(diff_ms, 2),
            "overhead_pct": round(overhead_pct, 2),
            "avg_events": round(avg_events, 1),
            "total_drops": total_drops,
            "avg_file_size_bytes": round(avg_size, 0),
            "avg_cpu_time_ms": round(avg_cpu, 1),
            "pass": overhead_pct <= 5.0 and total_drops == 0,
        }
        summary_results.append(res_entry)

        status_str = "PASS" if res_entry["pass"] else "FAIL"
        print(f"    Baseline: {b_med:.3f}s (p90 {b_p90:.3f}s) | Instrumented: {i_med:.3f}s (p90 {i_p90:.3f}s)")
        print(f"    Overhead: {overhead_pct:+.2f}% ({diff_ms:+.1f}ms) | CPU: {avg_cpu:.1f}ms | Drops: {total_drops} | Status: {status_str}\n")

    # Write JSON summary
    json_path = out_dir / "benchmark-breakdown.json"
    with open(json_path, "w") as f:
        json.dump(summary_results, f, indent=2)

    # Write overhead.txt
    txt_path = out_dir / "overhead.txt"
    with open(txt_path, "w") as f:
        full_cfg = next((c for c in summary_results if c["configuration"] == "full-normal"), summary_results[0])
        f.write(f"baseline_median_s={full_cfg['baseline_median_s']:.3f}\n")
        f.write(f"instrumented_median_s={full_cfg['instrumented_median_s']:.3f}\n")
        f.write(f"overhead_pct={full_cfg['overhead_pct']:.2f}\n")
        f.write(f"delta_ms={full_cfg['delta_ms']:.1f}\n")
        f.write(f"agent_cpu_ms={full_cfg['avg_cpu_time_ms']:.1f}\n")
        f.write(f"ring_buffer_drops={full_cfg['total_drops']}\n")
        f.write(f"pass={'true' if full_cfg['pass'] else 'false'}\n\n")

        f.write("CONFIGURATION BREAKDOWN:\n")
        f.write(f"{'Configuration':<16} {'Base Med':<10} {'Inst Med':<10} {'Delta ms':<10} {'Overhead':<10} {'CPU ms':<10} {'Drops':<8} {'Status'}\n")
        f.write("-" * 85 + "\n")
        for r in summary_results:
            st = "PASS" if r["pass"] else "FAIL"
            f.write(f"{r['configuration']:<16} {r['baseline_median_s']:<10.3f} {r['instrumented_median_s']:<10.3f} {r['delta_ms']:<+10.1f} {r['overhead_pct']:<+9.2f}% {r['avg_cpu_time_ms']:<10.1f} {r['total_drops']:<8} {st}\n")

    print(f"Saved benchmark results to {json_path} and {txt_path}")


if __name__ == "__main__":
    main()
