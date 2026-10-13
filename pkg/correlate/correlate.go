package correlate

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/buildlens/buildlens/pkg/attribution"
	"github.com/buildlens/buildlens/pkg/runschema"
)

const (
	ruleTaintedEgress       = "TAINTED_EGRESS"
	ruleProcessMemoryRead   = "PROCESS_MEMORY_READ"
	ruleInstallScriptEgress = "INSTALL_SCRIPT_EGRESS"
	ruleEnvExfil            = "ENV_EXFIL"
	defaultTaintWindow      = 60 * 1e9 // 60 seconds in nanoseconds
)

type ScoreOptions struct {
	LockfilePath    string
	TaintWindowNano int64
	AgentHealth     runschema.AgentHealth
	// AllowHosts adds to the built-in install-host list: extra hosts a
	// dependency's install script may contact without tripping
	// INSTALL_SCRIPT_EGRESS (e.g. Puppeteer/Cypress binary mirrors).
	// Compared case-insensitively against bare hostnames/IPs, no wildcards.
	AllowHosts []string
}

type procNode struct {
	PID          uint32
	PPID         uint32
	Comm         string
	Cmdline      string
	Cwd          string
	ProcessChain []string
	Attribution  runschema.Attribution
	Tainted      *taintMark
	Agent        string // AI coding agent this process belongs to, if any
	// envVars holds sensitive environment variable NAMES present at exec
	// (values never captured). Environ is fork-inherited, so children start
	// with the parent's set until their own exec refreshes it.
	envVars []string
	envTS   int64
}

type taintMark struct {
	path       string
	tier       string
	ts         int64
	originPID  uint32
	originComm string
}

// Score evaluates events deterministically using default options.
func Score(events []runschema.Event) runschema.Manifest {
	return ScoreWithOptions(events, ScoreOptions{})
}

// ScoreWithOptions evaluates events deterministically with ancestor-process taint propagation.
func ScoreWithOptions(events []runschema.Event, opts ScoreOptions) runschema.Manifest {
	// Send totals are per-run aggregates, not points in time: pull them out of
	// the timeline and attach them to findings by (pid, dest) afterwards.
	sentBytes := map[string]uint64{}
	haveSendTelemetry := false
	lookups := map[string][]runschema.Event{}    // IP -> dns events, by time
	sniLookups := map[string][]runschema.Event{} // IP -> sni events, by time
	sorted := make([]runschema.Event, 0, len(events))
	for _, e := range events {
		if e.Kind == "dns" {
			lookups[e.Dest] = append(lookups[e.Dest], e)
			continue
		}
		if e.Kind == "sni" {
			sniLookups[e.Dest] = append(sniLookups[e.Dest], e)
			continue
		}
		if e.Kind == "send" {
			haveSendTelemetry = true
			sentBytes[flowKey(e.PID, e.Dest)] += e.BytesSent
			continue
		}
		sorted = append(sorted, e)
	}
	slices.SortFunc(sorted, cmpEvent)
	for _, m := range []map[string][]runschema.Event{lookups, sniLookups} {
		for _, l := range m {
			slices.SortFunc(l, func(a, b runschema.Event) int {
				if n := cmp.Compare(a.TS, b.TS); n != 0 {
					return n
				}
				return strings.Compare(a.Host, b.Host)
			})
		}
	}

	taintWindow := opts.TaintWindowNano
	if taintWindow <= 0 {
		taintWindow = defaultTaintWindow
	}

	procs := map[uint32]*procNode{}
	dedupKeys := map[string]struct{}{}
	var findings []runschema.Finding
	activity := map[string]*agentLog{}
	logFor := func(p *procNode) *agentLog {
		if p.Agent == "" {
			return nil
		}
		if activity[p.Agent] == nil {
			activity[p.Agent] = &agentLog{files: map[string]struct{}{}, hosts: map[string]struct{}{}, cmds: map[string]struct{}{}}
		}
		return activity[p.Agent]
	}

	for _, e := range sorted {
		proc, exists := procs[e.PID]
		if !exists {
			chain := []string{e.Comm}
			parent := procs[e.PPID]
			agent := agentName(e.Comm, e.Cmdline)
			attr := runschema.UnknownAttribution()
			switch {
			case strings.Contains(filepath.ToSlash(e.Cwd), "node_modules/"):
				// A package's own lifecycle script: blame the package, not
				// whatever (npm, an AI agent) started it.
				attr = attribution.AttributeProcess(e.Cwd, e.Cmdline, opts.LockfilePath)
				if parent != nil && parent.Attribution.Package.Name == attr.Package.Name {
					attr = parent.Attribution // same package; keeps the lifecycle it started in
				}
			case agent != "":
				attr = agentAttribution(agent)
			case parent != nil:
				attr = parent.Attribution
			}
			if parent != nil {
				chain = append(slices.Clone(parent.ProcessChain), e.Comm)
				if agent == "" {
					agent = parent.Agent
				}
			}
			if attr.IsUnknown() && (e.Cwd != "" || e.Cmdline != "") {
				attr = attribution.AttributeProcess(e.Cwd, e.Cmdline, opts.LockfilePath)
			}
			proc = &procNode{
				PID:          e.PID,
				PPID:         e.PPID,
				Comm:         e.Comm,
				Cmdline:      e.Cmdline,
				Cwd:          e.Cwd,
				ProcessChain: chain,
				Attribution:  attr,
				Agent:        agent,
			}
			// Inherit taint from parent if within expiration window
			if parent, parentExists := procs[e.PPID]; parentExists && parent.Tainted != nil {
				if (e.TS - parent.Tainted.ts) <= taintWindow {
					proc.Tainted = parent.Tainted
				}
			}
			// Environ is fork-inherited: start with the parent's sensitive
			// names until this process's own exec refreshes them.
			if parent, parentExists := procs[e.PPID]; parentExists && len(parent.envVars) > 0 {
				if (e.TS - parent.envTS) <= taintWindow {
					proc.envVars = parent.envVars
					proc.envTS = parent.envTS
				}
			}
			procs[e.PID] = proc
		}

		if e.Comm != "" {
			proc.Comm = e.Comm
		}
		if e.Cmdline != "" {
			proc.Cmdline = e.Cmdline
		}
		if e.Cwd != "" {
			proc.Cwd = e.Cwd
		}
		if proc.Attribution.IsUnknown() && (proc.Cwd != "" || proc.Cmdline != "") {
			proc.Attribution = attribution.AttributeProcess(proc.Cwd, proc.Cmdline, opts.LockfilePath)
		}

		switch e.Kind {
		case "exec":
			if a := agentName(proc.Comm, proc.Cmdline); a != "" && proc.Agent != a {
				proc.Agent = a
				proc.Attribution = agentAttribution(a)
			}
			// execve replaces the environment: refresh from the agent-captured
			// names (already sensitive-filtered; empty means clean). This also
			// clears inherited names — a re-exec without secrets is clean, and
			// recordings that predate capture simply never taint.
			proc.envVars = SensitiveEnvNames(e.EnvNames)
			proc.envTS = e.TS
			// Record what the agent ran, not the agent binary itself (its
			// command line is the prompt).
			if l := logFor(proc); l != nil && agentName(proc.Comm, proc.Cmdline) == "" && proc.Cmdline != "" {
				l.addCommand(redact(proc.Cmdline))
			}
			// If parent exists and child newly execed, inherit parent's taint if valid
			if parent, parentExists := procs[e.PPID]; parentExists && parent.Tainted != nil {
				if (e.TS - parent.Tainted.ts) <= taintWindow {
					proc.Tainted = parent.Tainted
				}
				if proc.Attribution.IsUnknown() && !parent.Attribution.IsUnknown() {
					proc.Attribution = parent.Attribution
				}
			}

		case "open":
			tier := fileTier(e.Path)
			if tier == "" || (tier == "git_credential" && isGit(proc.Comm)) {
				continue
			}
			if tier == "process_memory" {
				if !readsOtherProcess(e.Path, e.PID) {
					continue
				}
				// Self-observation: the agent reads /proc/<pid>/environ at
				// every exec to capture env names. Flagging that would
				// incriminate the observer on every run. The opens stay in
				// the event stream for audit; they just aren't findings.
				// ponytail: comm match, like isGit — a payload named
				// "bl-agent" evades this the same way.
				if proc.Comm == "bl-agent" {
					continue
				}
				// Scraping another process's memory or environment is the
				// finding on its own; secrets can leave via logs, not just egress.
				dedupKey := fmt.Sprintf("%s|%s|%s|%s", ruleProcessMemoryRead, e.Path, proc.Attribution.Package.Name, proc.Comm)
				if _, seen := dedupKeys[dedupKey]; !seen {
					dedupKeys[dedupKey] = struct{}{}
					chain := proc.ProcessChain
					if len(chain) == 0 {
						chain = []string{proc.Comm}
					}
					findings = append(findings, runschema.Finding{
						Rule:     ruleProcessMemoryRead,
						Severity: "critical",
						Aggregatable: runschema.FindingAgg{
							Package:  proc.Attribution.Package,
							FileTier: tier,
						},
						Context: runschema.FindingContext{
							PID:          e.PID,
							Comm:         proc.Comm,
							Path:         e.Path,
							ProcessChain: chain,
							Cmdline:      proc.Cmdline,
							Cwd:          proc.Cwd,
							Fingerprint:  computeFingerprint(ruleProcessMemoryRead, tier, "", proc.Attribution.Package.Name),
							Attribution:  proc.Attribution,
						},
					})
				}
			}
			if l := logFor(proc); l != nil {
				l.files[e.Path] = struct{}{}
			}
			proc.Tainted = &taintMark{
				path:       e.Path,
				tier:       tier,
				ts:         e.TS,
				originPID:  e.PID,
				originComm: e.Comm,
			}

		case "connect":
			ip := destHost(e.Dest)
			// SNI is authoritative — it names the host on this actual
			// connection, so it wins over DNS (stale entries, shared CDN IPs).
			// DNS covers what SNI cannot: plaintext, resumed sessions, and
			// handshakes the sniffer missed.
			dHost := ip
			if h := resolvedHost(sniLookups[ip], e.TS); h != "" {
				dHost = h
			} else if h := resolvedHost(lookups[ip], e.TS); h != "" {
				dHost = h
			}
			if l := logFor(proc); l != nil && !isLoopback(ip) {
				l.hosts[dHost] = struct{}{}
			}

			var elapsedNano int64
			if proc.Tainted != nil {
				elapsedNano = max(e.TS-proc.Tainted.ts, 0)
			}
			if proc.Tainted == nil || elapsedNano > taintWindow {
				// No secret read first. Still suspicious if a dependency's install
				// script calls anything but the registry: secrets in env vars
				// leave without ever opening a file.
				if !isInstallScript(proc) || isLoopback(ip) || allowedInstallHost(dHost, opts.AllowHosts) {
					continue
				}
				// An install script holding secret-named variables upgrades the
				// finding: same trigger domain, but the held names are evidence.
				rule := ruleInstallScriptEgress
				if len(freshEnvVars(proc, e.TS, taintWindow)) > 0 {
					rule = ruleEnvExfil
				}
				dedupKey := fmt.Sprintf("%s|%s|%s", rule, dHost, proc.Attribution.Package.Name)
				if _, seen := dedupKeys[dedupKey]; seen {
					continue
				}
				dedupKeys[dedupKey] = struct{}{}
				chain := proc.ProcessChain
				if len(chain) == 0 {
					chain = []string{proc.Comm}
				}
				finding := runschema.Finding{
					Rule:     rule,
					Severity: "high",
					Aggregatable: runschema.FindingAgg{
						Package:  proc.Attribution.Package,
						DestHost: dHost,
					},
					Context: runschema.FindingContext{
						PID:          e.PID,
						Comm:         e.Comm,
						Dest:         e.Dest,
						ProcessChain: chain,
						Cmdline:      proc.Cmdline,
						Cwd:          proc.Cwd,
						Fingerprint:  computeFingerprint(rule, "", dHost, proc.Attribution.Package.Name),
						Attribution:  proc.Attribution,
					},
				}
				if rule == ruleEnvExfil {
					finding.Context.EnvVars = freshEnvVars(proc, e.TS, taintWindow)
				}
				findings = append(findings, finding)
				continue
			}
			if proc.Agent != "" && (isModelHost(dHost) || (isGit(proc.Comm) && dHost == "github.com")) {
				// An agent sends what it reads to its model API by design, and
				// pushes its work with git, where it's reviewable in the diff.
				// Both show in the activity report; anywhere else is a finding,
				// including api.github.com (a comment or gist carrying the secret).
				continue
			}
			elapsedMS := elapsedNano / 1e6

			dedupKey := fmt.Sprintf("%s|%s|%s|%s", proc.Tainted.path, dHost, proc.Attribution.Package.Name, proc.Comm)
			if _, seen := dedupKeys[dedupKey]; seen {
				continue
			}
			dedupKeys[dedupKey] = struct{}{}

			fingerprint := computeFingerprint(ruleTaintedEgress, proc.Tainted.tier, dHost, proc.Attribution.Package.Name)

			chain := proc.ProcessChain
			if len(chain) == 0 {
				chain = []string{proc.Comm}
			}

			findings = append(findings, runschema.Finding{
				Rule:     ruleTaintedEgress,
				Severity: "critical",
				Aggregatable: runschema.FindingAgg{
					Package:   proc.Attribution.Package,
					DestHost:  dHost,
					FileTier:  proc.Tainted.tier,
					ElapsedMS: elapsedMS,
				},
				Context: runschema.FindingContext{
					PID:          e.PID,
					Comm:         e.Comm,
					Path:         proc.Tainted.path,
					Dest:         e.Dest,
					ProcessChain: chain,
					Cmdline:      proc.Cmdline,
					Cwd:          proc.Cwd,
					Fingerprint:  fingerprint,
					Attribution:  proc.Attribution,
				},
			})
		}
	}

	for i := range findings {
		if p := procs[findings[i].Context.PID]; p != nil {
			findings[i].Context.Agent = p.Agent
		}
	}

	if haveSendTelemetry {
		for i := range findings {
			if findings[i].Context.Dest == "" {
				continue // no egress in this finding, so nothing was sent
			}
			n := sentBytes[flowKey(findings[i].Context.PID, findings[i].Context.Dest)]
			findings[i].Aggregatable.BytesSent = &n
		}
	}

	slices.SortFunc(findings, cmpFinding)

	status := "clean"
	if opts.AgentHealth.Degraded || opts.AgentHealth.EventsDropped > 0 {
		status = "degraded"
	} else if len(findings) > 0 {
		status = "findings"
	}

	return runschema.Manifest{
		SchemaVersion:  runschema.SchemaVersion,
		RulesetVersion: runschema.RulesetVersion,
		Status:         status,
		EventCount:     len(events),
		AgentHealth:    opts.AgentHealth,
		Findings:       findings,
		Agents:         agentActivities(activity),
	}
}

func flowKey(pid uint32, dest string) string {
	return fmt.Sprintf("%d|%s", pid, dest)
}

func computeFingerprint(rule, tier, host, pkg string) string {
	h := sha256.New()
	h.Write([]byte(rule + "|" + tier + "|" + host + "|" + pkg))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func cmpEvent(a, b runschema.Event) int {
	if n := cmp.Compare(a.TS, b.TS); n != 0 {
		return n
	}
	if n := cmp.Compare(a.PID, b.PID); n != 0 {
		return n
	}
	return strings.Compare(a.Kind, b.Kind)
}

func cmpFinding(a, b runschema.Finding) int {
	if n := strings.Compare(a.Rule, b.Rule); n != 0 {
		return n
	}
	if n := strings.Compare(a.Aggregatable.DestHost, b.Aggregatable.DestHost); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Context.PID, b.Context.PID); n != 0 {
		return n
	}
	return strings.Compare(a.Context.Path, b.Context.Path)
}

func fileTier(path string) string {
	lower := strings.ToLower(path)

	// Safe templates and non-secret examples are never credential-bearing
	if strings.HasSuffix(lower, ".example") ||
		strings.HasSuffix(lower, ".sample") ||
		strings.HasSuffix(lower, ".template") ||
		strings.HasSuffix(lower, ".test") {
		return ""
	}

	switch {
	// Another process's memory or environment: how the tj-actions payload
	// pulled every secret out of Runner.Worker.
	case strings.HasPrefix(lower, "/proc/") && (strings.HasSuffix(lower, "/mem") || strings.HasSuffix(lower, "/environ")):
		return "process_memory"
	case strings.Contains(lower, ".env"):
		return "env"
	case strings.Contains(lower, ".npmrc") || strings.Contains(lower, ".yarnrc") || strings.Contains(lower, "pip.conf"):
		return "package_token"
	case strings.Contains(lower, ".aws/credentials") || strings.Contains(lower, ".aws/config"):
		return "cloud_credential"
	case strings.Contains(lower, ".ssh/id_") || strings.Contains(lower, ".ssh/authorized_keys"):
		return "ssh_key"
	case strings.Contains(lower, ".netrc") || strings.Contains(lower, ".git-credentials") || strings.Contains(lower, ".gitconfig") ||
		strings.Contains(lower, ".git/config"): // actions/checkout persists GITHUB_TOKEN here
		return "git_credential"
	case strings.Contains(lower, "/etc/shadow") || strings.Contains(lower, "/etc/security"):
		return "system_auth"
	case isRunnerEnvFile(lower):
		return "runner_env"
	default:
		return ""
	}
}

// isRunnerEnvFile matches CI runner temp env files, where step secrets also
// live on disk (GitHub Actions: $RUNNER_TEMP/_runner_file_commands/add_env_*,
// github_env_*). Reading one taints like reading a .env. Pure in-memory
// process.env reads still open no file and stay blind — see README.
func isRunnerEnvFile(lower string) bool {
	base := lower[strings.LastIndex(lower, "/")+1:]
	if strings.HasSuffix(base, ".env.sh") {
		return true
	}
	if !strings.Contains(lower, "_temp") {
		return false
	}
	return strings.Contains(base, "env") || strings.Contains(lower, "_runner_file_commands")
}

// isGit reports git itself, which reads its own config and credentials before
// every fetch. ponytail: matches comm only, so a payload named "git" evades it;
// check the exe path if that shows up.
func isGit(comm string) bool {
	return comm == "git" || strings.HasPrefix(comm, "git-")
}

// readsOtherProcess reports whether a /proc/<pid>/... path names a process other
// than the reader. Reading your own environ is no worse than having the env.
func readsOtherProcess(path string, pid uint32) bool {
	parts := strings.Split(path, "/") // "", "proc", "<pid>", ...
	if len(parts) < 3 {
		return false
	}
	target := parts[2]
	return target != "self" && target != "thread-self" && target != fmt.Sprint(pid)
}

// isInstallScript reports a dependency's install-time code. npm runs every
// lifecycle script with its cwd set to the package's own node_modules folder.
func isInstallScript(p *procNode) bool {
	if p.Attribution.IsUnknown() {
		return false
	}
	switch p.Attribution.Lifecycle {
	case "preinstall", "install", "postinstall":
		return true
	}
	return strings.Contains(filepath.ToSlash(p.Cwd), "node_modules/")
}

// freshEnvVars reports the process's sensitive environment names when the
// capture is still within the taint window; stale or absent sets yield nil.
func freshEnvVars(p *procNode, now, taintWindow int64) []string {
	if len(p.envVars) == 0 || (now-p.envTS) > taintWindow {
		return nil
	}
	return p.envVars
}

// installHosts are where install scripts legitimately fetch packages, prebuilt
// binaries and node-gyp headers. Extra hosts come from ScoreOptions.AllowHosts
// (the `allow-hosts` Action input) for packages like Puppeteer/Cypress that
// download binaries from their own mirrors.
var installHosts = []string{
	"registry.npmjs.org", "registry.yarnpkg.com", "npm.pkg.github.com",
	"github.com", "codeload.github.com", "objects.githubusercontent.com",
	"release-assets.githubusercontent.com", "nodejs.org",
}

func allowedInstallHost(host string, extra []string) bool {
	h := normalizeHost(host)
	if slices.Contains(installHosts, h) {
		return true
	}
	for _, e := range extra {
		if normalizeHost(e) == h {
			return true
		}
	}
	return false
}

// normalizeHost lowercases, trims spaces and strips an optional :port so
// user-supplied entries like "CDN.example.com:443" match bare dest hosts.
func normalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if bare, _, err := net.SplitHostPort(h); err == nil {
		h = bare
	}
	return strings.TrimSuffix(h, ".")
}

func isLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

// resolvedHost is the name from the latest lookup of this IP before the connect.
// Lookups are stamped with kernel arrival time, so a later lookup of the same IP
// (another process resolving a name) never relabels an earlier connect.
// ponytail: for DNS, a CDN IP shared by many names gets the most recent one;
// per-process attribution of lookups needs the resolver's socket, not a
// sniffer. SNI lookups don't share this weakness — each names its own
// connection — which is why they take precedence at the call site.
func resolvedHost(lookups []runschema.Event, ts int64) string {
	host := ""
	for _, l := range lookups {
		if l.TS > ts {
			break
		}
		host = l.Host
	}
	return host
}

func destHost(dest string) string {
	if host, _, err := net.SplitHostPort(dest); err == nil {
		return host
	}
	if strings.HasPrefix(dest, "[") && strings.HasSuffix(dest, "]") {
		return strings.Trim(dest, "[]")
	}
	return dest
}

// LoadJSONL reads spike or schema JSONL. Spike's TAINTED_EGRESS rows are
// ignored — findings are always recomputed.
func LoadJSONL(r io.Reader) ([]runschema.Event, error) {
	dec := json.NewDecoder(r)
	var out []runschema.Event
	for {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				return out, nil
			}
			return nil, err
		}
		kind, _ := rec["kind"].(string)
		if kind == "" {
			kind, _ = rec["type"].(string)
		}
		if kind == "" || kind == "TAINTED_EGRESS" {
			continue
		}
		if kind != "exec" && kind != "open" && kind != "connect" && kind != "send" && kind != "dns" && kind != "sni" && kind != "wouldblock" {
			continue
		}
		ev := runschema.Event{Kind: kind}
		if ts, ok := rec["ts"].(float64); ok {
			ev.TS = int64(ts)
		}
		if pid, ok := rec["pid"].(float64); ok {
			ev.PID = uint32(pid)
		}
		if ppid, ok := rec["ppid"].(float64); ok {
			ev.PPID = uint32(ppid)
		}
		if comm, ok := rec["comm"].(string); ok {
			ev.Comm = comm
		}
		if path, ok := rec["path"].(string); ok {
			ev.Path = path
		}
		if dest, ok := rec["dest"].(string); ok {
			ev.Dest = dest
		}
		if host, ok := rec["host"].(string); ok {
			ev.Host = host
		}
		if cmdline, ok := rec["cmdline"].(string); ok {
			ev.Cmdline = cmdline
		}
		if cwd, ok := rec["cwd"].(string); ok {
			ev.Cwd = cwd
		}
		if n, ok := rec["bytes_sent"].(float64); ok {
			ev.BytesSent = uint64(n)
		}
		if rawNames, ok := rec["env_names"].([]any); ok {
			for _, rn := range rawNames {
				if s, ok := rn.(string); ok && s != "" {
					ev.EnvNames = append(ev.EnvNames, s)
				}
			}
		}
		out = append(out, ev)
	}
}

func LoadJSONLFile(path string) ([]runschema.Event, error) {
	if path == "" {
		return nil, os.ErrNotExist
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LoadJSONL(f)
}

// agentName recognizes an AI coding agent from its process name or command
// line. Package managers are skipped so `npm i -g @anthropic-ai/claude-code`
// isn't mistaken for the agent; `npx` still spawns the agent's own node process.
// ponytail: fixed signatures; Copilot's coding agent is matched on its CLI
// package name and hasn't been verified on a live run.
func agentName(comm, cmdline string) string {
	switch comm {
	case "npm", "npx", "yarn", "pnpm":
		return ""
	}
	c := strings.ToLower(cmdline)
	switch {
	case comm == "claude" || strings.Contains(c, "@anthropic-ai/claude-code"):
		return "claude-code"
	case comm == "codex" || strings.Contains(c, "@openai/codex"):
		return "codex"
	case comm == "gemini" || strings.Contains(c, "@google/gemini-cli"):
		return "gemini-cli"
	case comm == "copilot" || strings.Contains(c, "@github/copilot"):
		return "copilot"
	case comm == "cursor-agent":
		return "cursor-agent"
	}
	return ""
}

func agentAttribution(agent string) runschema.Attribution {
	return runschema.Attribution{
		Package:    runschema.PackageID{Ecosystem: "agent", Name: agent},
		Confidence: "probable",
		Lifecycle:  "agent",
	}
}

// isModelHost reports the model APIs agents send their context to.
func isModelHost(host string) bool {
	h := strings.ToLower(host)
	for _, d := range []string{"anthropic.com", "openai.com", "githubcopilot.com"} {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return h == "chatgpt.com" || h == "generativelanguage.googleapis.com"
}

const maxAgentCommands = 50

type agentLog struct {
	commands []string
	omitted  int
	cmds     map[string]struct{}
	files    map[string]struct{}
	hosts    map[string]struct{}
}

func (l *agentLog) addCommand(cmd string) {
	if _, seen := l.cmds[cmd]; seen {
		return
	}
	l.cmds[cmd] = struct{}{}
	if len(l.commands) >= maxAgentCommands {
		l.omitted++
		return
	}
	l.commands = append(l.commands, cmd)
}

func agentActivities(activity map[string]*agentLog) []runschema.AgentActivity {
	var out []runschema.AgentActivity
	for name, l := range activity {
		out = append(out, runschema.AgentActivity{
			Agent:           name,
			Commands:        append([]string{}, l.commands...),
			CommandsOmitted: l.omitted,
			SecretFiles:     sortedKeys(l.files),
			Hosts:           sortedKeys(l.hosts),
		})
	}
	slices.SortFunc(out, func(a, b runschema.AgentActivity) int { return strings.Compare(a.Agent, b.Agent) })
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// secretLike matches long unbroken runs typical of tokens and keys.
var secretLike = regexp.MustCompile(`[A-Za-z0-9_\-+=]{20,}`)

// redact masks secret-looking strings before a command reaches the job summary,
// which anyone who can read the repo can see. ponytail: length heuristic; it
// over-masks long hyphenated names and misses short secrets.
func redact(cmd string) string {
	if len(cmd) > 300 {
		cmd = cmd[:300] + "…"
	}
	return secretLike.ReplaceAllString(cmd, "***")
}
