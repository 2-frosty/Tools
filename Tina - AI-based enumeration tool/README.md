# Tina Security v1.0

**Tina is Not an Agent** — an AI-powered reconnaissance & enumeration assistant for authorised security testing engagements.

Tina runs on [Ollama](https://ollama.ai/) (currently qwen3.5) and provides an interactive CLI for:
- **Automated recon** — Tier-1 read-only commands (nmap, curl, dig, whatweb) run immediately
- **User-controlled actions** — Tier-2 commands (gobuster, nikto, hydra, sqlmap) pause for your approval
- **Scope enforcement** — All commands are checked against your declared authorised target range
- **Findings tracking** — Structured database of discovered vulnerabilities with severity levels
- **Report generation** — Markdown & JSON reports with audit logs

## Quick Start

### Prerequisites
- Python 3.9+
- [Ollama](https://ollama.ai/) running locally with `qwen3.5` model pulled
- Linux (tested on Debian/Ubuntu)
- Common recon tools (nmap, curl, dig, etc.)

### Installation

**Step 1: Install Python dependencies**

```bash
pip install -r requirements.txt
```

This installs:
- `requests` — HTTP client for Ollama API calls
- `rich` — Terminal UI library for formatted output

**Step 2: Set up Ollama** (in a separate terminal)

```bash
ollama pull qwen3.5
ollama serve
```

**Step 3: Run Tina** (in your main terminal)

```bash
python3 Tina_Security_v1.0.py --scope 192.168.1.0/24 --wordlist /path/to/wordlist.txt
```

**Optional: Use a Python virtual environment**

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 Tina_Security_v1.0.py
```

### CLI Arguments

```
--scope RANGE           Pre-authorise a target IP, hostname, or CIDR (e.g., 192.168.1.0/24)
--wordlist PATH         Path to a wordlist for directory/vhost enumeration (rockyou.txt, etc.)
--debug                 Enable verbose logging to stderr
--reasoning-off         Suppress model reasoning blocks in output
```

## Usage

### Interactive Commands

Once Tina starts, type commands at the prompt:

```
Frosty > /scope 192.168.0.0/24
Frosty > /wordlist /usr/share/wordlists/rockyou.txt
Frosty > run a version scan on 192.168.0.14
```

### Slash Commands

| Command | Purpose |
|---------|---------|
| `/scope [target]` | View or set the authorised scope |
| `/wordlist [path]` | Set or view the wordlist path |
| `/findings` | Display all discovered vulnerabilities in a table |
| `/report` | Save findings to markdown, JSON, and audit log |
| `/audit` | Show recent command approvals/denials |
| `/clear` | Reset conversation and mode |
| `/fullscan [prompt]` | Run a full autonomous engagement (vs. targeted mode) |
| `/history` | Show message count in context |
| `exit` | Exit Tina |

### Example Session

```
Frosty > /scope 192.168.0.100
  Scope set: 192.168.0.100

Frosty > /wordlist /home/user/wordlists/common.txt
  Wordlist set: /home/user/wordlists/common.txt  (4,614 entries)

Frosty > scan for web services on 192.168.0.100

   1 AUTO nmap
   2 ASK  run_command  Port 80 detected, probing with curl
  
  ╭─ Tina Security - Tier 2 Gate ──────────────────────────────────────╮
  │ Action:  Enumerate HTTP headers and fingerprint web server
  │ Command: curl -sI http://192.168.0.100
  │ Reason:  Initial HTTP header inspection
  ╰────────────────────────────────────────────────────────────────────╯
  Approve? [y/N] y
  
   3 ASK  run_command  WordPress detected, running WPScan
  
  ╭─ Tina Security - Tier 2 Gate ──────────────────────────────────────╮
  │ Action:  WPScan for WordPress vulnerability scan
  │ Command: wpscan --url http://192.168.0.100 -e u,p --disable-tls-checks
  │ Reason:  Deep enumeration of WordPress plugins and users
  ╰────────────────────────────────────────────────────────────────────╯
  Approve? [y/N] y
  
Frosty > /findings
  [CRITICAL] 192.168.0.100:80 | wordpress | Outdated WordPress 5.8 - CVE-2021-39200
  [HIGH] 192.168.0.100:80 | wordpress | Plugin "hello-dolly" v1.6 - RCE via upload filter bypass
  ...
```

## Security Model

### Tier 1 (Auto-Approved)
Commands that are safe, read-only, and non-invasive. These run immediately **without user confirmation**:
- `nmap` (version scanning, port enumeration)
- `curl` (headers only, no file download)
- `dig`, `nslookup`, `host` (DNS enumeration)
- `ping`, `ssh-keyscan` (connectivity checks)
- `whatweb` (web server fingerprinting)
- `enum4linux`, `smbclient -L` (share enumeration, list-only)

### Tier 2 (User Approval Required)
Potentially invasive actions. Tina shows the exact command and your stated reason; you type **y/N** to approve:
- `gobuster`, `nikto`, `ffuf` (directory brute-force)
- `hydra`, `medusa` (credential brute-force)
- `sqlmap` (SQL injection testing)
- `wpscan` (WordPress scanning)
- `nmap -O` (OS fingerprinting — requires sudo)
- **Any unknown binary**

### Scope Enforcement
Every command is checked against your declared scope before execution:
- If you set `/scope 192.168.1.0/24`, only targets in that range pass the check
- Package installs (`apt install`, `pip install`) are scope-exempt (local system)
- Loopback addresses (127.0.0.1, localhost, ::1) always pass

### Blocked Commands
These are **never** allowed:
- Command chaining: `&&`, `||`, `;`, `|`, `` ` ``
- Reverse shells: `bash -i`, `nc -e`, `/bin/sh -i`
- Destructive: `rm -rf /`, `mkfs`, `shutdown`
- Exploitation frameworks: direct msfconsole, msfvenom usage

## Findings & Reports

### Recording Findings

Tina tracks findings automatically and provides tools to record your own:

```python
# In a tool call (handled by the model):
add_finding(
    host="192.168.0.100",
    port="443",
    service="https",
    severity="CRITICAL",
    detail="OpenSSL 1.0.2 — CVE-2014-0160 (Heartbleed)"
)

# Batch findings (more efficient):
add_findings_batch([
    {
        "host": "192.168.0.100",
        "port": "22",
        "service": "ssh",
        "severity": "HIGH",
        "detail": "OpenSSH 7.2 — CVE-2016-6210 (user enumeration via timing)"
    },
    ...
])
```

### Severity Levels

| Level | Meaning |
|-------|---------|
| **CRITICAL** | Unauthenticated RCE, backdoor, empty credentials, exposed .git, EternalBlue |
| **HIGH** | Anonymous FTP with files, SMB null session, SQLi, weak auth |
| **MEDIUM** | Outdated version, weak TLS ciphers, missing security headers |
| **LOW** | Minor info disclosure, config mismatches |
| **INFO** | Open port, service version, OS fingerprint |

### Generating Reports

```
Frosty > /report
  Saved: recon_report.md  (18 findings)  audit: recon_report_audit.json
```

Three files are created:
- **recon_report.md** — Markdown report with findings table
- **recon_report.json** — Structured JSON with scope, wordlist, and all findings
- **recon_report_audit.json** — Audit log of every command run (approved/denied/blocked)

## Modes

### Targeted (default)
Do exactly what the user asked, then stop. Fast, focused, low tool-call overhead.

```
Frosty > run a version scan on 192.168.0.14
   1 AUTO nmap
[returns version info and calls task_done]
```

### Full Scan
Autonomous, exhaustive pipeline. Tina scans all open ports, enumerates services deeply, cross-references CVEs, and follows up on findings until complete.

```
Frosty > /fullscan scan 192.168.0.50
[runs 80 tool calls: full port scan → OS fingerprint → service enum → CVE lookup → web dir enum → report]
```

## Configuration

Edit the top-level constants in `Tina_Security_v1.0.py`:

```python
MODEL               = "qwen3.5"              # Ollama model name
OLLAMA_URL          = "http://localhost:11434/api/chat"
OLLAMA_TIMEOUT      = 600                   # seconds
MAX_STEPS           = 120                   # max tool calls per run
HARD_STOP_AFTER     = 80                    # real ceiling (not soft)
DEFAULT_RECON_TIMEOUT = 180                 # per-command timeout
```

## Known Limitations

- **Model-driven enumeration:** The model guides the scan; it may miss some attack vectors that a human tester would catch
- **Ollama availability:** Tina requires Ollama to be running locally; no API key management for remote models
- **Large outputs:** Commands with huge output (e.g., `nmap -p-` on a wide range) are truncated to 14,000 stdout chars to save context
- **Wordlist paths:** Directory enumeration without a wordlist falls back to nikto or manual curl probes

## Security Considerations

⚠️ **This tool is for authorised testing only.**

- **Always declare scope first** — Tina will refuse out-of-scope commands
- **Approve Tier-2 commands carefully** — You see the exact command before it runs
- **Keep audit logs** — Reports include a full audit trail of all approvals/denials
- **Run on a trusted machine** — Tina can execute arbitrary shell commands with your approval
- **Use in isolated networks when possible** — Brute-force and exploitation tools can trigger alarms

## Troubleshooting

### "Cannot reach Ollama at localhost:11434"
Make sure Ollama is running:
```bash
ollama serve
```

### "Tool not installed"
Tina will offer to install missing tools via `sudo apt install`. Accept if you trust the package.

### "You have executed N tool calls" (stuck loop)
The model repeated the same command 5+ times. This usually means:
- The target isn't responding (try a different tool)
- The wordlist path wasn't set (`/wordlist <path>`)
- The target is out of scope (check `/scope`)

Type a new command or `exit`.

### Context is too large
If you run 50+ tool calls, early messages are summarised and dropped. Save your report (`/report`) to preserve findings.

## Architecture

```
┌─────────────────────────────────┐
│   User Input (CLI)              │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  Slash-command Handler          │
│  (/scope, /wordlist, /findings) │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  TinaSecurityAgent.run()        │
│  (agentic loop)                 │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  call_model() → Ollama          │
│  (qwen3.5)                      │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  extract_tool_call()            │
│  (JSON parse + repair)          │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  Tool Execution Layer           │
│                                 │
│  ┌─────────────────────────────┐│
│  │ run_command()               ││
│  │ ├─ _classify_command()      ││
│  │ ├─ _scope_ok()              ││
│  │ ├─ _prompt_approval_gate()  ││
│  │ └─ _execute() / subprocess  ││
│  └─────────────────────────────┘│
│  ┌─────────────────────────────┐│
│  │ Findings Tracker            ││
│  │ ├─ add_finding()            ││
│  │ ├─ add_findings_batch()     ││
│  │ └─ get_findings()           ││
│  └─────────────────────────────┘│
│  ┌─────────────────────────────┐│
│  │ Report Generation           ││
│  │ ├─ markdown_report()        ││
│  │ └─ save_report()            ││
│  └─────────────────────────────┘│
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  Message History & Context      │
│  (trim_messages if > 80k chars) │
└─────────────────────────────────┘
```

## Contributing

Bug reports and security fixes are welcome. Please test locally before submitting PRs.

## License

Open source. See LICENSE for details.

---

**Made by Harry Ray** — Always open source.

For questions or issues, check the audit logs (`/audit`) and system prompt in the code to understand what Tina is attempting to do.
