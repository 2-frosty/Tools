r"""
___________.___ _______      _____                                             
\__    ___/|   |\      \    /  _  \                                            
  |    |   |   |/   |   \  /  /_\  \                                          
  |    |   |   /    |    \/    |    \                                          
  |____|   |___\____|__  /\____|__  /                                          
                       \/         \/                                           
Tina Security v1.0 - Reconnaissance & Enumeration Assistant
Built on Tina v0.8 (Tina is Not an Agent)

Made by Harry Ray
Always open source

USAGE:
  python3 tina_security.py [--scope 192.168.1.0/24] [--wordlist /path/to/list.txt]
                           [--debug] [--reasoning-off]

FLAGS:
  --scope RANGE       Pre-seed authorised target range (e.g. 192.168.1.0/24)
  --wordlist PATH     Path to wordlist for directory/vhost enumeration
  --debug             Verbose logging to stderr
  --reasoning-off     Hide model reasoning blocks

ARCHITECTURE (v1.0):
  Tier 1 - Auto-approved: nmap, curl (headers only), dig, host, ping, whatweb,
           ssh-keyscan, nslookup. These run immediately - pure read-only recon.
  Tier 2 - Requires approval: everything else. The model proposes the command
           and reason; you type y/N. If approved it runs. You stay in control.
  Package install: apt install is always Tier 2. Validated against a safe list.
  sudo: allowed (needed for OS fingerprinting). Not available to remote targets.
"""

import base64
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import glob as glob_module
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme
from rich.rule import Rule
from rich.table import Table
from rich.padding import Padding
from rich import box

# ──────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────

def _setup_logging(debug: bool = False) -> logging.Logger:
    logger = logging.getLogger("tina_security")
    level = logging.DEBUG if debug else logging.WARNING
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def _parse_flags() -> tuple[bool, bool, Optional[str], Optional[str]]:
    """
    Parse CLI flags. Returns (reasoning_on, debug_on, scope, wordlist).
    """
    args = sys.argv[1:]
    reasoning_on = "--reasoning-off" not in args
    debug_on     = "--debug" in args
    scope: Optional[str] = None
    wordlist: Optional[str] = None

    for flag, dest in (("--scope", "scope"), ("--wordlist", "wordlist")):
        if flag in args:
            idx = args.index(flag)
            if idx + 1 < len(args):
                if dest == "scope":
                    scope = args[idx + 1]
                else:
                    wordlist = args[idx + 1]

    skip = {"--reasoning-off", "--debug", "--scope", "--wordlist",
            scope or "", wordlist or ""}
    sys.argv = [sys.argv[0]] + [a for a in args if a not in skip]
    return reasoning_on, debug_on, scope, wordlist


_REASONING_ON, _DEBUG_ON, _CLI_SCOPE, _CLI_WORDLIST = _parse_flags()
log = _setup_logging(_DEBUG_ON)

# ──────────────────────────────────────────────
# RICH CONSOLE SETUP
# ──────────────────────────────────────────────

THEME = Theme({
    "accent":      "bold #58A6FF",
    "success":     "#3FB950",
    "warn":        "#E3B341",
    "error":       "#F85149",
    "muted":       "#8B949E",
    "tool":        "bold #BC8CFF",
    "thought":     "italic #8B949E",
    "user_label":  "bold #58A6FF",
    "tina_label":  "bold #3FB950",
    "dim_border":  "#30363D",
    "recon":       "bold #FF7B72",
    "finding":     "bold #FFA657",
    "tier1":       "bold #3FB950",
    "tier2":       "bold #E3B341",
    # ── extended palette ──
    "sev_critical": "bold #F85149",
    "sev_high":     "bold #FF7B72",
    "sev_medium":   "bold #E3B341",
    "sev_low":      "#58A6FF",
    "sev_info":     "#8B949E",
    "step_num":     "bold #BC8CFF",
    "elapsed":      "#6E7681",
    "panel_title":  "bold #58A6FF",
    "ok_check":     "bold #3FB950",
})

# severity -> style lookup for tables and findings
_SEV_STYLE = {
    "CRITICAL": "sev_critical",
    "HIGH":     "sev_high",
    "MEDIUM":   "sev_medium",
    "LOW":      "sev_low",
    "INFO":     "sev_info",
}

console = Console(theme=THEME, highlight=False)

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

def _safe_getuser() -> str:
    try:
        import getpass
        name = getpass.getuser()
        return name.capitalize() if name else "you"
    except Exception:
        return "you"


MODEL               = "qwen3.5"
OLLAMA_URL          = "http://localhost:11434/api/chat"
OLLAMA_TIMEOUT      = 600
OLLAMA_RETRIES      = 3
MAX_STEPS           = 120   # enough for a thorough multi-service scan
HARD_STOP_AFTER     = 80    # genuine last resort, not a soft ceiling
HARD_STOP_WARN_AT   = 8
DEFAULT_RECON_TIMEOUT = 180

# ── Scan mode ──────────────────────────────────────────────────────────────
# TARGETED  (default): do exactly what the user asked, then stop
# FULL_SCAN: autonomous staged pipeline, exhaust everything
class Mode:
    TARGETED  = "targeted"
    FULL_SCAN = "full_scan"
WORKING_DIR         = os.path.abspath(".")
USER_NAME           = os.environ.get("TINA_USER") or _safe_getuser()
SHOW_REASONING      = _REASONING_ON
THINK               = False
REASONING_MAX_CHARS = 400
CTX_LIMIT           = 80_000    # conservative - summarise before hitting model limit
CHARS_PER_TOKEN     = 3.5
MAX_READ_LINES      = 200

# ──────────────────────────────────────────────
# WORDLIST RESOLUTION
# ──────────────────────────────────────────────
#
# Priority: --wordlist CLI flag > common installed paths > None (fallback to nikto/curl)

_WORDLIST_FALLBACK_PATHS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/big.txt",
]

def _resolve_wordlist() -> Optional[str]:
    """Return the first available wordlist path, or None."""
    if _CLI_WORDLIST and Path(_CLI_WORDLIST).exists():
        return _CLI_WORDLIST
    for p in _WORDLIST_FALLBACK_PATHS:
        if Path(p).exists():
            return p
    return None

WORDLIST_PATH: Optional[str] = _resolve_wordlist()

# ──────────────────────────────────────────────
# SCOPE ENFORCEMENT
# ──────────────────────────────────────────────

_AUTHORISED_SCOPE: list[str] = []


def set_scope(targets: list[str]) -> None:
    global _AUTHORISED_SCOPE
    _AUTHORISED_SCOPE = [t.strip() for t in targets if t.strip()]
    log.debug("Scope set: %s", _AUTHORISED_SCOPE)


def _scope_ok(command: str) -> bool:
    """
    Return True if the command references an authorised target.
    Package installs (apt/pip) are scope-exempt - they run locally.
    """
    cmd_lower = command.lower()
    tokens = cmd_lower.split()
    binary = tokens[0] if tokens else ""

    # Package management is local - scope doesn't apply
    if binary in ("apt", "apt-get", "pip", "pip3", "snap"):
        return True

    if not _AUTHORISED_SCOPE:
        return False

    for token in _AUTHORISED_SCOPE:
        # Word-boundary match: "10.0.0.1" must not match "10.0.0.10"
        pattern = r'(?<![0-9A-Za-z._-])' + re.escape(token.lower()) + r'(?![0-9A-Za-z._-])'
        if re.search(pattern, cmd_lower):
            return True

    # Allow loopback
    if any(lo in cmd_lower for lo in ("127.0.0.1", "localhost", "::1")):
        return True

    return False

# ──────────────────────────────────────────────
# TIER 1 / TIER 2 CLASSIFICATION
# ──────────────────────────────────────────────
#
# Tier 1: Auto-approved. Non-invasive, read-only, no brute-force, no login
#         attempts. Runs immediately without asking the user.
#
# Tier 2: Everything else. Model proposes the command + reason; user types y/N.
#
# The model uses run_command() for both tiers. Classification happens here in
# Python, not in the prompt, so the model cannot override it.

# Tier 1 binary patterns - command must START with one of these
_TIER1_PATTERNS: list[re.Pattern] = [
    re.compile(r"^(sudo\s+)?nmap\s+"),         # nmap (with or without sudo)
    re.compile(r"^curl\s+"),                    # curl (download guards apply)
    re.compile(r"^dig\s+"),
    re.compile(r"^nslookup\s+"),
    re.compile(r"^host\s+"),
    re.compile(r"^ping\s+"),
    re.compile(r"^ssh-keyscan\s+"),
    re.compile(r"^whatweb\s+"),
    re.compile(r"^enum4linux"),                 # SMB enum - read only
    re.compile(r"^smbclient\s+.*-L\s+"),        # share LIST only
    # python3 -c is Tier 2: arbitrary code execution must be user-approved
]

# Flags that always force Tier 2 regardless of binary, because they indicate
# active attacks, file download/upload, or system modification
_FORCE_TIER2_FLAGS: list[str] = [
    # Exploitation
    "--os-shell", "--os-pwn", "--sql-shell", "--dump", "--dump-all",
    "--file-write", "--file-read",
    "--script=exploit", "--script exploit",
    # File download/upload (enumeration stays listing-only)
    "--output", "--remote-name", "--upload-file", "--output-document",
    # Reverse shells / dangerous patterns
    "bash -i", "nc -e", "ncat -e", "/bin/sh -i",
    # Metasploit
    "msfconsole", "msfvenom",
    # Destructive
    "rm -rf /", "mkfs", "shutdown", "reboot",
]

# Curl/wget/ftp file-output tokens (whole-token match, only for those binaries)
_DOWNLOADER_BINARIES  = {"curl", "wget", "ftp"}
_DOWNLOADER_BLOCKED_TOKENS = {"-o", "-O", "-T"}

# Whitelisted apt packages - model can only request these
_SAFE_APT_PACKAGES: set[str] = {
    "nmap", "curl", "wget", "nikto", "gobuster", "ffuf", "feroxbuster",
    "sqlmap", "enum4linux", "enum4linux-ng", "smbclient", "smbmap",
    "whatweb", "dirb", "dirbuster", "hydra", "medusa",
    "hashcat", "john", "johntheripper",
    "masscan", "rustscan",
    "nuclei", "testssl.sh", "sslscan",
    "dnsrecon", "dnsx", "subfinder", "amass",
    "wfuzz", "arjun",
    "netcat-openbsd", "netcat-traditional", "ncat",
    "git", "python3-pip", "python3", "python3-requests",
    "seclists", "wordlists",
    "metasploit-framework",
    "impacket-scripts", "python3-impacket",
    "crackmapexec", "evil-winrm",
    "ssh-audit",
    "onesixtyone", "snmpwalk", "snmp",
    "rpcbind", "rpcclient",
}


def _classify_command(command: str) -> tuple[str, str]:
    """
    Classify a command as 'tier1' (auto-approve) or 'tier2' (needs approval).
    Returns (tier, reason).
    """
    cmd = command.strip()
    tokens = cmd.split()
    binary = tokens[0] if tokens else ""

    # Strip sudo prefix for classification (sudo itself is fine - it's local)
    effective_binary = binary
    if binary == "sudo" and len(tokens) > 1:
        effective_binary = tokens[1]

    # Package installs are always Tier 2 - user sees exact command and approves
    if effective_binary in ("apt", "apt-get", "pip", "pip3", "snap", "cargo", "gem"):
        return "tier2", "Package installation - review the package name before approving"

    # Check force-tier2 flags
    for flag in _FORCE_TIER2_FLAGS:
        if flag in cmd:
            return "tier2", f"Flag '{flag}' requires approval"

    # Check downloader file-output tokens
    if effective_binary in _DOWNLOADER_BINARIES:
        for idx_tok, tok in enumerate(tokens[1:], 1):
            if tok in _DOWNLOADER_BLOCKED_TOKENS:
                # -o /dev/null is a discard, not a download - allow it
                next_tok = tokens[idx_tok + 1] if idx_tok + 1 < len(tokens) else ""
                if next_tok == "/dev/null":
                    continue
                return "tier2", f"Flag '{tok}' would write a file - requires approval"

    # nmap -O (OS fingerprint) is Tier 2 - needs root, more invasive
    if re.match(r"^(sudo\s+)?nmap\s+", cmd):
        toks = cmd.split()
        if "-O" in toks or "--osscan-guess" in toks:
            return "tier2", "OS fingerprinting requires local sudo and is more invasive"

    # Check Tier 1 patterns
    for pattern in _TIER1_PATTERNS:
        if pattern.match(cmd):
            return "tier1", "Auto-approved read-only enumeration"

    # For unknown binaries: still Tier 2 but with informative reason
    # The model is free to try ANY tool - the user just gets to approve it first
    return "tier2", f"Tool '{effective_binary}' requires approval before running"

# ──────────────────────────────────────────────
# FINDINGS TRACKER
# ──────────────────────────────────────────────

class FindingsTracker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._findings: list[dict] = []

    def add(self, host: str, port: Optional[str], service: str,
            severity: str, detail: str) -> None:
        with self._lock:
            self._findings.append({
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "host":      host,
                "port":      port or "-",
                "service":   service,
                "severity":  severity.upper(),
                "detail":    detail,
            })

    def all(self) -> list[dict]:
        with self._lock:
            return list(self._findings)

    def summary(self) -> dict:
        findings = self.all()
        by_sev: dict[str, int] = {}
        hosts: set[str] = set()
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
            hosts.add(f["host"])
        return {
            "total_findings":       len(findings),
            "hosts_with_findings":  list(hosts),
            "by_severity":          by_sev,
        }

    def markdown_report(self) -> str:
        findings = self.all()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            "# Tina Security - Recon Report",
            f"Generated: {now}",
            f"Authorised scope: {', '.join(_AUTHORISED_SCOPE) or 'not set'}",
            f"Wordlist: {WORDLIST_PATH or 'none (used nikto/curl fallback)'}",
            "",
            "## Summary",
            f"- Total findings: {len(findings)}",
        ]
        for sev, count in sorted(self.summary()["by_severity"].items()):
            lines.append(f"- {sev}: {count}")
        lines += ["", "## Findings", ""]
        if not findings:
            lines.append("_No findings recorded yet._")
        else:
            lines.append("| # | Host | Port | Service | Severity | Detail |")
            lines.append("|---|------|------|---------|----------|--------|")
            for i, f in enumerate(findings, 1):
                detail = f["detail"].replace("|", "\\|").replace("\n", " ")
                lines.append(
                    f"| {i} | {f['host']} | {f['port']} | {f['service']} "
                    f"| {f['severity']} | {detail} |"
                )
        return "\n".join(lines)


_FINDINGS = FindingsTracker()

# ──────────────────────────────────────────────
# SAFE FILESYSTEM LAYER
# ──────────────────────────────────────────────

def _safe(path: str) -> str:
    target = Path(WORKING_DIR).joinpath(path)
    try:
        resolved = target.resolve(strict=False)
    except OSError:
        resolved = Path(os.path.abspath(target))
    wd = str(Path(WORKING_DIR).resolve())
    if str(resolved) != wd and not str(resolved).startswith(wd + os.sep):
        raise PermissionError(f"Path '{path}' escapes working directory.")
    return str(resolved)

# ──────────────────────────────────────────────
# AUDIT LOG
# ──────────────────────────────────────────────
#
# Every command execution is logged here - approved, auto-run, or denied.

_AUDIT_LOG: list[dict] = []
_COMMAND_HISTORY: list[str] = []  # Track commands run this session to prevent duplicates

def _audit(tier: str, command: str, approved: Optional[bool], result_summary: str) -> None:
    _AUDIT_LOG.append({
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "tier":      tier,
        "command":   command,
        "approved":  approved,
        "result":    result_summary[:200],
    })


def get_audit_log() -> dict:
    """Return the full session audit log."""
    return {"entries": _AUDIT_LOG, "count": len(_AUDIT_LOG)}

# ──────────────────────────────────────────────
# CORE EXECUTION ENGINE
# ──────────────────────────────────────────────

def run_command(command: str, timeout: int = DEFAULT_RECON_TIMEOUT,
                reason: str = "") -> dict:
    """
    THE single execution function for all shell commands.

    Tier 1 (auto-approved, non-invasive recon): runs immediately.
    Tier 2 (potentially invasive): returns a sentinel for user approval.
    Blocked: returns an error immediately.

    Always scope-checks against authorised targets before running.
    """
    cmd = command.strip()

    # ── HARD BLOCK: command chaining operators ─────────────────────────
    # These bypass the whitelist and are never allowed, period.
    chaining_ops = ("&&", "||", ";", "|", " | ", " &", "$(", "`", "\n", "\r")
    for op in chaining_ops:
        if op in cmd:
            _audit("blocked", cmd, False, f"Command chaining operator '{op}' detected")
            return {"error": f"BLOCKED - command chaining '{op}' not allowed. "
                            "Run commands separately.", "command": cmd}

    # Classify first
    tier, tier_reason = _classify_command(cmd)

    if tier == "blocked":
        _audit("blocked", cmd, False, tier_reason)
        return {"error": f"BLOCKED - {tier_reason}", "command": cmd}

    # Scope check (package installs are exempt)
    if not _scope_ok(cmd):
        msg = (
            "BLOCKED - command does not reference an authorised target. "
            f"Authorised scope: {_AUTHORISED_SCOPE or 'not set'}. "
            "Call configure_scope first."
        )
        _audit(tier, cmd, False, msg)
        return {"error": msg, "command": cmd}

    if tier == "tier2":
        # Return sentinel - the agent loop handles the prompt outside Rich Live
        return {
            "__approval_required__": True,
            "tier":    "tier2",
            "action":  reason or cmd[:80],
            "command": cmd,
            "reason":  reason or tier_reason,
            "timeout": timeout,
        }

    # Tier 1: run immediately
    return _execute(cmd, timeout, tier="tier1")


def _check_tool_installed(binary: str) -> bool:
    """Check if a binary is available on the system PATH."""
    return shutil.which(binary) is not None


# Tools whose apt package name differs from the binary name.
# Keeps auto-install from failing on a name mismatch.
_APT_PACKAGE_ALIASES = {
    "testssl.sh":    "testssl.sh",
    "ffuf":          "ffuf",
    "feroxbuster":   "feroxbuster",
    "enum4linux-ng": "enum4linux-ng",
    "crackmapexec":  "crackmapexec",
    "evil-winrm":    "evil-winrm",
    "wpscan":        "wpscan",
    "joomscan":      "joomscan",
    "onesixtyone":   "onesixtyone",
    "smbmap":        "smbmap",
    "nuclei":        "nuclei",
    "gobuster":      "gobuster",
    "nikto":         "nikto",
    "sslscan":       "sslscan",
    "snmpwalk":      "snmp",
    "dig":           "dnsutils",
    "host":          "dnsutils",
    "nslookup":      "dnsutils",
}


def _offer_install(binary: str) -> dict:
    """
    Tool not found. Offer to install it via apt.
    Returns the result of installation or a denial dict.
    """
    # Some tools have a package name that differs from the binary name.
    pkg = _APT_PACKAGE_ALIASES.get(binary, binary)

    # Reject packages not on the approved list before showing any prompt.
    if pkg not in _SAFE_APT_PACKAGES:
        _audit("install", f"apt install {pkg}", False,
               f"Package '{pkg}' not in approved list")
        return {"installed": False, "binary": binary,
                "message": f"Package '{pkg}' is not in the approved install list. "
                           "Use an alternative tool or approach. Do NOT retry the install."}

    console.print()
    body = Text.assemble(
        ("Tool not installed\n\n", "warn"),
        ("Binary:   ", "muted"), (binary + "\n", "recon"),
        ("Package:  ", "muted"), (pkg + "\n", "recon"),
        ("Command:  ", "muted"), (f"sudo apt install -y {pkg}\n", "accent"),
        ("Note:     ", "muted"),
        ("Installs locally on this machine. You stay in control.", "muted"),
    )
    console.print(Panel(
        body,
        title="[tier2]Auto-Install[/tier2]",
        border_style="warn",
        padding=(0, 1),
        box=box.ROUNDED,
    ))
    console.print(Text(f"  Install {pkg}? [y/N] ", style="warn"), end="")
    try:
        answer = input().strip().lower()
    except EOFError:
        answer = "n"
    console.print()

    if answer not in ("y", "yes"):
        _audit("install", f"apt install {pkg}", False, "User declined install")
        return {"installed": False, "binary": binary,
                "message": f"User declined to install {binary}. "
                           "Do NOT retry the install. Use an alternative tool or approach."}

    # Run the install with visible output (apt can take a while).
    # Use a list (not shell=True) to avoid shell-injection via pkg.
    console.print(Text(f"  Installing {pkg} ...", style="muted"))
    try:
        result = subprocess.run(
            ["sudo", "apt", "install", "-y", pkg],
            text=True, timeout=180,
        )
        if result.returncode == 0 and _check_tool_installed(binary):
            _audit("install", f"apt install {pkg}", True, "Installed OK")
            console.print(Text(f"  ✓ {binary} installed.\n", style="ok_check"))
            return {"installed": True, "binary": binary,
                    "message": f"{binary} installed successfully. Retry your command now."}
        else:
            _audit("install", f"apt install {pkg}", True,
                   f"Install rc={result.returncode}, present={_check_tool_installed(binary)}")
            console.print(Text(f"  ✗ Could not install {binary}.\n", style="error"))
            return {"installed": False, "binary": binary,
                    "message": f"Failed to install {binary}. Use a different tool or approach. "
                               "Do NOT retry the install."}
    except subprocess.TimeoutExpired:
        console.print(Text(f"  ✗ Install of {pkg} timed out.\n", style="error"))
        return {"installed": False, "binary": binary,
                "message": f"Install of {binary} timed out. Use a different approach."}


def _execute(command: str, timeout: int, tier: str = "tier1") -> dict:
    """Run the command and return the result."""
    # Check if the binary is installed - offer to install if not
    tokens = command.strip().split()
    effective_binary = tokens[0]
    if effective_binary == "sudo" and len(tokens) > 1:
        effective_binary = tokens[1]

    if effective_binary not in ("nmap", "curl", "wget", "dig", "host",
                                 "ping", "whatweb", "python3", "bash", "sh",
                                 "apt", "apt-get") and not _check_tool_installed(effective_binary):
        console.print(Text(f"\n  [{effective_binary}] not found on this system.", style="warn"))
        return _offer_install(effective_binary)

    try:
        result = subprocess.run(
            command,
            shell=True,
            cwd=WORKING_DIR,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = {
            "command":    command,
            "returncode": result.returncode,
            "stdout":     result.stdout[:14000],   # more output
            "stderr":     result.stderr[:4000],
        }
        _audit(tier, command, True,
               f"rc={result.returncode} stdout={len(result.stdout)}b")
        return out
    except subprocess.TimeoutExpired:
        msg = (
            f"TIMEOUT after {timeout}s. This service or endpoint is slow/unresponsive. "
            "DO NOT retry this command. DO NOT increase the timeout. "
            "Move on to the next enumeration step. If this service is critical, return to it later "
            "with a different tool or technique."
        )
        _audit(tier, command, True, f"TIMEOUT after {timeout}s")
        return {"error": msg, "command": command, "timed_out": True}
    except Exception as e:
        _audit(tier, command, True, f"ERROR: {e}")
        return {"error": str(e), "command": command}

# ──────────────────────────────────────────────
# APPROVAL PROMPT
# ──────────────────────────────────────────────

def _prompt_approval_gate(sentinel: dict) -> dict:
    """
    Display an approval panel and read user y/N.
    Called by the agent loop OUTSIDE any Rich Live context.
    On approval, executes the command and returns the result.
    On denial, returns a denial dict so the model can adapt.
    """
    action  = sentinel["action"]
    command = sentinel["command"]
    reason  = sentinel["reason"]
    timeout = sentinel.get("timeout", DEFAULT_RECON_TIMEOUT)
    tier    = sentinel.get("tier", "tier2")

    console.print()
    console.print(Panel(
        Text.assemble(
            ("APPROVAL REQUIRED\n\n", "tier2"),
            ("Action:  ", "muted"), (action + "\n", "recon"),
            ("Command: ", "muted"), (command + "\n", "accent"),
            ("Reason:  ", "muted"), (reason, "muted"),
        ),
        title="[tier2]Tina Security - Tier 2 Gate[/tier2]",
        border_style="warn",
        padding=(0, 1),
        box=box.ROUNDED,
    ))
    console.print(Text("  Approve? [y/N] ", style="warn"), end="")
    try:
        answer = input().strip().lower()
    except EOFError:
        answer = "n"

    approved = answer in ("y", "yes")
    console.print()

    if not approved:
        _audit(tier, command, False, "User denied")
        return {
            "approved": False,
            "command":  command,
            "message":  "User denied this action. Do NOT attempt it again. Suggest an alternative or move to the next enumeration step.",
        }

    # User approved - execute now
    console.print(Text(f"  Running: {command[:80]}", style="muted"))
    return _execute(command, timeout, tier=tier)

# ──────────────────────────────────────────────
# TOOL FUNCTIONS
# ──────────────────────────────────────────────

def set_wordlist(path: str) -> dict:
    """
    Set the wordlist path for this session mid-conversation.
    Use this when the user tells you where their wordlist is.
    """
    global WORDLIST_PATH
    p = Path(path)
    if not p.exists():
        return {"error": f"Wordlist not found at: {path}",
                "suggestion": "Check the path and try again."}
    WORDLIST_PATH = str(p.resolve())
    with open(WORDLIST_PATH, errors="replace") as _wl:
        line_count = sum(1 for _ in _wl)
    return {"ok": True, "wordlist_path": WORDLIST_PATH,
            "lines": line_count,
            "message": f"Wordlist set to {WORDLIST_PATH}. Use this path in gobuster/ffuf."}


def configure_scope(targets: list[str]) -> dict:
    """Declare authorised targets for this session. Call this first."""
    set_scope(targets)
    return {
        "ok":               True,
        "authorised_scope": _AUTHORISED_SCOPE,
        "wordlist":         WORDLIST_PATH or "none - will use nikto/curl fallback",
        "message": (
            f"Scope: {_AUTHORISED_SCOPE}. "
            f"Wordlist: {WORDLIST_PATH or 'not found - directory enum will use nikto or curl'}. "
            "All commands will be scope-checked and classified before execution."
        ),
    }


def get_scope() -> dict:
    return {
        "authorised_scope": _AUTHORISED_SCOPE,
        "scope_set":        bool(_AUTHORISED_SCOPE),
        "wordlist":         WORDLIST_PATH,
    }


def get_wordlist() -> dict:
    """Return the active wordlist path and check if it exists."""
    return {
        "wordlist_path": WORDLIST_PATH,
        "exists":        Path(WORDLIST_PATH).exists() if WORDLIST_PATH else False,
        "fallback_paths_checked": _WORDLIST_FALLBACK_PATHS,
        "recommendation": (
            "Use this path in gobuster/ffuf commands. "
            "If None, use nikto for web scanning or curl to probe fixed paths."
        ),
    }


def add_finding(host: str, port: Optional[str], service: str,
                severity: str, detail: str) -> dict:
    """Record a single finding."""
    valid = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    sev = severity.upper()
    if sev not in valid:
        return {"error": f"severity must be one of {valid}"}
    _FINDINGS.add(host, port, service, sev, detail)
    return {"ok": True, "finding_count": len(_FINDINGS.all())}


def add_findings_batch(findings: list[dict]) -> dict:
    """
    Record multiple findings at once. PREFER THIS over add_finding.
    Each item: {host, port, service, severity, detail}
    """
    valid = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    recorded, errors = 0, []
    for f in findings:
        if not isinstance(f, dict):
            errors.append("non-dict item skipped")
            continue
        sev = str(f.get("severity", "INFO")).upper()
        if sev not in valid:
            sev = "INFO"
        _FINDINGS.add(
            str(f.get("host", "?")), f.get("port"),
            str(f.get("service", "?")), sev, str(f.get("detail", "")),
        )
        recorded += 1
    return {"ok": True, "recorded": recorded, "errors": errors,
            "total_findings": len(_FINDINGS.all())}


def get_findings() -> dict:
    return {"summary": _FINDINGS.summary(), "findings": _FINDINGS.all()}


def save_report(path: str = "recon_report.md") -> dict:
    try:
        md_target  = _safe(path)
        base       = Path(md_target)
        json_path  = str(base.parent / (base.stem + ".json"))
        audit_path = str(base.parent / (base.stem + "_audit.json"))
        md = _FINDINGS.markdown_report()
        Path(md_target).parent.mkdir(parents=True, exist_ok=True)
        with open(md_target, "w", encoding="utf-8") as f:
            f.write(md)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "scope":     _AUTHORISED_SCOPE,
                "wordlist":  WORDLIST_PATH,
                "generated": datetime.now().isoformat(),
                "findings":  _FINDINGS.all(),
                "summary":   _FINDINGS.summary(),
            }, f, indent=2)
        with open(audit_path, "w", encoding="utf-8") as f:
            json.dump({"audit_log": _AUDIT_LOG}, f, indent=2)
        return {
            "ok":            True,
            "markdown":      path,
            "json":          os.path.relpath(json_path, WORKING_DIR),
            "audit":         os.path.relpath(audit_path, WORKING_DIR),
            "finding_count": len(_FINDINGS.all()),
        }
    except Exception as e:
        return {"error": str(e)}


def get_info() -> dict:
    return {
        "working_dir":      WORKING_DIR,
        "datetime":         datetime.now().isoformat(timespec="seconds"),
        "python":           sys.version,
        "platform":         os.uname().sysname if hasattr(os, "uname") else os.name,
        "authorised_scope": _AUTHORISED_SCOPE,
        "wordlist":         WORDLIST_PATH,
    }


def task_done(result: str) -> dict:
    """Signal task completion."""
    return {"__done__": True, "result": result}


# ──────────────────────────────────────────────
# KNOWN-FLAW KNOWLEDGE BASE
# ──────────────────────────────────────────────

_KNOWN_FLAWS: dict[str, list[dict]] = {
    "apache 2.4.49": [
        {"cve": "CVE-2021-41773", "severity": "CRITICAL",
         "note": "Path traversal + RCE if mod_cgi enabled"}],
    "apache 2.4.50": [
        {"cve": "CVE-2021-42013", "severity": "CRITICAL",
         "note": "Incomplete fix for CVE-2021-41773"}],
    "openssh 7.2": [
        {"cve": "CVE-2016-6210", "severity": "MEDIUM",
         "note": "User enumeration via timing attack"}],
    "openssh 8.5": [
        {"cve": "CVE-2021-28041", "severity": "MEDIUM",
         "note": "ssh-agent double-free"}],
    "vsftpd 2.3.4": [
        {"cve": "CVE-2011-2523", "severity": "CRITICAL",
         "note": "Backdoor - smiley-face username trigger"}],
    "proftpd 1.3.5": [
        {"cve": "CVE-2015-3306", "severity": "CRITICAL",
         "note": "mod_copy SITE CPFR/CPTO arbitrary file copy"}],
    "samba 3.5.0": [
        {"cve": "CVE-2017-7494", "severity": "CRITICAL",
         "note": "SambaCry / EternalRed - unauthenticated RCE"}],
    "exim 4.87": [
        {"cve": "CVE-2019-10149", "severity": "CRITICAL",
         "note": "Return of the WIZard - remote command execution"}],
    "microsoft-ds": [
        {"cve": "MS17-010", "severity": "CRITICAL",
         "note": "EternalBlue - run smb-vuln-ms17-010 NSE script to confirm"}],
    "php 8.1.0-dev": [
        {"cve": "CVE-2021-49522", "severity": "CRITICAL",
         "note": "Backdoor in dev build - User-Agentt header RCE"}],
    "log4j": [
        {"cve": "CVE-2021-44228", "severity": "CRITICAL",
         "note": "Log4Shell - JNDI injection; check Java web apps"}],
    "shellshock": [
        {"cve": "CVE-2014-6271", "severity": "CRITICAL",
         "note": "Bash env var injection - check CGI endpoints"}],
    "heartbleed": [
        {"cve": "CVE-2014-0160", "severity": "CRITICAL",
         "note": "OpenSSL memory leak - run ssl-heartbleed NSE"}],
}


def lookup_known_flaws(service_version: str) -> dict:
    """
    Look up known CVEs for a service version string.
    Matches loosely - 'Apache httpd 2.4.49' matches 'apache 2.4.49'.
    Always verify CVEs before reporting as confirmed.
    """
    q = service_version.lower()
    matches = []
    for key, flaws in _KNOWN_FLAWS.items():
        if all(tok in q for tok in key.split()):
            for fl in flaws:
                matches.append({**fl, "matched_on": key})
    if matches:
        return {"service_version": service_version, "known_flaws": matches,
                "count": len(matches)}
    return {
        "service_version": service_version,
        "known_flaws":     [],
        "note": (
            "No entry in local KB. Run: nmap -sV --script vuln -p <port> <host> "
            "to check for version-specific vulnerabilities. Flag the version as INFO."
        ),
    }

# ──────────────────────────────────────────────
# TOOL REGISTRY
# ──────────────────────────────────────────────

TOOLS = {
    "run_command":        run_command,
    "set_wordlist":        set_wordlist,
    "configure_scope":    configure_scope,
    "get_scope":          get_scope,
    "get_wordlist":       get_wordlist,
    "add_finding":        add_finding,
    "add_findings_batch": add_findings_batch,
    "lookup_known_flaws": lookup_known_flaws,
    "get_findings":       get_findings,
    "get_audit_log":      get_audit_log,
    "save_report":        save_report,
    "get_info":           get_info,
    "task_done":          task_done,
    # Lightweight file tools
    "read_file":          lambda path, start_line=1, end_line=None: _read_file(path, start_line, end_line),
    "write_file":         lambda path, content: _write_file(path, content),
    "list_dir":           lambda path=".": _list_dir(path),
}

TOOL_SCHEMAS = {
    "set_wordlist": {
        "path": "string - full path to wordlist file. Call this as soon as the user mentions a wordlist path.",
    },
    "run_command": {
        "command": (
            "string - ANY shell command you want to run. Tier 1 (nmap, curl headers, dig, "
            "host, ping, whatweb, ssh-keyscan, enum4linux, smbclient -L) runs automatically. "
            "Everything else (hydra, gobuster, hashcat, sqlmap, apt install, etc.) pauses for "
            "user approval with your reason shown. sudo is allowed."
        ),
        "timeout": "int (optional, default 180s)",
        "reason":  "string (optional) - shown to user when approval is needed. Be specific.",
    },
    "configure_scope": {
        "targets": "list[string] - authorised IPs, CIDRs, or hostnames",
    },
    "get_scope":    {},
    "get_wordlist": {},
    "add_finding": {
        "host":     "string",
        "port":     "string or null",
        "service":  "string",
        "severity": "INFO | LOW | MEDIUM | HIGH | CRITICAL",
        "detail":   "string",
    },
    "add_findings_batch": {
        "findings": "list of {host, port, service, severity, detail} - use this, not add_finding",
    },
    "lookup_known_flaws": {
        "service_version": "string e.g. 'Apache httpd 2.4.49'",
    },
    "get_findings":   {},
    "get_audit_log":  {},
    "save_report": {
        "path": "string (optional, default 'recon_report.md')",
    },
    "get_info":    {},
    "task_done":   {"result": "string - final summary shown to user"},
    "read_file":   {"path": "string", "start_line": "int (opt)", "end_line": "int (opt)"},
    "write_file":  {"path": "string", "content": "string"},
    "list_dir":    {"path": "string (opt, default '.')"},
}


def _read_file(path: str, start_line: int = 1, end_line=None) -> dict:
    try:
        target = _safe(path)
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        total = len(lines)
        s = max(0, start_line - 1)
        e = min(end_line, s + MAX_READ_LINES) if end_line else s + MAX_READ_LINES
        chunk = lines[s:e]
        result = {"path": path, "total_lines": total,
                  "shown_lines": f"{s+1}-{min(e, total)}", "content": "".join(chunk)}
        if e < total:
            result["note"] = f"File has {total} lines. Use start_line={e+1} to continue."
        return result
    except Exception as ex:
        return {"error": str(ex), "path": path}


def _write_file(path: str, content: str) -> dict:
    try:
        target = _safe(path)
        if not content:
            return {"error": "empty content"}
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)
        return {"path": path, "bytes_written": len(content.encode()),
                "lines": content.count("\n") + 1, "ok": True}
    except Exception as ex:
        return {"error": str(ex), "path": path}


def _list_dir(path: str = ".") -> dict:
    try:
        target = _safe(path)
        entries = [
            {"name": item.name, "type": "dir" if item.is_dir() else "file",
             "size": item.stat().st_size if item.is_file() else None}
            for item in sorted(Path(target).iterdir())
        ]
        return {"path": path, "entries": entries, "count": len(entries)}
    except Exception as ex:
        return {"error": str(ex), "path": path}

# ──────────────────────────────────────────────
# SYSTEM PROMPT
# ──────────────────────────────────────────────

_SYSTEM_PROMPT_CACHE:      dict[str, str] = {}   # mode -> prompt
_SYSTEM_PROMPT_SCHEMA_KEY: Optional[str]  = None


def build_system_prompt(mode: str = Mode.TARGETED) -> str:
    """
    Returns the system prompt for the given mode.
    TARGETED  — do exactly what the user asked, then call task_done.
    FULL_SCAN — autonomous staged pipeline, exhaust every service.
    """
    global _SYSTEM_PROMPT_SCHEMA_KEY

    schema_key = json.dumps(TOOL_SCHEMAS, sort_keys=True) + "|wp=" + str(WORDLIST_PATH)
    if _SYSTEM_PROMPT_SCHEMA_KEY == schema_key and mode in _SYSTEM_PROMPT_CACHE:
        return _SYSTEM_PROMPT_CACHE[mode]

    schemas_str = json.dumps(TOOL_SCHEMAS, indent=2)
    wordlist_info = (
        f"WORDLIST AVAILABLE: {WORDLIST_PATH}"
        if WORDLIST_PATH else
        "NO WORDLIST FOUND - use nikto for web scanning or probe fixed paths with curl"
    )
    wp = WORDLIST_PATH or "WORDLIST_PATH"

    # ── Shared sections ───────────────────────────────────────────────────
    SHARED_HEADER = f"""You are Tina Security — an expert penetration testing assistant for authorised engagements. You run on {MODEL} via Ollama.

## RESPONSE FORMAT
Every response must be a single raw JSON object — no prose, no markdown fences, no text outside:
{{"action": "<tool_name>", "input": {{...}}, "thought": "<one concise line>"}}

When finished:
{{"action": "task_done", "input": {{"result": "<your answer or summary>"}}, "thought": "done"}}

## TOOL EXECUTION
You have full freedom to use ANY tool. Call run_command() with any binary.

TIER 1 (runs immediately):
  nmap, curl, dig, host, ping, whatweb, ssh-keyscan, nslookup, enum4linux, smbclient -L

TIER 2 (user sees the command + your reason, types y/N):
  gobuster, nikto, sqlmap, hydra, hashcat, masscan, nuclei, wpscan, testssl.sh, ffuf,
  feroxbuster, impacket, crackmapexec, evil-winrm, ANY unlisted tool

If a tool is not installed, the system will offer to install it automatically.
NEVER chain commands with &&, ||, ;, |. Run them separately.
sudo IS ALLOWED locally.

## WORDLIST STATUS
{wordlist_info}

## TIMEOUT HANDLING
If a command times out, the error says "DO NOT retry". Obey this absolutely.
A timeout means the service is slow or filtered. Note it and move on immediately.
DO NOT retry with a longer timeout or --insecure.

## FINDINGS QUALITY — BE SPECIFIC
Every finding needs: exact version, CVE if applicable, what it means to an attacker.
BAD:  "SSH service detected"
GOOD: "OpenSSH 7.2p2 Ubuntu — CVE-2016-6210 (user enumeration via timing, MEDIUM)"

## SEVERITY GUIDE
CRITICAL: Unauthenticated RCE, backdoor, empty DB password, exposed .git, EternalBlue
HIGH:     Anonymous FTP with files, SMB null session, SQLi, login with default creds
MEDIUM:   Outdated version, weak TLS ciphers, missing headers, directory listing
LOW:      Minor info disclosure, low-risk misconfigs
INFO:     Open port, service version, OS fingerprint, tech stack

## AVAILABLE TOOLS
{schemas_str}

## RULES (always apply)
- Target only the configured scope
- NEVER chain commands with &&, ||, ;, |
- NEVER retry a timed-out command
- NEVER write vague findings — include specific versions, CVEs, and impact
- ALWAYS call set_wordlist first if the user provides a path
- ALWAYS save_report before task_done in full scan mode
"""

    # ── TARGETED mode prompt ──────────────────────────────────────────────
    TARGETED_PROMPT = SHARED_HEADER + f"""
## YOUR MODE: TARGETED

The user has given you a specific, focused task. Your job is to:
  1. Do exactly what was asked — nothing more, nothing less
  2. Call task_done as soon as the task is complete

DO NOT run a full staged scan. DO NOT enumerate services that weren't asked about.
DO NOT follow up on unrelated findings. DO NOT save a report unless asked.

INTENT EXAMPLES:
  "run a version scan on 192.168.0.14"
  → nmap -sV 192.168.0.14, then task_done with the result

  "check if port 22 is open"
  → nmap -p 22 192.168.0.14, then task_done

  "run a version scan and map it to CVEs"
  → nmap -sV 192.168.0.14, then lookup_known_flaws on each version, then task_done

  "check the SSL certificate on 192.168.0.14"
  → nmap --script ssl-cert 192.168.0.14, then task_done

  "enumerate SMB shares"
  → nmap smb scripts + enum4linux, then task_done

  "check what version of Minecraft is running"
  → nmap -p 25565 --script minecraft-info <host>, then task_done
  DO NOT use nc — Minecraft uses a binary protocol, nc will always timeout

  "run gobuster on 192.168.0.14"
  → run gobuster, then task_done (no follow-up unless explicitly asked)

After completing the specific task, call task_done with a clear, concise answer.
Your result should directly answer what was asked — no padding, no full report template.

You have {HARD_STOP_AFTER} tool calls. A targeted task should need 1-5.
"""

    # ── FULL_SCAN mode prompt ─────────────────────────────────────────────
    FULL_SCAN_PROMPT = SHARED_HEADER + f"""
## YOUR MODE: FULL AUTONOMOUS SCAN

You are running a full, thorough, authorised reconnaissance engagement.
You do not stop until every service has been exhaustively enumerated.

## CORE PHILOSOPHY
You are autonomous. You do not suggest things — you DO them.
When you find something, you immediately follow up on it. Keep going until:
  - Every open port has been fully enumerated
  - Every detected version has been cross-referenced against CVEs
  - Every web path that returned non-404 has been investigated
  - Every piece of information has been used to drive the next step
  - You have genuinely nothing left to enumerate

## STAGED SCANNING PIPELINE

Stage 1 — SETUP (1 tool call):
  - If user mentioned a wordlist: set_wordlist(path)
  - configure_scope if not set

Stage 2 — PORT DISCOVERY (1-2 tool calls):
  Full TCP: nmap -sV --open -T4 --min-rate 2000 -p- <host> (timeout=300)
  UDP:      nmap -sU --open -T4 --top-ports 100 <host>

Stage 3 — OS FINGERPRINT (Tier 2):
  sudo nmap -O --osscan-guess <host>

Stage 4 — DEEP SERVICE ENUMERATION (see PLAYBOOK)

Stage 5 — CVE CORRELATION:
  lookup_known_flaws on every version string found
  nmap --script vuln -p <port> <host> to attempt confirmation

Stage 6 — REPORT:
  save_report() then task_done with the full detailed report

## DIRECTORY ENUMERATION
If wordlist available:
  gobuster dir -u <url> -w {wp} -t 50 -q --no-error -x php,html,txt,bak,js,json,xml,zip,conf,config,env,log
If no wordlist — batch ALL paths in ONE curl command:
  curl -sk -o /dev/null -w "%{{http_code}} %{{url_effective}}\n" <url>/admin <url>/login <url>/api <url>/.git <url>/backup <url>/phpmyadmin <url>/wp-admin <url>/config <url>/uploads <url>/robots.txt <url>/sitemap.xml <url>/.env <url>/server-status <url>/web.config <url>/dashboard <url>/console <url>/cgi-bin <url>/passwd <url>/.htaccess

CRITICAL: ONE command with ALL paths. Do NOT loop. Do NOT probe one path per call.

## SERVICE ENUMERATION PLAYBOOK

### HTTP/HTTPS
1. curl -sI <url>
2. whatweb -a 3 <url>
3. nmap --script http-title,http-headers,http-methods,http-auth-finder,http-robots.txt,http-shellshock,http-php-version,http-generator,http-server-header,http-cookie-flags -p <port> <host>
4. nmap --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params -p <port> <host>  (HTTPS)
5. nikto -h <url> -maxtime 90  [Tier 2]
6. gobuster or batched curl probe
7. Follow up every 200/301 result with curl to read content
8. If login page: nmap --script http-default-accounts -p <port> <host>
9. If .git 200: CRITICAL finding
10. If param URL: sqlmap detection [Tier 2]
11. If WordPress: wpscan [Tier 2]

### FTP (21)
1. nmap -sV -p 21 --script ftp-anon,ftp-syst,ftp-bounce,ftp-vsftpd-backdoor <host>
2. If anon: curl -s "ftp://<host>/" --user "anonymous:anonymous"
3. Recurse into each found directory
4. lookup_known_flaws on version

### SSH (22)
1. nmap -p 22 --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey <host>
2. ssh-keyscan -t rsa,ecdsa,ed25519 <host>
3. lookup_known_flaws on version

### SMB (139, 445)
1. nmap -p 139,445 --script smb-os-discovery,smb-security-mode,smb-protocols,smb-vuln-ms17-010,smb-vuln-ms08-067,smb-enum-shares,smb-enum-users,smb-system-info,smb2-security-mode <host>
2. enum4linux-ng -A <host>
3. smbclient -N -L //<host>/
4. If null session shares: smbclient -N //<host>/<share>

### DNS (53)
1. nmap -sU -sV -p 53 --script dns-zone-transfer,dns-recursion,dns-cache-snoop,dns-brute <host>
2. dig axfr @<host> <domain>

### Databases
MySQL 3306:    nmap --script mysql-info,mysql-empty-password,mysql-databases,mysql-users -p 3306 <host>
MSSQL 1433:    nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-config -p 1433 <host>
MongoDB 27017: nmap --script mongodb-info,mongodb-databases -p 27017 <host>
Redis 6379:    nmap --script redis-info -p 6379 <host>
Elasticsearch: curl -s http://<host>:9200/

### SMTP (25, 465, 587)
1. nmap -p 25,465,587 --script smtp-commands,smtp-open-relay,smtp-enum-users <host>

### SNMP (161 UDP)
1. nmap -sU -p 161 --script snmp-info,snmp-sysdescr,snmp-processes,snmp-interfaces <host>
2. onesixtyone [Tier 2]

### RDP (3389)
1. nmap -p 3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 <host>

### VNC (5900)
1. nmap -p 5900-5910 --script vnc-info,vnc-brute --script-args brute.firstonly=true <host>

### Minecraft (25565)
1. nmap -p 25565 --script minecraft-info <host>
   - Returns: version string, MOTD, player count, protocol version
2. If nmap script unavailable: python3 -c "import socket,json,struct; ..."  — do NOT use nc (will timeout, Minecraft uses custom binary protocol)
3. lookup_known_flaws on version string found

### LDAP (389, 636)
1. nmap -p 389,636 --script ldap-rootdse,ldap-search <host>

### NFS (2049)
1. nmap -p 2049 --script nfs-ls,nfs-showmount,nfs-statfs <host>

### Tomcat (8080, 8443, 8009)
1. nmap -p 8080,8443,8009 --script ajp-headers,ajp-request,http-title,http-methods <host>
2. Port 8009 open = CVE-2020-1938 Ghostcat [CRITICAL]

## DEEP PARSING — EXTRACT EVERYTHING
From every tool result, extract and record:
- Exact version strings (not just "SSH" — "OpenSSH 7.2p2 Ubuntu 4ubuntu2.10")
- SSL certificate: CN, SANs, issuer, expiry, self-signed flag
- Every NSE script output line
- Every hostname or domain found (add to enumeration)
- Every non-404 web path
- Every share, user, password policy from SMB/enum4linux

## FINAL REPORT FORMAT
Your task_done result must contain:

=== TINA SECURITY REPORT ===
Target: <host> | Scan duration: <approx>

HOSTS:
  <host> — OS: <os+kernel> — <N> open ports

OPEN PORTS & SERVICES:
  <port>/tcp  <service>  <exact version>

FINDINGS (<N> total):
  [CRITICAL] <host>:<port> <service> — <detail with CVE>
  [HIGH] ...

SSL/TLS (if applicable):
  Protocols: ... | Ciphers: ... | Cert: CN=... Expires=...

ATTACK SURFACE:
  <what an attacker targets first and why>

NEXT STEPS (require exploitation, not enumeration):
  1. <exact command> — <what it achieves>

## FULL SCAN RULES
- NEVER call task_done while unexplored services or findings remain
- ALWAYS run UDP scan — SNMP/DNS on UDP are commonly missed
- ALWAYS call lookup_known_flaws on every version string
- ALWAYS save_report before task_done
- NEVER probe web paths one at a time — batch all in ONE curl command
- NEVER retry a timed-out command — move on immediately
- You have {HARD_STOP_AFTER} tool calls. Use them on enumeration, not admin.
"""

    _SYSTEM_PROMPT_CACHE[Mode.TARGETED]  = TARGETED_PROMPT
    _SYSTEM_PROMPT_CACHE[Mode.FULL_SCAN] = FULL_SCAN_PROMPT
    _SYSTEM_PROMPT_SCHEMA_KEY = schema_key
    return _SYSTEM_PROMPT_CACHE[mode]

# ──────────────────────────────────────────────
# CONTEXT TRIMMING
# ──────────────────────────────────────────────

def _estimate_tokens(messages: list) -> int:
    return int(sum(len(m["content"]) for m in messages) / CHARS_PER_TOKEN)


def trim_messages(messages: list) -> list:
    if _estimate_tokens(messages) <= CTX_LIMIT:
        return messages

    system = messages[:1]
    rest   = messages[1:]

    # Build a compact summary of early tool calls rather than just dropping them
    # Keep the last 40 messages verbatim (recent context)
    # Summarise everything older into a single "history so far" message
    KEEP_RECENT = 40

    if len(rest) <= KEEP_RECENT:
        # Just drop oldest pairs if still too long
        while len(rest) > 2 and _estimate_tokens(system + rest) > CTX_LIMIT:
            rest = rest[2:]
        return system + rest

    old_msgs  = rest[:-KEEP_RECENT]
    recent    = rest[-KEEP_RECENT:]

    # Summarise old tool results into a brief "context so far" block
    summary_lines = ["[CONTEXT SUMMARY - earlier steps this session]"]
    for msg in old_msgs:
        content_str = msg.get("content", "")
        if msg["role"] == "user" and content_str.startswith("TOOL_RESULT("):
            # Extract just the command and key result
            summary_lines.append(content_str[:300])
        elif msg["role"] == "assistant":
            # Extract action name from JSON if possible
            try:
                d = json.loads(content_str)
                summary_lines.append(f"[ran: {d.get('action','?')}]")
            except Exception:
                pass

    summary = '\n'.join(summary_lines[:60])  # cap summary length
    summary_msg = {"role": "user", "content": summary}

    trimmed = system + [summary_msg] + recent
    log.debug("Context summarised: %d old msgs -> 1 summary, keeping %d recent",
              len(old_msgs), len(recent))
    return trimmed

# ──────────────────────────────────────────────
# OLLAMA CALL
# ──────────────────────────────────────────────

def call_model(messages: list) -> str:
    payload = {
        "model":   MODEL,
        "messages": messages,
        "stream":  True,
        "options": {
            "temperature":    0.0,
            "top_p":          0.9,
            "top_k":          20,
            "num_ctx":        32768,
            "repeat_penalty": 1.05,
        },
    }
    last_err = None
    for attempt in range(1, OLLAMA_RETRIES + 1):
        try:
            r = requests.post(OLLAMA_URL, json=payload,
                              timeout=OLLAMA_TIMEOUT, stream=True)
            r.raise_for_status()
            content = []
            for line in r.iter_lines():
                if not line:
                    continue
                chunk = json.loads(line)
                if "message" in chunk and "content" in chunk["message"]:
                    content.append(chunk["message"]["content"])
                if chunk.get("done"):
                    break
            return "".join(content)
        except requests.exceptions.ConnectionError:
            raise RuntimeError(
                "Cannot reach Ollama at localhost:11434 - is it running?")
        except requests.exceptions.ReadTimeout:
            last_err = f"timed out after {OLLAMA_TIMEOUT}s"
            wait = 5 * attempt
            console.print(
                f"  [warn]Ollama timeout (attempt {attempt}/{OLLAMA_RETRIES}), "
                f"retrying in {wait}s[/warn]")
            time.sleep(wait)
        except KeyError:
            raise RuntimeError(f"Unexpected Ollama response: {r.text[:300]}")
    raise RuntimeError(f"Ollama failed after {OLLAMA_RETRIES} attempts: {last_err}")

# ──────────────────────────────────────────────
# JSON EXTRACTION
# ──────────────────────────────────────────────

def _strip_think(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _show_reasoning(text: str, step: int) -> None:
    if not SHOW_REASONING or not THINK:
        return
    match = re.search(r"<think>(.*?)</think>", text, re.DOTALL)
    if not match:
        return
    thought = match.group(1).strip()
    if not thought:
        return
    if not log.isEnabledFor(logging.DEBUG) and len(thought) > REASONING_MAX_CHARS:
        thought = thought[:REASONING_MAX_CHARS].rstrip() + "..."
    console.print(Panel(Text(thought, style="thought"),
                        title=f"[muted]reasoning step {step}[/muted]",
                        border_style="dim_border", padding=(0, 1)))


def _find_json_objects(text: str) -> list[str]:
    results = []
    i, n = 0, len(text)
    while i < n:
        if text[i] != "{":
            i += 1
            continue
        depth, j = 0, i
        in_string = escape_next = False
        while j < n:
            ch = text[j]
            if escape_next:
                escape_next = False
            elif ch == "\\" and in_string:
                escape_next = True
            elif ch == '"':
                in_string = not in_string
            elif not in_string:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        results.append(text[i:j+1])
                        break
            j += 1
        # Jump past the matched object; fall back to i+1 if no complete object found
        i = j + 1 if j < n else i + 1
    results.sort(key=len, reverse=True)
    return results


def _repair_json_strings(text: str) -> str:
    out, in_string, escape_next = [], False, False
    for ch in text:
        if escape_next:
            out.append(ch); escape_next = False; continue
        if ch == "\\" and in_string:
            out.append(ch); escape_next = True; continue
        if ch == '"':
            in_string = not in_string; out.append(ch); continue
        if in_string:
            if ch == "\n": out.append("\\n"); continue
            if ch == "\r": out.append("\\r"); continue
            if ch == "\t": out.append("\\t"); continue
        out.append(ch)
    return "".join(out)


def _repair_json_misc(text: str) -> str:
    text = re.sub(r'\bTrue\b',  'true',  text)
    text = re.sub(r'\bFalse\b', 'false', text)
    text = re.sub(r'\bNone\b',  'null',  text)
    text = re.sub(r',\s*([}\]])', r'\1', text)
    return text


def extract_tool_call(text: str) -> tuple[Optional[str], Optional[dict], Optional[str]]:
    cleaned = _strip_think(text)
    candidates = []
    for m in re.finditer(r"```(?:\w+)?\s*([\s\S]*?)\s*```", cleaned):
        candidates.extend(_find_json_objects(m.group(1)))
    candidates.extend(_find_json_objects(cleaned))
    candidates.append(cleaned)

    def _try(raw: str) -> Optional[dict]:
        for t in (lambda s: s,
                  _repair_json_strings,
                  lambda s: _repair_json_misc(_repair_json_strings(s)),
                  _repair_json_misc):
            try:
                d = json.loads(t(raw))
                if isinstance(d, dict) and "action" in d:
                    return d
            except Exception:
                continue
        return None

    seen: set[str] = set()
    for raw in candidates:
        raw = raw.strip()
        if raw in seen:
            continue
        seen.add(raw)
        d = _try(raw)
        if d:
            return d["action"], d.get("input", {}), d.get("thought", "")
    return None, None, None

# ──────────────────────────────────────────────
# FINDINGS DISPLAY HELPERS
# ──────────────────────────────────────────────

def _build_findings_block() -> str:
    findings = _FINDINGS.all()
    if not findings:
        return ""
    lines = ["-" * 60, f"  FINDINGS ({len(findings)} total)", "-" * 60]
    for i, f in enumerate(findings, 1):
        lines.append(
            f"  [{i:02d}] {f['host']}:{f['port']}  "
            f"{f['service']:<10} {f['severity']:<8}  {f['detail']}"
        )
    lines.append("-" * 60)
    return "\n".join(lines)


def _build_fallback_summary() -> str:
    findings = _FINDINGS.all()
    summary  = _FINDINGS.summary()
    lines = [
        "Scan complete (tool call limit reached).",
        f"  Total findings : {summary['total_findings']}",
        f"  Hosts affected : {', '.join(summary['hosts_with_findings']) or 'none'}",
        f"  By severity    : {summary['by_severity']}",
        "",
        _build_findings_block(),
        "",
        "Run /report to save the full markdown report.",
    ]
    return "\n".join(lines)


def _print_findings_table() -> None:
    findings = _FINDINGS.all()
    if not findings:
        console.print(Text("  No findings recorded yet.\n", style="muted"))
        return
    summary = _FINDINGS.summary()

    # Severity count bar
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    by_sev = summary["by_severity"]
    console.print()
    bar = Text("  ")
    for sev in sev_order:
        n = by_sev.get(sev, 0)
        if n:
            bar.append(f" {sev} {n} ", style=_SEV_STYLE[sev])
            bar.append(" ")
    console.print(bar)
    console.print(Text(
        f"  {summary['total_findings']} findings across "
        f"{len(summary['hosts_with_findings'])} host(s)",
        style="muted",
    ))
    console.print()

    # Sort findings by severity (critical first), then host
    rank = {s: i for i, s in enumerate(sev_order)}
    ordered = sorted(
        findings,
        key=lambda f: (rank.get(f["severity"], 99), f["host"], str(f["port"])),
    )

    table = Table(
        show_header=True,
        header_style="muted",
        box=box.SIMPLE_HEAD,
        padding=(0, 1),
        expand=False,
        border_style="dim_border",
    )
    table.add_column("#", style="muted", justify="right", width=3)
    table.add_column("Host:Port", style="accent", no_wrap=True)
    table.add_column("Service", style="recon", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Detail", style="default", overflow="fold")

    for i, f in enumerate(ordered, 1):
        sev = f["severity"]
        table.add_row(
            f"{i:02d}",
            f"{f['host']}:{f['port']}",
            f["service"],
            Text(sev, style=_SEV_STYLE.get(sev, "muted")),
            f["detail"],
        )
    console.print(table)
    console.print()

# ──────────────────────────────────────────────
# CONTEXT COMPRESSION
# ──────────────────────────────────────────────
# Tool results can be enormous (nmap -p- output, gobuster results, nikto).
# Storing the full output in every message burns context fast and causes
# JSON parse failures as the model loses track of the conversation.
# We summarise outputs to keep only the lines that matter.

def _compress_result(action: str, result: dict) -> str:
    """
    Compress a tool result to the key information only.
    Full output is still used for display; this is only what goes into context.
    """
    if not isinstance(result, dict):
        return json.dumps(result)[:2000]

    # Errors and non-command results: pass through as-is (usually small)
    if "error" in result and action != "run_command":
        return json.dumps(result)[:1000]

    if action == "run_command":
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        rc     = result.get("returncode", "?")
        cmd    = result.get("command", "")[:80]

        if result.get("timed_out"):
            return json.dumps({"timed_out": True, "command": cmd})

        if "error" in result:
            return json.dumps({"error": result["error"][:300], "command": cmd})

        # Extract only interesting lines from stdout
        interesting = _extract_interesting_lines(stdout)
        compressed  = {
            "rc":      rc,
            "cmd":     cmd,
            "out":     interesting[:8000],   # still generous but bounded
        }
        if stderr and rc != 0:
            compressed["err"] = stderr[:500]
        return json.dumps(compressed)

    # Findings batch: just confirm count
    if action in ("add_findings_batch", "add_finding"):
        return json.dumps({"ok": result.get("ok"), 
                           "total": result.get("total_findings", result.get("finding_count"))})

    # Everything else: cap at 1500 chars
    raw = json.dumps(result)
    if len(raw) <= 1500:
        return raw
    return raw[:1500] + "...[truncated]"


def _extract_interesting_lines(stdout: str) -> str:
    """
    From a large stdout blob, keep only lines that carry useful information.
    Filters out blank lines, nmap boilerplate, progress indicators, etc.
    """
    if not stdout:
        return ""

    # If output is small enough, return as-is
    if len(stdout) <= 3000:
        return stdout

    lines = stdout.splitlines()
    keep = []
    skip_prefixes = (
        "Starting Nmap", "Nmap scan report", "Host is up",
        "Not shown:", "Nmap done:", "Read data files",
        "# Nmap", "Service detection performed",
        "PORT     STATE", "PORT    STATE", "PORT STATE",
        "---", "===",
    )
    important_keywords = (
        "open", "ssl", "http", "ftp", "ssh", "smb", "443", "80", "22", "21",
        "script", "version", "cve", "vuln", "nikto", "osvdb", "error",
        "admin", "login", "password", "auth", "anonymous", "null",
        "certificate", "cipher", "tls", "heartbleed", "ms17",
        "redirect", "found", "interesting", "warning", "backdoor",
        "php", "wordpress", "apache", "nginx", "iis",
        "/", "200", "301", "302", "403", "500",
    )

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if any(stripped.startswith(p) for p in skip_prefixes):
            # Still keep if it has important content
            if not any(k in stripped.lower() for k in important_keywords):
                continue
        keep.append(line)

    result = '\n'.join(keep)
    # Final cap
    if len(result) > 6000:
        # Keep first 3000 and last 1000 (interesting stuff at start and end)
        result = result[:3000] + "\n...[middle truncated]...\n" + result[-1000:]
    return result


# ──────────────────────────────────────────────
# AGENT CLASS
# ──────────────────────────────────────────────

_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class _thinking_spinner:
    # Phase labels shown while the model is working, cycled slowly so the
    # line reads as meaningful activity rather than a generic "scanning".
    _PHASES = ["thinking", "planning", "analysing", "working"]

    def __init__(self, step: int) -> None:
        self.step = step
        self._live = None
        self._frame = 0
        self._start = 0.0

    def __enter__(self):
        self._frame = 0
        self._start = time.time()
        self._live = Live(self._render(), console=console,
                          refresh_per_second=12, transient=True)
        self._live.__enter__()
        return self

    def _render(self) -> Text:
        frame   = _SPINNER_FRAMES[self._frame % len(_SPINNER_FRAMES)]
        elapsed = time.time() - self._start
        # cycle phase label every ~2.5s so it feels alive but not frantic
        phase = self._PHASES[int(elapsed // 2.5) % len(self._PHASES)]
        t = Text()
        t.append(f"  {frame} ", style="accent")
        t.append(f"{phase}", style="muted")
        t.append(f"  ·  step {self.step}", style="elapsed")
        t.append(f"  {elapsed:.1f}s", style="elapsed")
        self._frame += 1
        return t

    def run(self, fn, *args, **kwargs):
        result_holder: dict = {"value": None, "error": None}
        def _target():
            try:
                result_holder["value"] = fn(*args, **kwargs)
            except Exception as exc:
                result_holder["error"] = exc
        t = threading.Thread(target=_target, daemon=True)
        t.start()
        while t.is_alive():
            self._live.update(self._render())
            time.sleep(0.08)
        t.join()
        if result_holder["error"] is not None:
            raise result_holder["error"]
        return result_holder["value"]

    def __exit__(self, *_):
        # transient Live clears itself; we print nothing here so the only
        # visible per-step line is the tool-call line (printed next), which
        # carries the actual meaning. This removes the redundant "+ step N".
        self._live.__exit__(None, None, None)
        self._elapsed = time.time() - self._start


def _print_tool_call(action: str, tier: str, description: str,
                     step: Optional[int] = None) -> None:
    t = Text()
    if step is not None:
        t.append(f"  {step:>2} ", style="step_num")
    else:
        t.append("  ", style="")
    tier_style = "tier1" if tier == "tier1" else "tier2"
    badge = "AUTO" if tier == "tier1" else "ASK "
    t.append(f"{badge} ", style=tier_style)
    t.append(f"{action}", style="recon")
    desc = (description or "").strip()
    if desc:
        t.append("  ", style="")
        t.append(desc[:110], style="thought")
    console.print(t)


def _print_result(result: str) -> None:
    console.print()
    console.print(Panel(
        Text(result, style="default"),
        title="[tina_label]Tina Security[/tina_label]",
        border_style="success",
        padding=(0, 1),
        box=box.ROUNDED,
    ))
    console.print()


def _print_error(message: str) -> None:
    console.print(Panel(
        Text(message, style="error"),
        title="[error]Error[/error]",
        border_style="error",
        padding=(0, 1),
        box=box.ROUNDED,
    ))


class TinaSecurityAgent:
    def __init__(self) -> None:
        self.history: list[dict] = []
        self._init_conversation()

    def _init_conversation(self) -> None:
        self.history = [{"role": "system", "content": build_system_prompt()}]

    def reset(self) -> None:
        self._init_conversation()

    @property
    def message_count(self) -> int:
        return len(self.history) - 1

    def _add(self, role: str, content: str) -> None:
        self.history.append({"role": role, "content": content})

    def _handle_parse_failure(self, raw, consecutive_failures, messages):
        self.history = messages
        visible_raw = _strip_think(raw)[:300]
        large_hint = ""
        if len(_strip_think(raw)) > 1500:
            large_hint = "\n\nYour response was very long. Respond with ONLY a JSON object."
        if consecutive_failures >= 3:
            messages.append({"role": "assistant", "content": raw})
            messages.append({"role": "user", "content": (
                "STOP. You have failed 3 times. Output ONLY:\n"
                '{"action":"task_done","input":{"result":"<summary>"},"thought":"done"}'
            )})
            raw2 = call_model(messages)
            action, tool_input, thought = extract_tool_call(raw2)
            if action in ("task_done",) or (action and action in TOOLS):
                return action, tool_input, thought, False
            return None, None, None, False
        else:
            messages.append({"role": "assistant", "content": raw})
            messages.append({"role": "user", "content": (
                f"ERROR: Could not parse JSON from your response.\n"
                f"Started with: {visible_raw!r}\n\n"
                "Respond with ONLY a raw JSON object:\n"
                '{"action":"<tool>","input":{...},"thought":"<brief>"}'
                f"{large_hint}"
            )})
            return None, None, None, True

    def _force_completion(self, reason, executed_count, messages, raw):
        findings_snapshot = json.dumps(_FINDINGS.all(), indent=2)[:3000]
        messages.append({"role": "assistant", "content": raw})
        messages.append({"role": "user", "content": (
            f"{reason} Call task_done immediately. Your result MUST include:\n"
            "1. A findings table (host:port | service | severity | detail)\n"
            "2. 2-3 recommended next steps\n"
            f"Current findings:\n{findings_snapshot}\nDo not call any other tool."
        )})
        raw2 = call_model(messages)
        action, tool_input, _ = extract_tool_call(raw2)
        if action == "task_done":
            result_text = tool_input.get("result", "(Task ended)")
            block = _build_findings_block()
            if block:
                result_text = result_text.rstrip() + "\n\n" + block
            return result_text
        return _build_fallback_summary()

    def run(self, user_input: str, mode: str = Mode.TARGETED) -> str:
        # Rebuild the system prompt for the correct mode.
        # Always update messages[0] so a mode switch mid-session takes effect.
        self.history[0] = {"role": "system", "content": build_system_prompt(mode)}
        self._add("user", user_input)
        messages = self.history
        tool_call_history: list[tuple] = []
        run_binary_history: list[str]  = []   # for fuzzy same-binary loop detection
        executed_tool_count    = 0
        consecutive_failures   = 0
        self._current_mode     = mode

        for step in range(1, MAX_STEPS + 1):
            log.debug("Step %d - executed=%d", step, executed_tool_count)
            messages = trim_messages(messages)
            self.history = messages

            # Inject a JSON format reminder every 15 steps to prevent drift
            if step > 1 and step % 15 == 0:
                messages.append({"role": "user", "content":
                    "REMINDER: Respond with ONLY a raw JSON object: "
                    '{"action":"<tool>","input":{...},"thought":"<brief>"}  '
                    "No prose, no markdown, no text outside the JSON."
                })

            with _thinking_spinner(step) as spinner:
                raw = spinner.run(call_model, messages)

            _show_reasoning(raw, step)
            action, tool_input, thought = extract_tool_call(raw)
            log.debug("action=%r", action)

            # ── Parse failure ──────────────────────────────────────────
            if action is None:
                consecutive_failures += 1
                action, tool_input, thought, should_continue = \
                    self._handle_parse_failure(raw, consecutive_failures, messages)
                if should_continue:
                    continue
                if action is None:
                    return "(Task ended: agent could not produce valid tool calls)"

            consecutive_failures = 0

            # ── task_done ──────────────────────────────────────────────
            if action == "task_done":
                result_text = tool_input.get("result", "(no result)")
                block = _build_findings_block()
                if block:
                    result_text = result_text.rstrip() + "\n\n" + block
                return result_text

            # ── Unknown tool ───────────────────────────────────────────
            if action not in TOOLS:
                messages.append({"role": "assistant", "content": raw})
                messages.append({"role": "user", "content":
                    f"Tool '{action}' does not exist. Available: {', '.join(TOOLS)}."})
                continue

            # ── Bad input type ─────────────────────────────────────────
            if not isinstance(tool_input, dict):
                messages.append({"role": "assistant", "content": raw})
                messages.append({"role": "user", "content":
                    f"'input' must be a JSON object, got {type(tool_input).__name__}."})
                continue

            # ── Classify for display (run_command gets special treatment) ──
            tier = "tier1"
            if action == "run_command":
                cmd = tool_input.get("command", "")
                tier, _ = _classify_command(cmd)

            _print_tool_call(action, tier, thought or json.dumps(tool_input)[:120], step=step)

            # ── Duplicate short-circuit (BEFORE execution) ─────────────
            # If the model re-proposes a command it already ran, do NOT run it
            # again and do NOT re-prompt for approval. Return immediately with a
            # firm instruction to move on. This breaks the retry loops that
            # otherwise bloat context and crash JSON generation.
            if action == "run_command":
                cmd = tool_input.get("command", "").strip()
                if cmd in _COMMAND_HISTORY:
                    log.debug("DUPLICATE short-circuit: '%s'", cmd[:60])
                    messages.append({"role": "assistant", "content": raw})
                    messages.append({"role": "user", "content": (
                        "TOOL_RESULT(run_command): "
                        '{"skipped": true, "reason": "You already ran this exact command '
                        'this session. It was NOT run again. Do NOT repeat it. '
                        'Either use the earlier result, try a DIFFERENT command, or '
                        'call task_done if you are finished."}'
                    )})
                    executed_tool_count += 1
                    # count repeated attempts toward the stuck-detector immediately
                    sig = (action, cmd[:80])
                    tool_call_history.append(sig)
                    if tool_call_history.count(sig) >= 3:
                        return self._force_completion(
                            f"You repeated the same command {tool_call_history.count(sig)} "
                            "times without progress.",
                            executed_tool_count, messages, raw)
                    continue
                _COMMAND_HISTORY.append(cmd)

            # ── Execute ────────────────────────────────────────────────
            try:
                result = TOOLS[action](**tool_input)
            except TypeError as e:
                result = {"error": f"Invalid args for '{action}': {e}. "
                          f"Schema: {json.dumps(TOOL_SCHEMAS.get(action, {}))}"}
            except Exception as e:
                result = {"error": str(e)}

            # ── Approval gate (run OUTSIDE spinner so terminal is free) ──
            if isinstance(result, dict) and result.get("__approval_required__"):
                result = _prompt_approval_gate(result)

            log.debug("Result: %s", json.dumps(result, indent=2)[:600])
            executed_tool_count += 1

            # ── Hard stop ──────────────────────────────────────────────
            if executed_tool_count >= HARD_STOP_AFTER:
                return self._force_completion(
                    f"You have executed {executed_tool_count} tool calls.",
                    executed_tool_count, messages, raw)

            # ── Stuck detection ────────────────────────────────────────
            sig = (action, json.dumps(tool_input, sort_keys=True)[:80])
            tool_call_history.append(sig)
            if tool_call_history[-3:].count(sig) >= 3:
                return self._force_completion(
                    f"You have repeated '{action}' 3 times without progress.",
                    executed_tool_count, messages, raw)

            # Fuzzy stuck detection: same binary 5 times in a row = loop
            if action == "run_command":
                cmd_words = tool_input.get("command", "").strip().split()
                cmd_binary = cmd_words[0] if cmd_words else ""
                run_binary_history.append(cmd_binary)
                if (len(run_binary_history) >= 5
                        and len(set(run_binary_history[-5:])) == 1
                        and cmd_binary):
                    return self._force_completion(
                        f"You have tried '{cmd_binary}' 5 times in a row without success. "
                        "Stop retrying. Use the wordlist already configured or call task_done.",
                        executed_tool_count, messages, raw)

            messages.append({"role": "assistant", "content": raw})
            tool_result_content = f"TOOL_RESULT({action}): {_compress_result(action, result)}"
            remaining = HARD_STOP_AFTER - executed_tool_count
            if remaining <= HARD_STOP_WARN_AT:
                tool_result_content += (
                    f"\n\nONLY {remaining} TOOL CALLS REMAINING. "
                    "Save report and call task_done now."
                )
            messages.append({"role": "user", "content": tool_result_content})

        return f"Agent stopped: reached {MAX_STEPS} steps without completing."

# ──────────────────────────────────────────────
# UI
# ──────────────────────────────────────────────

def print_banner(mode: str = Mode.TARGETED) -> None:
    console.print()
    console.print(Rule(style="dim_border"))
    console.print()

    title = Text()
    title.append("TINA SECURITY", style="bold #FF7B72")
    title.append("  v1.0  ·  ", style="muted")
    title.append(MODEL, style="accent")
    console.print(Padding(title, (0, 2)))

    meta = Text()
    meta.append("Tier 1: auto-run  ·  ", style="tier1")
    meta.append("Tier 2: asks permission  ·  ", style="tier2")
    meta.append(
        "/findings  /report  /scope  /wordlist  /audit  /fullscan  /clear  exit",
        style="muted"
    )
    console.print(Padding(meta, (0, 2)))
    console.print()
    console.print(Rule(style="dim_border"))
    console.print()

    # Mode indicator
    if mode == Mode.FULL_SCAN:
        mode_text = Text()
        mode_text.append("  Mode:     ", style="muted")
        mode_text.append("FULL SCAN", style="sev_critical")
        mode_text.append("  — autonomous pipeline, exhausts all services", style="muted")
        console.print(mode_text)
    else:
        mode_text = Text()
        mode_text.append("  Mode:     ", style="muted")
        mode_text.append("Targeted", style="tier1")
        mode_text.append(
            "  — does exactly what you ask, then stops  "
            "(use /fullscan to run a full engagement)",
            style="muted"
        )
        console.print(mode_text)

    if _AUTHORISED_SCOPE:
        console.print(Text(f"  Scope:    {', '.join(_AUTHORISED_SCOPE)}", style="success"))
    if WORDLIST_PATH:
        console.print(Text(f"  Wordlist: {WORDLIST_PATH}", style="success"))
    else:
        console.print(Text("  Wordlist: not found - will use nikto/curl fallback", style="warn"))
    console.print()


def _prompt_user() -> str:
    console.print(Text(f"  {USER_NAME} ", style="user_label"), end="")
    console.print(Text(">  ", style="muted"), end="")
    try:
        return input()
    except EOFError:
        return "exit"


def main() -> None:
    if _CLI_SCOPE:
        set_scope([_CLI_SCOPE])

    print_banner()
    agent = TinaSecurityAgent()

    try:
        _next_mode = Mode.TARGETED   # default: targeted
        while True:
            user_input = _prompt_user().strip()
            if not user_input:
                continue

            cmd = user_input.lower()
            # Isolate the slash-word (e.g. "/scope" from "/scope something")
            first_word = cmd.split()[0] if cmd.split() else ""
            has_args   = len(user_input.split(maxsplit=1)) > 1

            # ── Exit ─────────────────────────────────────────────────────────
            if cmd in ("exit", "quit", "q"):
                console.print(Text(f"\n  Goodbye, {USER_NAME}.\n", style="muted"))
                break

            # ── Slash-command block ───────────────────────────────────────────
            # Commands that start with "/" are intercepted here.
            # Unknown slash-words are rejected with an error rather than passed
            # to the model. Commands that take no arguments reject trailing text.
            if first_word.startswith("/"):

                # Commands that take NO arguments — must be used alone
                _SOLO_COMMANDS = {"/clear", "/history", "/findings",
                                  "/report", "/audit"}

                # Commands that optionally accept arguments
                _ARG_COMMANDS  = {"/wordlist", "/fullscan", "/scope"}

                # All known slash commands
                _ALL_COMMANDS  = _SOLO_COMMANDS | _ARG_COMMANDS

                # ── Unknown command ──────────────────────────────────────────
                if first_word not in _ALL_COMMANDS:
                    console.print(Text(
                        f"  Unknown command: {first_word}\n"
                        f"  Valid commands: "
                        + "  ".join(sorted(_ALL_COMMANDS)) + "\n",
                        style="error"))
                    continue

                # ── Solo-only enforcement ────────────────────────────────────
                if first_word in _SOLO_COMMANDS and has_args:
                    console.print(Text(
                        f"  {first_word} takes no arguments — use it on its own.\n",
                        style="warn"))
                    continue

                # ── /clear ───────────────────────────────────────────────────
                if first_word == "/clear":
                    agent.reset()
                    _next_mode = Mode.TARGETED
                    console.print(Text("  Conversation cleared. Mode reset to Targeted.\n",
                                       style="success"))
                    continue

                # ── /history ─────────────────────────────────────────────────
                if first_word == "/history":
                    console.print(Text(f"  {agent.message_count} messages in context.\n",
                                       style="muted"))
                    continue

                # ── /findings ────────────────────────────────────────────────
                if first_word == "/findings":
                    _print_findings_table()
                    continue

                # ── /report ──────────────────────────────────────────────────
                if first_word == "/report":
                    r = save_report()
                    if r.get("ok"):
                        console.print(Text(
                            f"  Saved: {r['markdown']}  ({r['finding_count']} findings)  "
                            f"audit: {r['audit']}\n", style="success"))
                    else:
                        console.print(Text(f"  Error: {r.get('error')}\n", style="error"))
                    continue

                # ── /scope [target] ──────────────────────────────────────────
                if first_word == "/scope":
                    if has_args:
                        target = user_input.strip().split(maxsplit=1)[1].strip()
                        set_scope([target])
                        console.print(Text(f"  Scope set: {target}\n", style="success"))
                    else:
                        scope = _AUTHORISED_SCOPE or ["not set"]
                        console.print(Text(f"  Scope: {', '.join(scope)}\n", style="accent"))
                    continue

                # ── /audit ───────────────────────────────────────────────────
                if first_word == "/audit":
                    for entry in _AUDIT_LOG[-20:]:
                        style = "tier1" if entry["tier"] == "tier1" else "tier2"
                        approved_str = (
                            "auto" if entry["approved"] and entry["tier"] == "tier1"
                            else "YES" if entry["approved"]
                            else "NO"
                        )
                        console.print(Text(
                            f"  [{approved_str}] {entry['command'][:70]}", style=style))
                    console.print()
                    continue

                # ── /wordlist [path] ─────────────────────────────────────────
                if first_word == "/wordlist":
                    parts = user_input.split(maxsplit=1)
                    if has_args:
                        r = set_wordlist(parts[1].strip())
                        if r.get("error"):
                            console.print(Text(f"  {r['error']}\n", style="error"))
                        else:
                            console.print(Text(
                                f"  Wordlist set: {r['wordlist_path']}  "
                                f"({r['lines']:,} entries)\n", style="success"))
                    else:
                        wl = WORDLIST_PATH or "not found"
                        console.print(Text(f"  Wordlist: {wl}\n", style="accent"))
                    continue

                # ── /fullscan [prompt] ───────────────────────────────────────
                if first_word == "/fullscan":
                    if has_args:
                        # "/fullscan <prompt>" — run immediately in full scan mode
                        _next_mode = Mode.FULL_SCAN
                        user_input = user_input.split(maxsplit=1)[1].strip()
                        console.print()
                        # fall through to agent.run() below
                    else:
                        # "/fullscan" alone — arm for next prompt
                        _next_mode = Mode.FULL_SCAN
                        console.print(Text(
                            "  Full scan mode armed — your next prompt will run a complete "
                            "autonomous engagement.\n", style="warn"))
                        continue

            console.print()
            try:
                result = agent.run(user_input, mode=_next_mode)
                _next_mode = Mode.TARGETED   # reset after every turn
                _print_result(result)
            except RuntimeError as e:
                _print_error(str(e))
            except KeyboardInterrupt:
                console.print(Text("\n  [Interrupted]\n", style="warn"))
                continue

            console.print(Text(
                f"  {agent.message_count} messages in context  ·  "
                f"{len(_FINDINGS.all())} findings  ·  "
                f"{len(_AUDIT_LOG)} commands run",
                style="muted"))
            console.print()

    except KeyboardInterrupt:
        console.print(Text(f"\n  Goodbye, {USER_NAME}.\n", style="muted"))


if __name__ == "__main__":
    main()