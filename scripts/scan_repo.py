#!/usr/bin/env python3
"""
repo-scan - Static security scanner for repositories and agent skills.

Clones a repository (or accepts a local path), runs a battery of static
detections, and emits a structured JSON with findings, a 0-100 score, risk per
category, a recommendation, and a final verdict.

It NEVER executes any code from the target repository. It only reads and
classifies text.

Usage:
  python3 scan_repo.py <github_url | git_url | local_path> [--out scan.json] [--keep]

Output: prints the JSON path and a short summary to stdout.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

# Files that are execution points (run code). Weighted higher in the analysis.
EXEC_EXT = {
    ".sh",
    ".bash",
    ".zsh",
    ".py",
    ".js",
    ".cjs",
    ".mjs",
    ".ts",
    ".rb",
    ".pl",
    ".php",
    ".ps1",
    ".cmd",
    ".bat",
    ".go",
    ".rs",
}

# Text files worth reading (skills, docs, manifests)
TEXT_EXT = {
    ".md",
    ".txt",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".dot",
    ".html",
    ".cfg",
    ".ini",
    ".env",
    ".example",
    ".rst",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    "vendor",
    ".cache",
}

MAX_FILE_BYTES = 2_000_000  # skip very large files (likely binary/minified)

# Default output directory (relative to the current working directory).
DEFAULT_OUT_DIR = os.path.join(os.getcwd(), "repo-scan-output")

# Severity weights used only for counts; scoring uses BASE in compute_score().
SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# ---------------------------------------------------------------------------
# DETECTION RULES
# Each rule: id, category, base severity, regex, description, recommendation,
# and scope. The scope controls WHERE the rule is applied to reduce false
# positives:
#   "code"     -> only real code files and manifests (NOT docs .md)
#   "manifest" -> only manifests (package.json, setup.py, requirements...)
#   "text"     -> only text/skill/config (.md/.txt/.json/.yaml) and manifests
#   "any"      -> any file
# This avoids flagging commands that appear only as EXAMPLES inside docs.
# ---------------------------------------------------------------------------

RULES = [
    # ---- EXFILTRATION / NETWORK (real code) ----
    dict(
        id="NET_PIPE_SHELL",
        cat="Network & Exfiltration",
        sev="CRITICAL",
        scope="code",
        rx=r"(curl|wget)\b[^\n|]*\|\s*(ba)?sh\b",
        desc="Remote content piped straight into the shell (curl|bash).",
        rec="Classic malicious-installer pattern. Do NOT install without understanding the exact payload source.",
    ),
    dict(
        id="NET_OUTBOUND",
        cat="Network & Exfiltration",
        sev="HIGH",
        scope="code",
        rx=r"\b(curl|wget|netcat)\b|\bnc\s+-|requests\.(get|post|put)\(|urllib\.request|http\.client|axios\.(get|post)|fetch\(\s*['\"]https?://|new\s+XMLHttpRequest|Invoke-WebRequest",
        desc="Outbound network call.",
        rec="Confirm the destination. Network egress in an install script can exfiltrate data or pull a payload.",
    ),
    dict(
        id="NET_RAW_SOCKET",
        cat="Network & Exfiltration",
        sev="HIGH",
        scope="code",
        rx=r"socket\.socket\(|socket\.connect\(|new\s+Socket\(|net\.connect\(|net\.createConnection\(",
        desc="Raw network socket opened.",
        rec="Raw sockets are rare in legitimate skill tooling. Audit the destination and purpose.",
    ),
    dict(
        id="NET_BIND_ALL",
        cat="Network & Exfiltration",
        sev="MEDIUM",
        scope="code",
        rx=r"listen\([^\n)]*0\.0\.0\.0|host\s*=\s*['\"]0\.0\.0\.0|HOST\s*=\s*['\"]0\.0\.0\.0|--host\s+0\.0\.0\.0",
        desc="Server binds to 0.0.0.0 (exposed to the whole network).",
        rec="Check whether the exposed bind is opt-in (a flag) or the default. A default-exposed bind is a risk; opt-in is acceptable.",
    ),
    # ---- DYNAMIC EXECUTION / OBFUSCATION ----
    dict(
        id="EXEC_DYNAMIC",
        cat="Dynamic Execution",
        sev="HIGH",
        scope="code",
        rx=r"(?<![.\w])eval\s*\(|(?<![.\w])exec\s*\(|new\s+Function\s*\(|os\.system\(|commands\.getoutput\(",
        desc="Dynamic code/command execution (eval, exec, os.system, new Function).",
        rec="Verify the input is fixed/controlled rather than coming from an external source (command injection).",
    ),
    dict(
        id="EXEC_SUBPROCESS",
        cat="Dynamic Execution",
        sev="MEDIUM",
        scope="code",
        rx=r"subprocess\.(call|run|Popen|check_output)\(|\bexecSync\s*\(|\bexecFileSync\s*\(|\bspawnSync\s*\(|\bspawn\s*\(|\bpopen\s*\(|Runtime\.getRuntime\(\)\.exec",
        desc="System process/command execution.",
        rec="Common in build tooling. Check whether the command is literal/fixed or assembled from external input.",
    ),
    dict(
        id="OBF_BASE64_EXEC",
        cat="Dynamic Execution",
        sev="CRITICAL",
        scope="code",
        rx=r"(base64\s+-d|base64\s+--decode|atob\s*\(|b64decode|from_base64|FromBase64String)[^\n]{0,80}(\||eval|exec|\|\s*sh\b|\|\s*node\b|\|\s*python)",
        desc="Base64 decoding feeding execution (obfuscated payload).",
        rec="Strong indicator of obfuscated malicious code. Do NOT install.",
    ),
    dict(
        id="OBF_HEX_ESCAPE",
        cat="Dynamic Execution",
        sev="MEDIUM",
        scope="code",
        rx=r"(\\x[0-9a-fA-F]{2}){12,}|(\\u[0-9a-fA-F]{4}){12,}",
        desc="Long run of hex/unicode byte escapes (possible obfuscation).",
        rec="Long obfuscated strings deserve manual inspection of what they decode to.",
    ),
    dict(
        id="EXEC_DOWNLOAD_RUN",
        cat="Dynamic Execution",
        sev="CRITICAL",
        scope="code",
        rx=r"(curl|wget|Invoke-WebRequest)[^\n]{0,120}(-o|-O|>)[^\n]{0,40}\.(sh|py|js|exe|bin)[^\n]{0,40}(chmod|node\b|python|\|\s*sh\b|\./)",
        desc="Downloads an executable file and runs it right after.",
        rec="Download-and-execute. Do NOT install without verifying the binary's source and contents.",
    ),
    # ---- SECRETS / CREDENTIALS ----
    dict(
        id="SECRET_FILES",
        cat="Secrets & Credentials",
        sev="HIGH",
        scope="code",
        rx=r"\.ssh/|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|\.netrc\b|known_hosts|authorized_keys",
        desc="Access to the user's credential/key files.",
        rec="Reading SSH/AWS keys is highly suspicious. Confirm why the tool needs this.",
    ),
    dict(
        id="SECRET_ENV",
        cat="Secrets & Credentials",
        sev="LOW",
        scope="code",
        rx=r"(API_KEY|CLIENT_SECRET|PRIVATE_KEY|AWS_SECRET|ACCESS_KEY)\b",
        desc="Reference to sensitive environment variables.",
        rec="Check whether the variable is only read locally or sent outbound (combine with NET_OUTBOUND).",
    ),
    dict(
        id="SECRET_HARDCODED",
        cat="Secrets & Credentials",
        sev="HIGH",
        scope="any",
        rx=r"(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|xox[baprs]-[a-zA-Z0-9-]{10,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)",
        desc="Credential/key apparently hardcoded in the repository.",
        rec="Embedded credential in code. Treat it as compromised and do not trust the repo.",
    ),
    # ---- INSTALL HOOKS / PERSISTENCE ----
    dict(
        id="INSTALL_HOOK_NPM",
        cat="Install Hooks",
        sev="HIGH",
        scope="manifest",
        rx=r"\"(pre|post)(install|pack|publish|prepare)\"\s*:",
        desc="package.json defines a pre/post install script (runs on install).",
        rec="(pre|post)install scripts run automatically. Read exactly what they execute.",
    ),
    dict(
        id="INSTALL_SETUPPY",
        cat="Install Hooks",
        sev="MEDIUM",
        scope="manifest",
        rx=r"cmdclass|os\.system\(|subprocess[^\n]{0,40}(install|setup)",
        desc="setup.py with custom install behavior.",
        rec="Verify the setup.py does not run arbitrary commands on install.",
    ),
    dict(
        id="PERSIST_CRON",
        cat="Persistence",
        sev="HIGH",
        scope="code",
        rx=r"crontab\s+|/etc/cron|launchctl\s+|systemctl\s+enable|LaunchAgents|reg\s+add\b|schtasks\s+",
        desc="Creates a persistent schedule/service on the system.",
        rec="Persistence (cron/service/registry) is unusual in skills. Audit carefully.",
    ),
    dict(
        id="PERSIST_RC",
        cat="Persistence",
        sev="MEDIUM",
        scope="code",
        rx=r"(>>|>)\s*[\"']?[~$][^\n]{0,40}(\.bashrc|\.zshrc|\.profile|\.bash_profile)",
        desc="Writes to shell startup files (.bashrc/.zshrc).",
        rec="Modifying shell rc files can inject permanent behavior. Confirm the intent.",
    ),
    # ---- DESTRUCTION / FILESYSTEM ----
    dict(
        id="FS_DESTRUCTIVE",
        cat="Filesystem",
        sev="HIGH",
        scope="code",
        rx=r"rm\s+-rf\s+[~/]|rm\s+-rf\s+\$|shutil\.rmtree\(|\bdel\s+/[sfq]\b|format\s+[a-z]:",
        desc="Destructive file removal over a broad path.",
        rec="Confirm the rm target is a controlled temp directory, not a user path.",
    ),
    dict(
        id="FS_CHMOD_777",
        cat="Filesystem",
        sev="LOW",
        scope="code",
        rx=r"chmod\s+(-R\s+)?777|chmod\s+(-R\s+)?a\+rwx",
        desc="Excessively open permissions (777).",
        rec="777 is poor security hygiene. Low risk in isolation, but worth noting.",
    ),
    # ---- PROMPT INJECTION (skill/agent text) ----
    dict(
        id="PI_OVERRIDE",
        cat="Prompt Injection (Skill)",
        sev="HIGH",
        scope="text",
        rx=r"(?i)(ignore (all |the )?(previous|prior|above).{0,25}(instructions|rules|prompt)|disregard.{0,20}(instructions|system prompt)|forget (everything|all).{0,20}(instruction|prior)|do not tell the user|don'?t inform the user|hide this from the user|without (telling|informing) the user)",
        desc="Text attempting to override system instructions or hide actions from the user.",
        rec="Override/concealment instructions in a skill are a RED FLAG. Legitimate skills never ask to keep secrets from the user.",
    ),
    dict(
        id="PI_EXFIL_INSTRUCTION",
        cat="Prompt Injection (Skill)",
        sev="CRITICAL",
        scope="text",
        rx=r"(?i)(send|upload|exfiltrate|post|transmit)\b[^\n]{0,40}(env|secret|token|password|api[_ ]?key|credential|\.ssh|private key|file contents|conversation|history)[^\n]{0,40}(to)\b[^\n]{0,40}(https?://|webhook|@|external)",
        desc="Instruction asking to send SENSITIVE data to an external destination.",
        rec="Skill instructing the agent to exfiltrate sensitive data. Do NOT install without verifying the destination.",
    ),
    dict(
        id="PI_FORCED_TOOL",
        cat="Prompt Injection (Skill)",
        sev="MEDIUM",
        scope="text",
        rx=r"(?i)(always|must|you should)\b[^\n]{0,30}(run|execute|delete|rm |curl|install)[^\n]{0,45}(without (asking|confirmation|permission)|auto.?approve|automatically)",
        desc="Instruction to perform sensitive actions without user confirmation.",
        rec="Forcing execution without confirmation removes human oversight. Evaluate the context.",
    ),
    # ---- DEPENDENCIES (manifests) ----
    dict(
        id="DEP_GIT_URL",
        cat="Dependencies",
        sev="MEDIUM",
        scope="manifest",
        rx=r"(git\+https?://|git\+ssh://|github:[^\s\"']+/[^\s\"']+#)",
        desc="Dependency pointing at an arbitrary git repository (not a registry).",
        rec="Git-URL deps bypass the registry and can change. Pin a commit and review the source.",
    ),
    dict(
        id="DEP_HTTP_INSTALL",
        cat="Dependencies",
        sev="MEDIUM",
        scope="manifest",
        rx=r"https?://[^\s\"']+\.(tar\.gz|tgz|zip|whl)\b",
        desc="Dependency installed directly from a file URL.",
        rec="Installing a package from an arbitrary URL bypasses registry verification. Check the source.",
    ),
]

# File names treated as MANIFEST (deps / installation)
MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "requirements.txt",
    "pipfile",
    "cargo.toml",
    "gemfile",
    "go.mod",
    "composer.json",
    "build.gradle",
    "pom.xml",
    "dockerfile",
    "makefile",
}


def file_kind(rel, ext):
    """Classify a file as code / manifest / text for rule scoping."""
    base = os.path.basename(rel).lower()
    if base in MANIFEST_NAMES:
        return "manifest"
    if ext in EXEC_EXT or base in ("session-start", "run-hook"):
        return "code"
    return "text"


def rule_applies(scope, kind):
    if scope == "any":
        return True
    if scope == "code":
        return kind in ("code", "manifest")
    if scope == "manifest":
        return kind == "manifest"
    if scope == "text":
        return kind in ("text", "manifest")
    return False


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------


def run(cmd, cwd=None, timeout=120):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def is_git_url(s):
    return bool(re.match(r"^(https?://|git@|git://|ssh://)", s.strip()))


def normalize_github(url):
    """Accept github.com/owner/repo or .git; return a clonable URL."""
    u = url.strip().rstrip("/")
    if u.startswith("git@") or u.endswith(".git"):
        return u
    if "github.com" in u and not u.endswith(".git"):
        return u + ".git"
    return u


def clone_repo(url, dest):
    cu = normalize_github(url)
    r = run(["git", "clone", "--depth", "1", cu, dest], timeout=180)
    if r.returncode != 0:
        raise RuntimeError(f"git clone failed: {r.stderr.strip()[:500]}")
    return cu


def get_commit(path):
    r = run(["git", "rev-parse", "HEAD"], cwd=path)
    return r.stdout.strip()[:12] if r.returncode == 0 else "unknown"


def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            yield full, rel, os.path.splitext(fn)[1].lower()


def looks_like_test_or_fixture(rel):
    low = rel.lower()
    return any(
        seg in low for seg in ("test", "fixture", "example", "spec", "mock", "sample", "demo")
    )


# ---------------------------------------------------------------------------
# SCAN
# ---------------------------------------------------------------------------


def scan_tree(root):
    findings = []
    exec_files = []
    text_files = []
    total_files = 0
    total_bytes = 0
    ext_counts = {}

    for full, rel, ext in iter_files(root):
        total_files += 1
        ext_counts[ext or "(none)"] = ext_counts.get(ext or "(none)", 0) + 1
        scannable = (
            ext in EXEC_EXT
            or ext in TEXT_EXT
            or os.path.basename(rel) in ("session-start", "run-hook", "Makefile", "Dockerfile")
        )
        if ext in EXEC_EXT:
            exec_files.append(rel)
        try:
            size = os.path.getsize(full)
        except OSError:
            continue
        total_bytes += size
        if not scannable or size > MAX_FILE_BYTES:
            continue
        try:
            with open(full, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except Exception:
            continue
        text_files.append(rel)
        is_test = looks_like_test_or_fixture(rel)
        kind = file_kind(rel, ext)
        order = SEVERITY_LEVELS
        for i, line in enumerate(lines, 1):
            if len(line) > 4000:
                line = line[:4000]
            for rule in RULES:
                if not rule_applies(rule.get("scope", "any"), kind):
                    continue
                if re.search(rule["rx"], line):
                    sev = rule["sev"]
                    eff_sev = sev
                    notes = []
                    # 1) Findings in test/fixture files are downgraded one level
                    #    (vulnerabilities planted on purpose are not a real threat).
                    if is_test and sev in ("CRITICAL", "HIGH", "MEDIUM"):
                        eff_sev = order[max(0, order.index(eff_sev) - 1)]
                        notes.append("test/fixture file")
                    # 2) rm -rf targeting /tmp is legitimate cleanup: downgrade.
                    if rule["id"] == "FS_DESTRUCTIVE" and "/tmp" in line:
                        eff_sev = order[max(0, order.index(eff_sev) - 1)]
                        notes.append("target in /tmp")
                    note = (" (" + "; ".join(notes) + "; severity downgraded)") if notes else ""
                    findings.append(
                        dict(
                            rule_id=rule["id"],
                            category=rule["cat"],
                            severity=eff_sev,
                            raw_severity=sev,
                            file=rel,
                            line=i,
                            file_kind=kind,
                            snippet=line.strip()[:200],
                            description=rule["desc"] + note,
                            recommendation=rule["rec"],
                            in_test=is_test,
                        )
                    )

    return findings, dict(
        total_files=total_files,
        total_bytes=total_bytes,
        exec_files=sorted(exec_files),
        exec_file_count=len(exec_files),
        scanned_text_files=len(text_files),
        ext_counts=ext_counts,
    )


def detect_exec_points(root):
    """Files that may run automatically: hooks, manifests, dockerfile."""
    points = []
    for _full, rel, _ext in iter_files(root):
        base = os.path.basename(rel).lower()
        if (
            base
            in (
                "hooks.json",
                "plugin.json",
                "marketplace.json",
                "package.json",
                "setup.py",
                "pyproject.toml",
                "dockerfile",
                "makefile",
            )
            or "hook" in rel.lower()
        ):
            points.append(rel)
    return sorted(set(points))


# ---------------------------------------------------------------------------
# SCORING
# ---------------------------------------------------------------------------


def compute_score(findings):
    import math

    # Base penalty per severity, applied with diminishing returns:
    # penalty = base * sqrt(count). This prevents repetitions of a benign
    # pattern (e.g. several legitimate execSync calls) from unfairly zeroing
    # the score, while staying sensitive to a single truly severe finding.
    BASE = {"CRITICAL": 45, "HIGH": 18, "MEDIUM": 6, "LOW": 1.5, "INFO": 0}
    by_sev = {k: 0 for k in SEVERITY_LEVELS}
    by_cat = {}
    order = SEVERITY_LEVELS
    for f in findings:
        sev = f["severity"]
        by_sev[sev] = by_sev.get(sev, 0) + 1
        by_cat.setdefault(f["category"], {"count": 0, "max_sev": "INFO"})
        by_cat[f["category"]]["count"] += 1
        cur = by_cat[f["category"]]["max_sev"]
        if order.index(sev) > order.index(cur):
            by_cat[f["category"]]["max_sev"] = sev

    penalty = 0.0
    for sev, base in BASE.items():
        n = by_sev.get(sev, 0)
        if n > 0:
            penalty += base * math.sqrt(n)
    score = int(round(max(0, min(100, 100 - penalty))))
    return score, by_sev, by_cat


def verdict_for(score, by_sev):
    if by_sev.get("CRITICAL", 0) > 0 and score < 60:
        band = "CRITICAL"
    elif score >= 90:
        band = "SAFE"
    elif score >= 70:
        band = "LOW RISK"
    elif score >= 40:
        band = "MODERATE RISK"
    elif score >= 20:
        band = "HIGH RISK"
    else:
        band = "CRITICAL"

    mapping = {
        "SAFE": (
            "INSTALL",
            "No relevant signs of malicious code. Safe to install, preferably pinning the version/commit.",
        ),
        "LOW RISK": (
            "INSTALL WITH REVIEW",
            "A few points of attention. Review the medium/high findings before installing.",
        ),
        "MODERATE RISK": (
            "REVIEW BEFORE INSTALLING",
            "Patterns that require manual inspection. Do not install before understanding each HIGH/CRITICAL finding.",
        ),
        "HIGH RISK": (
            "DO NOT INSTALL WITHOUT A DEEP AUDIT",
            "Multiple risk signals. Only proceed after a line-by-line audit by someone you trust.",
        ),
        "CRITICAL": (
            "DO NOT INSTALL",
            "Strong signs of malicious or dangerous behavior. Do not install.",
        ),
    }
    action, text = mapping[band]
    return band, action, text


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------


def main():
    args = sys.argv[1:]
    if not args:
        print("Usage: scan_repo.py <repo_url | local_path> [--out scan.json] [--keep]")
        sys.exit(1)

    target = args[0]
    os.makedirs(DEFAULT_OUT_DIR, exist_ok=True)
    out_path = os.path.join(DEFAULT_OUT_DIR, "repo_scan.json")
    keep = "--keep" in args
    if "--out" in args:
        out_path = args[args.index("--out") + 1]

    tmp = None
    cloned_from = None
    if is_git_url(target) or "github.com" in target:
        tmp = tempfile.mkdtemp(prefix="reposcan_")
        repo_dir = os.path.join(tmp, "repo")
        cloned_from = clone_repo(target, repo_dir)
        source_label = target
    else:
        repo_dir = os.path.abspath(target)
        if not os.path.isdir(repo_dir):
            print(f"Path not found: {repo_dir}")
            sys.exit(1)
        source_label = repo_dir

    commit = get_commit(repo_dir) if os.path.isdir(os.path.join(repo_dir, ".git")) else "n/a"

    findings, stats = scan_tree(repo_dir)
    exec_points = detect_exec_points(repo_dir)
    score, by_sev, by_cat = compute_score(findings)
    band, action, verdict_text = verdict_for(score, by_sev)

    report = dict(
        meta=dict(
            source=source_label,
            cloned_from=cloned_from,
            commit=commit,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            scanner="repo-scan",
            scanner_version="1.0.0",
            rules_count=len(RULES),
        ),
        stats=stats,
        auto_exec_points=exec_points,
        score=score,
        severity_counts=by_sev,
        category_summary=by_cat,
        verdict=dict(band=band, action=action, text=verdict_text),
        findings=sorted(findings, key=lambda f: SEVERITY_LEVELS.index(f["severity"]), reverse=True),
    )

    out_dir = os.path.dirname(out_path) or "."
    os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    if tmp and not keep:
        shutil.rmtree(tmp, ignore_errors=True)

    # Short summary for stdout
    print(f"JSON: {out_path}")
    print(f"SCORE: {score}/100  | VERDICT: {band} -> {action}")
    print(
        f"Findings: CRIT={by_sev.get('CRITICAL',0)} HIGH={by_sev.get('HIGH',0)} "
        f"MED={by_sev.get('MEDIUM',0)} LOW={by_sev.get('LOW',0)}"
    )
    print(
        f"Files: {stats['total_files']} | exec: {stats['exec_file_count']} | "
        f"auto-exec points: {len(exec_points)}"
    )


if __name__ == "__main__":
    main()
