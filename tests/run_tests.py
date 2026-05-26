#!/usr/bin/env python3
"""
repo-scan - integration test runner.

Runs scripts/scan_repo.py against the two fixture trees under test-samples/
and asserts the scanner produces the expected bands and rule coverage. Uses
only the standard library - no pytest, no extra deps.

Exits 0 on success, 1 on any failed assertion. Designed to be invoked from CI
(.github/workflows/ci.yml) and locally:

    python3 tests/run_tests.py
"""

import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER = os.path.join(REPO_ROOT, "scripts", "scan_repo.py")
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".out")

CLEAN_DIR = os.path.join(REPO_ROOT, "test-samples", "clean")
MALICIOUS_DIR = os.path.join(REPO_ROOT, "test-samples", "malicious")

# Rule ids the malicious fixture is built to trigger. Keep in sync with the
# fixture contents. Removing a rule from this list means the fixture no longer
# exercises it - update the fixture or the list explicitly.
EXPECTED_MALICIOUS_RULES = {
    "NET_PIPE_SHELL",  # install.sh: curl | bash
    "OBF_BASE64_EXEC",  # payload.js: atob(...) ... eval(...)
    "EXEC_DYNAMIC",  # setup.py: os.system(...)
    "INSTALL_HOOK_NPM",  # package.json: postinstall
    "INSTALL_SETUPPY",  # setup.py: cmdclass / os.system
    "PI_OVERRIDE",  # SKILL.md: ignore previous instructions
    "PI_EXFIL_INSTRUCTION",  # SKILL.md: send ~/.ssh/id_rsa to https://...
    "PI_FORCED_TOOL",  # SKILL.md: always run ... without asking
    "SECRET_FILES",  # exfil.py: ~/.ssh/id_rsa
    "NET_OUTBOUND",  # exfil.py: requests.post
    "DEP_GIT_URL",  # package.json: git+https url
}

CLEAN_OK_BANDS = {"SAFE", "LOW RISK"}
MALICIOUS_OK_BANDS = {"HIGH RISK", "CRITICAL"}


def run_scan(target_dir, out_name):
    os.makedirs(OUT_DIR, exist_ok=True)
    out_path = os.path.join(OUT_DIR, out_name)
    cmd = [sys.executable, SCANNER, target_dir, "--out", out_path]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print("--- scanner stdout ---")
        print(proc.stdout)
        print("--- scanner stderr ---")
        print(proc.stderr)
        raise SystemExit(f"scan_repo.py failed for {target_dir}: exit {proc.returncode}")
    with open(out_path, encoding="utf-8") as fh:
        return json.load(fh)


def check(label, ok, detail=""):
    mark = "OK  " if ok else "FAIL"
    print(f"  [{mark}] {label}" + (f"  -- {detail}" if detail else ""))
    return ok


def main():
    failures = 0

    print("[clean fixture]")
    clean = run_scan(CLEAN_DIR, "clean.json")
    score = clean["score"]
    band = clean["verdict"]["band"]
    if not check(f"score >= 70 (got {score})", score >= 70):
        failures += 1
    if not check(f"band in {sorted(CLEAN_OK_BANDS)} (got {band!r})", band in CLEAN_OK_BANDS):
        failures += 1
    if not check(
        "no CRITICAL findings",
        clean["severity_counts"].get("CRITICAL", 0) == 0,
        detail=str(clean["severity_counts"]),
    ):
        failures += 1

    print()
    print("[malicious fixture]")
    mal = run_scan(MALICIOUS_DIR, "malicious.json")
    score = mal["score"]
    band = mal["verdict"]["band"]
    if not check(f"score <= 39 (got {score})", score <= 39):
        failures += 1
    if not check(
        f"band in {sorted(MALICIOUS_OK_BANDS)} (got {band!r})", band in MALICIOUS_OK_BANDS
    ):
        failures += 1
    if not check(
        "at least 1 CRITICAL finding",
        mal["severity_counts"].get("CRITICAL", 0) >= 1,
        detail=str(mal["severity_counts"]),
    ):
        failures += 1

    triggered = {f["rule_id"] for f in mal["findings"]}
    missing = EXPECTED_MALICIOUS_RULES - triggered
    if not check(
        f"all expected rule_ids triggered ({len(EXPECTED_MALICIOUS_RULES)})",
        not missing,
        detail=f"missing: {sorted(missing)}" if missing else "",
    ):
        failures += 1

    print()
    if failures:
        print(f"FAILED: {failures} assertion(s)")
        sys.exit(1)
    print(
        f"PASSED: clean=score {clean['score']}/{clean['verdict']['band']}, "
        f"malicious=score {mal['score']}/{mal['verdict']['band']}, "
        f"rules triggered={len(triggered & EXPECTED_MALICIOUS_RULES)}/{len(EXPECTED_MALICIOUS_RULES)}"
    )


if __name__ == "__main__":
    main()
