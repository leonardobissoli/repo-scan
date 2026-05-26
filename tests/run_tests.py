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

    if not check(
        "every finding carries the likely_false_positive field",
        all("likely_false_positive" in f for f in mal["findings"]),
    ):
        failures += 1

    fp_in_malicious = [f for f in mal["findings"] if f.get("likely_false_positive")]
    detail = (
        f"{len(fp_in_malicious)} flagged: "
        + ", ".join(f"{x['file']}:{x['line']} {x['rule_id']}" for x in fp_in_malicious[:3])
        if fp_in_malicious
        else ""
    )
    if not check(
        "malicious fixture has zero likely_false_positive findings",
        not fp_in_malicious,
        detail=detail,
    ):
        failures += 1

    if not check(
        "fixtures are NOT detected as self-scan",
        not clean.get("self_scan") and not mal.get("self_scan"),
        detail=f"clean.self_scan={clean.get('self_scan')} mal.self_scan={mal.get('self_scan')}",
    ):
        failures += 1

    print()
    print("[repo-scan root (self-scan)]")
    self = run_scan(REPO_ROOT, "self.json")
    if not check(
        "self_scan flag is True",
        self.get("self_scan") is True,
        detail=f"got {self.get('self_scan')!r}",
    ):
        failures += 1
    if not check(
        "verdict band is SELF-SCAN",
        self["verdict"]["band"] == "SELF-SCAN",
        detail=f"got {self['verdict']['band']!r}",
    ):
        failures += 1
    if not check(
        "verdict action is NOT REPRESENTATIVE",
        self["verdict"]["action"] == "NOT REPRESENTATIVE",
        detail=f"got {self['verdict']['action']!r}",
    ):
        failures += 1

    print()
    print("[generate_report.py on self-scan JSON]")
    self_json = os.path.join(OUT_DIR, "self.json")
    docx_out = os.path.join(OUT_DIR, "self_report.docx")
    html_out = os.path.join(OUT_DIR, "self_dashboard.html")
    proc = subprocess.run(
        [
            sys.executable,
            os.path.join(REPO_ROOT, "scripts", "generate_report.py"),
            self_json,
            "--docx",
            docx_out,
            "--html",
            html_out,
        ],
        capture_output=True,
        text=True,
    )
    if not check(
        "report generator exits 0 on self-scan",
        proc.returncode == 0,
        detail=proc.stderr.strip()[:200] if proc.returncode else "",
    ):
        failures += 1
    if not check(
        "no DOCX written for self-scan (without --force)",
        not os.path.exists(docx_out),
    ):
        failures += 1
    if not check(
        "no HTML written for self-scan (without --force)",
        not os.path.exists(html_out),
    ):
        failures += 1

    print()
    if failures:
        print(f"FAILED: {failures} assertion(s)")
        sys.exit(1)
    print(
        f"PASSED: clean=score {clean['score']}/{clean['verdict']['band']}, "
        f"malicious=score {mal['score']}/{mal['verdict']['band']}, "
        f"rules triggered={len(triggered & EXPECTED_MALICIOUS_RULES)}/{len(EXPECTED_MALICIOUS_RULES)}, "
        f"self_scan_band={self['verdict']['band']}"
    )


if __name__ == "__main__":
    main()
