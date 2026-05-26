# repo-scan

> Static security audit for repositories and AI agent skills - **before** you install them.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Made for Claude Code](https://img.shields.io/badge/Claude%20Code-skill-8b5cf6.svg)](https://docs.claude.com)
[![Static analysis](https://img.shields.io/badge/analysis-static%20only-16A34A.svg)](#how-it-works)
[![Read-only repository](https://img.shields.io/badge/repository-read--only-6B7280.svg)](#repository-access-policy)

`repo-scan` clones a repository (or reads a local path), statically scans the
code **without executing anything**, and produces a **DOCX report** plus an
interactive **HTML dashboard** with a **0-100 score**, per-category risk,
findings with snippet and recommendation, and a final **install verdict**.

It exists because installing a third-party plugin, agent skill, or package runs
their code with the same power your tools already have. `repo-scan` gives you a
fast, repeatable second opinion before you trust something new.

---

## Table of contents

- [Repository access policy](#repository-access-policy)
- [Why](#why)
- [What it detects](#what-it-detects)
- [Install](#install)
- [Usage](#usage)
- [Output](#output)
- [Scoring](#scoring)
- [How it works](#how-it-works)
- [Limitations](#limitations)
- [License](#license)

---

## Repository access policy

This repository is public for transparency and read-only access. External
contributions, pull requests, issues, GitHub Actions, bots, and automated
workflows are not accepted. Only the repository owner is authorized to modify
the official source code.

You may clone or fork this repository to use the scanner locally; any changes
you make in your fork have no effect on the official codebase. See
[`SECURITY.md`](SECURITY.md) for the full policy.

## Why

AI coding agents and skill marketplaces make it trivial to install code from
strangers. Most of it is fine. Some of it is not. A manual review is slow and
easy to skip. `repo-scan` automates the first pass:

- **Static, never executes the target.** Read-only by design.
- **One score, one verdict.** From `INSTALL` to `DO NOT INSTALL`.
- **Shareable artifacts.** A DOCX you can archive and an HTML dashboard you can open in any browser.
- **Tuned against noise.** Documentation examples, test fixtures, and `/tmp` cleanup are not treated as threats.

## What it detects

| Category | Examples |
|---|---|
| Network & Exfiltration | `curl \| bash`, outbound requests, raw sockets, bind to `0.0.0.0` |
| Dynamic Execution | `eval`/`exec`/`os.system`, `subprocess`/`child_process`, base64+exec, download-and-run |
| Secrets & Credentials | reads of `~/.ssh` / `.aws`, sensitive env vars, hardcoded keys |
| Install Hooks | `pre`/`post` install scripts in `package.json`, custom `setup.py` |
| Persistence | cron, launchd, systemd, registry, `.bashrc`/`.zshrc` writes |
| Filesystem | destructive `rm -rf`, `chmod 777` |
| Prompt Injection (Skill) | instruction override, hiding actions from the user, exfiltration instructions |
| Dependencies | arbitrary git-URL deps, install from a file URL |

Full rule reference: [`references/threat-patterns.md`](references/threat-patterns.md).

## Install

Requirements: **Python 3.8+** and **git** on your PATH.

```bash
git clone https://github.com/leonardobissoli/repo-scan.git
cd repo-scan
pip install python-docx   # only needed for the DOCX report
```

### Use as a Claude Code skill

Place the folder where Claude Code discovers skills (e.g. `~/.claude/skills/`),
or load it via your plugin/marketplace flow. The skill is defined by
[`SKILL.md`](SKILL.md). Once available, ask Claude to *"scan this repo before I
install it: &lt;link&gt;"* and it runs the workflow below.

## Usage

```bash
# 1) Scan a remote repo (or a local path)
python3 scripts/scan_repo.py https://github.com/owner/repo

# 2) Generate the DOCX + HTML reports from the JSON
python3 scripts/generate_report.py ./repo-scan-output/repo_scan.json
```

Options:

```text
scan_repo.py <url|path> [--out PATH] [--keep]
  --out PATH   Where to write the JSON (default: ./repo-scan-output/repo_scan.json)
  --keep       Keep the temporary clone instead of deleting it

generate_report.py <scan.json> [--docx PATH] [--html PATH]
  --docx PATH  Output DOCX path (default: ./repo-scan-output/repo_scan_report.docx)
  --html PATH  Output HTML path (default: ./repo-scan-output/repo_scan_dashboard.html)
```

## Output

All artifacts land in `./repo-scan-output/` by default:

- `repo_scan.json` - structured findings, score, category summary, verdict.
- `repo_scan_report.docx` - detailed, archivable report.
- `repo_scan_dashboard.html` - dark dashboard with a 0-100 gauge, severity cards, and a filterable findings table.

## Scoring

The score starts at **100** and subtracts points by severity with **diminishing
returns** (`penalty = base x sqrtcount`) so repeated benign patterns do not unfairly
zero the result.

| Score | Band | Action |
|---|---|---|
| 90-100 | SAFE | INSTALL (pin version/commit) |
| 70-89 | LOW RISK | INSTALL WITH REVIEW |
| 40-69 | MODERATE RISK | REVIEW BEFORE INSTALLING |
| 20-39 | HIGH RISK | DO NOT INSTALL without a deep audit |
| 0-19 | CRITICAL | DO NOT INSTALL |

Details: [`references/scoring-rubric.md`](references/scoring-rubric.md).

## How it works

1. **Clone** the target shallowly (`--depth 1`) into a temp directory, or read a local path.
2. **Walk** the tree, skipping VCS/build/vendor directories and oversized files.
3. **Match** each line against a rule set, scoped by file type so documentation
   examples and test fixtures do not generate noise.
4. **Score** the findings and derive a verdict band.
5. **Render** the JSON into a DOCX report and an HTML dashboard.

The scanner never imports, sources, or runs any file from the target. The only
executed code is `repo-scan`'s own two scripts.

## Limitations

Static analysis does not understand intent or dynamic control flow. Expect both
false positives and false negatives - heavily obfuscated code or logic spread
across multiple files can slip through. **A high score reduces, but does not
eliminate, the need to manually review the auto-execution points** the report
lists. Always prefer official sources and pin a version/commit.

**Scanning `repo-scan` itself.** The scanner cannot meaningfully audit its own
source: `scripts/scan_repo.py` contains the detection regexes as literal Python
strings (`r"(curl|wget)...sh"`, `eval(`, `base64`, ...), so they match
themselves when the file is read line-by-line. The `test-samples/` fixtures are
also intentionally detected - that is their purpose. A scan of this repository
will therefore land in CRITICAL. This is a known limitation of every
regex-based scanner (bandit, detect-secrets, semgrep behave the same way) and
not a signal about `repo-scan`'s real security posture. To sanity-check the
scanner on a clean tree, point it at `test-samples/clean/` instead.

## License

MIT - see [`LICENSE`](LICENSE).
