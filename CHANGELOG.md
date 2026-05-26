# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]
### Added
- README hero screenshot of the HTML dashboard plus a secondary screenshot
  of the DOCX cover page, both from a real-world scan of
  [`obra/superpowers`](https://github.com/obra/superpowers) (89/100 LOW RISK).
  Replaces the previous text-only README with a visual that conveys what the
  product does in 5 seconds. Screenshots live under `docs/`.

### Fixed
- HTML dashboard gauge had its color gradient inverted relative to the
  universal convention: high scores were pointing at the red side and low
  scores at the green side. The conic-gradient was swapped so the green
  half now sits where the needle lands for high (good) scores and the red
  half where it lands for low (bad) scores. The self-scan grey override is
  unaffected.

### Changed
- `generate_report.py` now **SKIPS** DOCX/HTML generation when the input
  JSON is a self-scan (`self_scan: true`); pass `--force` to override.
  A self-scan report is misleading by definition (its own verdict says
  "NOT REPRESENTATIVE"), so producing 30+ pages of findings nobody should
  act on is anti-pattern. The raw JSON is still written by `scan_repo.py`.

### Added
- **Self-scan detection.** When the target repository is a copy of
  `repo-scan` (detected via content fingerprint on `scripts/scan_repo.py`),
  the scanner overrides the verdict to `SELF-SCAN - NOT REPRESENTATIVE`
  (grey, neutral) instead of CRITICAL. The HTML and DOCX reports show a
  banner at the top explaining the situation; the raw numeric score is
  preserved in the JSON (`self_scan: true`, `score: <raw>`) for
  transparency. stdout prints `SELF-SCAN DETECTED` instead of the usual
  `SCORE x/100 | VERDICT: ...` line.
- `likely_false_positive` boolean on every finding (JSON, DOCX, HTML). Set
  to `true` when the match falls inside a Python raw-string literal, a
  Python `#` comment, a Python rule-metadata assignment (`rx=`, `desc=`,
  `rec=`), or a Markdown span wrapped by `` ` `` / `'` / `"`. Informational
  only - does NOT change severity or score in v1.x.
- HTML dashboard: "Hide likely FP" filter button + per-row dimming + a
  "likely FP" badge next to the severity pill.
- DOCX report: inline "[likely false positive]" tag next to the severity
  heading when the flag is set.
- New documentation [`references/interpreting-findings.md`](references/interpreting-findings.md) -
  step-by-step playbook for triaging a report, with two worked examples
  (a real positive and a false positive that look identical in summary).
- README "Limitations" section now explains the self-scan paradox and
  points to the new interpreting-findings guide.
- `references/scoring-rubric.md` section "Known false positive: scanning
  `repo-scan` itself".

### Changed
- Repository switched to **public read-only** mode: no GitHub Actions, no
  pull requests, no Issues, no external contributions accepted. See
  [`SECURITY.md`](SECURITY.md) for the full access policy.

### Removed
- CI / CodeQL / OpenSSF Scorecard workflows under `.github/workflows/`.
- `.github/dependabot.yml`, Issue / Pull Request templates.
- `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` (no external contributions).
- `.pre-commit-config.yaml` and `.secrets.baseline` (commit-time automation).

## [1.0.0] - 2026-05-25
### Added
- Initial release.
- Static scanner (`scripts/scan_repo.py`) with 23 detection rules across
  Network & Exfiltration, Dynamic Execution, Secrets & Credentials, Install
  Hooks, Persistence, Filesystem, Prompt Injection, and Dependencies.
- 0-100 scoring with diminishing-returns penalties and a five-band verdict.
- Report generator (`scripts/generate_report.py`) producing a DOCX report and an
  interactive HTML dashboard.
- False-positive controls: documentation-aware rule scoping, test/fixture
  downgrade, `/tmp` cleanup downgrade, method-call exclusion for `eval`/`exec`.
- Claude Code skill definition (`SKILL.md`) and reference docs.
