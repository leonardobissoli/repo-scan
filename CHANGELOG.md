# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]
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
