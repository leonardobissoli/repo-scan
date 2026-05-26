# Scoring Rubric - repo-scan

Reference document. Read this when you need to explain HOW a score was computed
or justify a verdict.

## Calculation

1. Initial score = **100**.
2. For each severity present, the penalty is applied with diminishing returns:

   ```
   penalty_severity = base * sqrt(count)
   total_penalty    = sum of all penalty_severity
   score            = max(0, min(100, round(100 - total_penalty)))
   ```

   Bases: CRITICAL=45, HIGH=18, MEDIUM=6, LOW=1.5, INFO=0.

3. The square root makes the first finding of a severity weigh fully and each
   repetition weigh progressively less. Examples (HIGH only):
   - 1 HIGH  -> 18  -> score 82
   - 4 HIGH  -> 36  -> score 64
   - 9 HIGH  -> 54  -> score 46

   This prevents a repeated benign pattern (e.g. many legitimate `execSync`
   calls) from zeroing the score, while staying sensitive to a single truly
   severe finding.

## Bands and verdict

| Score   | Band          | Recommended action |
|---------|---------------|--------------------|
| 90-100  | SAFE          | INSTALL. Prefer the official source and pin a version/commit. |
| 70-89   | LOW RISK      | INSTALL WITH REVIEW. Read the MEDIUM/HIGH findings first. |
| 40-69   | MODERATE RISK | REVIEW BEFORE INSTALLING. Understand each HIGH/CRITICAL. |
| 20-39   | HIGH RISK     | DO NOT INSTALL without a trusted line-by-line audit. |
| 0-19    | CRITICAL      | DO NOT INSTALL. |

**CRITICAL override**: if at least one effective CRITICAL finding remains (after
downgrades) AND the score is < 60, the verdict is forced to CRITICAL regardless
of the numeric band.

## Severity adjustments (anti-false-positive)

Before scoring, a finding's effective severity may be downgraded one level
(CRITICAL->HIGH->MEDIUM->LOW->INFO) when:

- The file is a **test/fixture** (name contains test, fixture, example, spec,
  mock, sample, demo). Vulnerabilities planted to test reviewers are not a real
  threat from the package.
- The rule is `FS_DESTRUCTIVE` and the `rm -rf` target is in **/tmp** (cleanup).

Both can stack (a two-level downgrade if both conditions hold).

## Known false positive: scanning `repo-scan` itself

`scripts/scan_repo.py` defines its detection regexes as literal Python strings.
When the scanner reads its own source line-by-line, those literals match the
patterns they are designed to catch (e.g. the string
`r"(curl|wget)\b[^\n|]*\|\s*(ba)?sh\b"` matches the `NET_PIPE_SHELL` rule).
The `test-samples/malicious/` fixtures are also intentionally detected. As a
result, a scan of this repository will land in CRITICAL - this is expected and
not a real signal. Every regex-based scanner has the same property
(`bandit`, `detect-secrets`, `semgrep`). There is no mechanism in v1.0.0 to
exempt the scanner's own source; a future version may add one.

## Rule scoping by file type

- **code** (`.sh .py .js .ts .rb .pl .php .ps1` ... + hooks): network, execution,
  filesystem secrets, persistence, filesystem.
- **manifest** (`package.json`, `setup.py`, `requirements.txt`, `Dockerfile` ...):
  install hooks, dependencies.
- **text** (`.md .txt .json .yaml`): prompt injection, hardcoded credentials.
- **any**: hardcoded credentials apply in any file.

Dangerous commands that appear only as EXAMPLES in documentation (`.md`) do not
count, because code rules are not applied to text files.

## How to report to the user

Always include, briefly:
1. Score and band.
2. Recommended action (one line).
3. Top findings by severity (CRITICAL and HIGH first).
4. Auto-execution points to review manually.
5. A reminder of the limits of static analysis.
