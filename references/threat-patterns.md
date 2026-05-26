# Threat Patterns - repo-scan

Reference for the detection rules. Read this when you need to explain a specific
finding or to adjust/extend the scanner.

Each rule has: id, category, base severity, scope (where it applies), and the
reason it exists. Base severity is before test/tmp downgrades.

## Network & Exfiltration

- **NET_PIPE_SHELL** (CRITICAL, code) - `curl ... | bash` or `wget ... | sh`.
  Downloads and executes remote code without review. Classic malicious-installer
  and supply-chain compromise vector.
- **NET_OUTBOUND** (HIGH, code) - curl/wget/netcat, `requests.get/post`,
  `urllib.request`, `fetch('https://...')`, `Invoke-WebRequest`. Any network
  egress in a tool script can exfiltrate data or pull a payload. The destination
  must be inspected.
- **NET_RAW_SOCKET** (HIGH, code) - `socket.socket`, `net.connect`, `new Socket`.
  Raw network connections are rare in legitimate skill tooling.
- **NET_BIND_ALL** (MEDIUM, code) - server binding to `0.0.0.0`. Exposes the
  service to the whole network. Acceptable if opt-in via a flag; a risk if it is
  the default.

## Dynamic Execution

- **EXEC_DYNAMIC** (HIGH, code) - `eval(`, `exec(`, `new Function(`,
  `os.system(`. Uses a lookbehind so it does NOT match methods like
  `regex.exec()`. Dynamic execution is dangerous when the input comes from an
  external source (command injection).
- **EXEC_SUBPROCESS** (MEDIUM, code) - `subprocess.run/Popen`, `child_process`,
  `execSync`, `spawn`, `popen`. Common and legitimate in build tooling; the risk
  is in commands assembled from external input (vs. a fixed literal command).
- **OBF_BASE64_EXEC** (CRITICAL, code) - base64 decode (`base64 -d`, `atob`,
  `b64decode`) feeding execution (`| sh`, `eval`, `node`). Payload obfuscation:
  a strong malware indicator.
- **OBF_HEX_ESCAPE** (MEDIUM, code) - 12+ consecutive `\xNN` or `\uNNNN` escapes.
  Long obfuscated strings deserve inspection of what they decode to.
- **EXEC_DOWNLOAD_RUN** (CRITICAL, code) - downloads a `.sh/.py/.js/.exe/.bin`
  and runs it right after (chmod + ./, node, python). Download-and-execute.

## Secrets & Credentials

- **SECRET_FILES** (HIGH, code) - access to `~/.ssh`, `id_rsa`,
  `.aws/credentials`, `.netrc`, `known_hosts`, `authorized_keys`. Reading the
  user's keys is highly suspicious in a skill.
- **SECRET_ENV** (LOW, code) - references to sensitive env vars (`API_KEY`,
  `CLIENT_SECRET`, `PRIVATE_KEY`, `AWS_SECRET`). Low on its own; dangerous when
  combined with NET_OUTBOUND (read + send = exfiltration).
- **SECRET_HARDCODED** (HIGH, any) - an apparent embedded key (`sk-...`,
  `ghp_...`, `xox...`, `AKIA...`, a PRIVATE KEY block). A leaked credential in the
  repo; treat the repo as untrustworthy.

## Install Hooks

- **INSTALL_HOOK_NPM** (HIGH, manifest) - `"preinstall"/"postinstall"/"prepare"`
  in package.json. These run automatically on `npm install`, before any use. Read
  exactly what they execute.
- **INSTALL_SETUPPY** (MEDIUM, manifest) - `cmdclass`, `os.system`, subprocess in
  setup.py. Custom install behavior in Python packages.

## Persistence

- **PERSIST_CRON** (HIGH, code) - `crontab`, `/etc/cron`, `launchctl`,
  `systemctl enable`, `LaunchAgents`, `reg add`, `schtasks`. Creates recurring or
  persistent execution. Very unusual in legitimate skills.
- **PERSIST_RC** (MEDIUM, code) - writes to `.bashrc/.zshrc/.profile`. Injects
  permanent behavior into the user's shell.

## Filesystem

- **FS_DESTRUCTIVE** (HIGH, code) - `rm -rf ~`, `rm -rf $VAR`, `shutil.rmtree`,
  `del /s`, `format c:`. Downgraded when the target is `/tmp` (legitimate
  cleanup).
- **FS_CHMOD_777** (LOW, code) - 777 / a+rwx permissions. Poor hygiene; low risk
  in isolation.

## Prompt Injection (Skill)

Specific to skills/agents: the skill's text content tries to manipulate the agent
that uses it.

- **PI_OVERRIDE** (HIGH, text) - "ignore previous instructions", "disregard
  system prompt", "do not tell the user", "hide this from the user". An attempt
  to override the system or hide actions from the user. Honest skills never ask
  to keep secrets from the user.
- **PI_EXFIL_INSTRUCTION** (CRITICAL, text) - text instructing the agent to SEND
  sensitive data (env, secret, token, `.ssh`, file contents, conversation) to an
  external destination (http, webhook, @). The regex requires a sensitive-data
  term to be present to reduce false positives.
- **PI_FORCED_TOOL** (MEDIUM, text) - "always run X without asking",
  "auto-approve", "automatically". Removes human oversight over sensitive
  actions.

## Dependencies

- **DEP_GIT_URL** (MEDIUM, manifest) - dependency pointing at an arbitrary git URL
  (`git+https`, `github:owner/repo#`). Bypasses the registry and can change; pin a
  commit and review the source.
- **DEP_HTTP_INSTALL** (MEDIUM, manifest) - dependency installed from a file URL
  (`.tar.gz/.tgz/.zip/.whl`). Bypasses registry verification.

## Auto-execution points (flagged separately)

Independently of the rules above, the scanner lists files that may run
automatically: `hooks.json`, `plugin.json`, `marketplace.json`, `package.json`,
`setup.py`, `pyproject.toml`, `Dockerfile`, `Makefile`, and any file with "hook"
in its path. These are review priorities even when no rule fires, because they
run before or at install/session time.

## Extending the scanner

To add a rule, edit `RULES` in `scripts/scan_repo.py`:

```python
dict(id="MY_RULE", cat="Category", sev="HIGH", scope="code",
     rx=r"your regex",
     desc="what it is",
     rec="what to do")
```

Valid scopes: `code`, `manifest`, `text`, `any`. Always test against a known-clean
repo (expect a high score) AND a known-malicious repo (expect a low score) before
trusting the result.
