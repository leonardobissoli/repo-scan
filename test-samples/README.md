# test-samples

Inert fixtures consumed by `tests/run_tests.py`.

These files are **read as text** by the static scanner. They are never executed
by the test suite, by CI, or by any part of `repo-scan`. The `malicious/`
samples use the reserved `.invalid` TLD (RFC 2606) and contain no working
payloads - the strings are crafted to match detection rules, nothing more.

## Layout

- `clean/` - benign sample tree. Expected verdict: **SAFE** or **LOW RISK**
  (score >= 70).
- `malicious/` - synthetic sample tree exercising the high-signal rules
  (curl|bash, base64+exec, install hooks, prompt injection, SSH key reads,
  outbound network). Expected verdict: **HIGH RISK** or **CRITICAL**
  (score <= 39).

The runner asserts both bands and the presence of the expected `rule_id`s. If
you change a fixture intentionally, update `tests/run_tests.py` accordingly.

## Why these files are safe to ship

- No shebangs, no executable bits, no install hooks that any tool would honor
  in this repository (the `package.json` and `setup.py` here are not at the
  repo root - they are nested under `test-samples/malicious/`).
- Network destinations use `.invalid` so DNS resolution is guaranteed to fail.
- The "credentials" referenced are paths (`~/.ssh/id_rsa`), not embedded keys.
