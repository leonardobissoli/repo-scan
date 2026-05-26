# Repository Access & Security Policy

This repository is public **for transparency and read-only consultation**.

## Access policy

- **Pull requests are not accepted.** Any PR opened against this repository
  will be closed without review.
- **Issues are not accepted.** The Issues tab is disabled.
- **GitHub Actions, bots, and automated workflows are not run on this
  repository.**
- **Forks are permitted** (it is a public repository), but changes in a fork
  have no effect on the official codebase.
- **Only the repository owner** maintains the official source code.

## Reporting a security concern in `repo-scan` itself

If you believe you have found a vulnerability in the scanner's own code,
contact the owner privately via the contact channel listed on the owner's
GitHub profile. Public Issues are disabled and pull requests will not be
accepted - including for security fixes. The owner will evaluate the report
and, if valid, ship the fix in a normal release.

## Hardening notes about the scanner

- The scanner clones target repositories with `git clone --depth 1` into a
  temporary directory and removes it after the scan (unless `--keep` is
  passed).
- No network egress is performed other than the `git clone` of the target.
- The tool reads files as text and never imports or executes them.
