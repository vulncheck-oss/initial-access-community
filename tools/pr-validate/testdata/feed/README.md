End-to-end fixtures for the rule lint and the shell-evidence checks. The rule
files are stored as `*.rule.txt` so the repository's SID tooling
(`reassign_sids.py`, `test-names-and-sid.yml`) never mistakes them for feed
rules; the tests copy this directory to a temporary feed and drop the `.txt`.

- `cve-0000-0001` passes every rule check.
- `cve-0000-0002` breaks many of them.
- `cve-0000-0003` is a reverse-shell exploit entry that passes every check.
  The tests write its `00-exploited-unencrypted.pcap` (a synthetic capture
  holding the exploit request and the shell's callback) into the temporary
  copy, so no capture is committed.
- `cve-0000-0004` is a reverse-shell exploit entry that fails each
  shell-evidence check: its README documents a listener its run command did
  not ask for and its Dockerfile copies `*.go`. The tests add a
  `reverse_shell.go` symlink out of the entry.
