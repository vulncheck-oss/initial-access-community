End-to-end fixtures for the rule lint. The rule files are stored as
`*.rule.txt` so the repository's SID tooling (`reassign_sids.py`,
`test-names-and-sid.yml`) never mistakes them for feed rules; the tests copy
this directory to a temporary feed and drop the `.txt`.

- `cve-0000-0001` passes every check.
- `cve-0000-0002` breaks many of them.
