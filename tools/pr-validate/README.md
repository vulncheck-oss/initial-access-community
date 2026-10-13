# pr-validate

The pull request validator for feed entries. It checks each entry's README frontmatter against its files, the target `docker-compose.yml`, the pcaps, the `go.mod` module path and the IDS rule files. This document covers the rule files.

`.github/workflows/pr-gate.yml` runs it on every entry a PR touches, inside the ia-feed-builder image, which has Suricata and Snort:

```sh
cd tools/pr-validate
go run . -dir ../../feed/ -base-ref HEAD~1 -entry-id cve-2026-0001
```

In CI, HEAD is the PR merge commit, so `HEAD~1` is the base branch. To run it locally, compare with the branch you will merge into, and skip the pcap replay unless both engines are installed:

```sh
go run . -dir ../../feed/ -offline -skip-rule-match -base-ref origin/main -entry-id cve-2026-0001
```

Findings are logged as `ERROR: <ENTRY> - <message>` or `WARN: <ENTRY> - <message>`. Rule findings end in `[<check-id>]` and start with the file's `path:line:column`. Any error fails the run.

## Flags

| Flag | Default | Use |
|---|---|---|
| `-dir` | `./feed` | the feed directory |
| `-entry-id` | all entries | an entry to validate; repeatable |
| `-offline` | false | skip the online Docker image platform check |
| `-skip-rule-match` | false | skip replaying the pcaps through Suricata and Snort |
| `-base-ref` | none | git ref to compare rule SIDs with (`vc-sid-preserved`) |
| `-fix-rules` | false | rewrite the entries' rule files with every autofix applied first (local use; pass `-entry-id`, or every entry's rules are rewritten) |
| `-snort-etc`, `-snort-lib`, `-suricata-config` | CI image paths | engine paths for the replay |

## Rule files

The `*.suricata.rule` and `*.snort.rule` files of an entry, including sub-packages, are checked in three ways:
- **Linting:** by [idsrule](https://github.com/zeroSteiner/idsrule) and by the VulnCheck checks in `rulecheck.go`. Together they enforce the mechanically checkable parts of the vc-iai `style-rules` skill. Snort/Suricata parity (§4), `flowbits:noalert` (§3) and the buffer and technique choices (§14, §16) still need a reviewer.
- **Replay (`rule-pcap-match`):** every `*-unencrypted.pcap` or `*-unencrypted.pcapng` in a rule file's directory must make every rule file in that directory alert. A directory with rules but no such capture only warns.
- **Frontmatter:** the README flags `suricataRule` and `snortRule` must match the files.

### Fixing a failing entry

Touching any file of an entry, even only its README, lints all of its rules. Most older entries predate these checks, so expect to update their rules too:

1. Run `go run . -dir ../../feed/ -offline -skip-rule-match -fix-rules -entry-id <id>`. This fixes:
   - indentation, spacing, trailing whitespace, the final newline and concatenated rules;
   - Snort 3 style `content:"x", depth 4` modifiers;
   - URI path depths.
2. Fix the rest by hand. The usual findings are:
   - `vc-msg-format`: the CVE right after `VULNCHECK`, and an ` Attempt` or ` Success` ending.
   - Capture groups, which become `(?:...)`.
   - Snort pcre buffer flags.
   - One option per line.
   - Flowbit names.
3. Keep each rule's SID when you edit or rename it. Keep the msg and SID of the Snort and Suricata twins in step.
4. If a rule is deployed with `SSLDecrypt` but the entry has no encrypted capture, either add `00-exploited-encrypted.pcap` or correct `targetEncryptedComms` and the rules' deployment metadata to match.

### idsrule checks

idsrule's generic checks cover:
- syntax, header and keyword validity;
- deprecated or wrong-dialect keywords;
- msg, sid and rev presence, plus duplicate msgs and SIDs (SIDs are checked across the whole feed);
- a `depth` or `within` shorter than its content, which can never match (`content-depth-too-short`);
- style: the four-space continuation indent, spacing, trailing whitespace, the final newline, and one rule per line.

Policy:
- **SIDs:** real SIDs must lie in 12,700,001 to 12,800,001. Placeholders below 12,700,000 (`sid:1`, `sid:2`, ...) are what new rules use; the reassign-sids workflow replaces them after merge.
- **msg prefix:** `VULNCHECK `.
- **Severity:** every finding is an error except `keyword-unknown`, `sticky-buffer-empty` and `value-unescaped-quote`, which are warnings.

### VulnCheck checks

| Check | Level | Rule (style-rules §) |
|---|---|---|
| `vc-msg-format` | error | msg ends in ` Attempt` or ` Success`; a CVE, if any, comes right after `VULNCHECK` (§2) |
| `vc-msg-first` | error | msg is the first option (§12) |
| `vc-reference-cve` | error | the msg's CVE has a `reference:cve,CVE-…`, and cve references are well formed |
| `vc-classtype` | error | classtype present and allowed (§11, plus `targeted-activity`) |
| `vc-classtype-admin` | warning | `attempted-admin`/`successful-admin` must be privilege escalation (§11) |
| `vc-flowbits-name` | error | flowbits are named `vc-cve-YYYY-NNNNN`, optionally with a `-stage` suffix (§1) |
| `vc-flowbits-unset` | error | a tested flowbit is set in the same file (§1) |
| `vc-success-impact` | error | Success rules end their metadata with `impact successful-exploitation`, and only they carry it (§5) |
| `vc-success-direction` | error | `impact successful-exploitation` sits on a rule matching the server response (§5) |
| `vc-no-comments` | error | no comments in rule files (§8) |
| `vc-option-per-line` | error | options start on the line after the header, one per line; a content or pcre keeps its modifiers, a sticky buffer may share its line with its first match, and sid shares a line with rev (§12) |
| `vc-sid-rev-line` | error | sid and rev share a line (§12) |
| `vc-sid-placeholder-sequence` | warning | placeholders run `sid:1`, `sid:2`, ...; a repeated placeholder is an error (§6) |
| `vc-no-fast-pattern` | error | no `fast_pattern` (§10) |
| `vc-pcre-buffer-flag` | error | Suricata pcre does not pick its buffer with a flag (§9) |
| `vc-snort-pcre-flag` | error | Snort `http_*` modifiers do not follow a pcre; use the pcre flag (§13) |
| `vc-pcre-anchor` | error | every pcre has a content in its buffer before it (§13) |
| `vc-pcre-capture-group` | error | no capture groups, unless a backreference needs them (§13) |
| `vc-pcre-trailing` | error | a pcre does not end in `.*`, `.+`, a quantified class such as `[^&]*`, or `$` (§13) |
| `vc-pcre-fixed-string` | error | a fixed string is a content, not a pcre (§13) |
| `vc-pcre-dotstar` | warning | prefer a bounded class to `.*` or `.+` (§15) |
| `vc-nocase-case-sensitive` | warning | no `nocase` on HTTP methods or the URI path (§17) |
| `vc-uri-path-anchor` | warning | the URI path (the first `http.uri` content, when it starts with `/`) is anchored with `startswith` (Suricata) or `depth` (Snort) (§15) |
| `vc-uri-path-depth` | error | the path anchor's `depth` equals the decoded path length (autofixable) and it has no nonzero `offset` (§15). On the path anchor it replaces idsrule's `content-depth-too-short` |
| `vc-tcp-unbounded-content` | warning | raw tcp/udp/ip content is bounded by a buffer, offset/depth or distance/within, unless the rule has `isdataat`, `bsize` or `dsize` (§18) |
| `vc-snort-put-body` | warning | Snort `http_client_body` is not used for PUT bodies |
| `vc-deployment-metadata` | error | deployment metadata matches `targetEncryptedComms`, which must be set (§7): `either` → Datacenter and SSLDecrypt, `no` → Datacenter, `yes` → SSLDecrypt |
| `vc-encrypted-pcap` | error | a rule deployed with SSLDecrypt has an encrypted capture (`NN-exploited-encrypted.pcap` or `NN-exploit-attempt-encrypted.pcap`, or `.pcapng`) beside it (§7) |
| `vc-sid-preserved` | error | with `-base-ref`: a rule that CI assigned a SID keeps it, and real SIDs are never invented (§6) |

## Tests

```sh
go vet ./... && go test ./...
```

`.github/workflows/pr-validate-tests.yml` runs them on PRs that change this tool. The rule-lint fixtures under `testdata/feed` are described in [its README](testdata/feed/README.md).
