#!/usr/bin/env bash
# regen.sh -- (re)generate the `goexploit:` YAML block in one or more exploit READMEs.
#
# For each exploit directory passed as an argument it builds the exploit binary
# (`make exploit`) and pipes the binary's `--details --log-json` output to the
# goexploit-meta tool, which updates the README.md front-matter in place. This is a
# standalone driver: it does NOT require a per-Makefile `meta:` target.
#
#   tools/meta-generation/regen.sh feed/cve-2017-12617               # one dir
#   tools/meta-generation/regen.sh feed/*                            # the whole feed
#   tools/meta-generation/regen.sh --keep-going feed/*               # exit 0 even if some fail
#
# Runs continue on failure; a summary is printed. By default a non-zero exit reports any
# directory that failed to build or introspect; pass --keep-going to exit 0 anyway (used by
# CI so one un-introspectable exploit -- e.g. a Windows-only build that can't run on the
# Linux runner -- doesn't block syncing the others). Directories that aren't exploits (no
# Makefile or no matching <name>.go) are skipped.
set -uo pipefail

keep_going=0
if [ "${1:-}" = "--keep-going" ]; then keep_going=1; shift; fi

tool_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
goos="$(go env GOOS)"
goarch="$(go env GOARCH)"

# Build the meta tool ONCE and reuse it (vs. `go run .` per directory, which would
# recompile it hundreds of times during a bulk run).
tool_bin="$(mktemp)"
trap 'rm -f "$tool_bin"' EXIT
echo "[*] building goexploit-meta ..."
( cd "$tool_dir" && go build -o "$tool_bin" . ) || { echo "[!] failed to build goexploit-meta" >&2; exit 1; }

ok=0
skip=0
fail=0
failed=()

for dir in "$@"; do
  dir="${dir%/}"
  [ -d "$dir" ] || { echo "skip (not a dir): $dir"; skip=$((skip + 1)); continue; }
  [ -f "$dir/Makefile" ] || { echo "skip (no Makefile): $dir"; skip=$((skip + 1)); continue; }
  # Detect an exploit by its source file, matching the Makefile's exploit_files wildcard
  # (cve-*.go / vc-*.go). The file isn't always named after the dir -- e.g. dual-assigned
  # CVEs like cve-2025-31161/ ship cve-2025-2825.go -- so glob the prefixes, don't assume.
  if ! compgen -G "$dir/cve-*.go" >/dev/null 2>&1 && ! compgen -G "$dir/vc-*.go" >/dev/null 2>&1; then
    echo "skip (no exploit source): $dir"; skip=$((skip + 1)); continue
  fi

  echo "==> $dir"
  # Some exploits embed a generated asset (e.g. `javac Abcdefg.java` -> Abcdefg.class) via
  # a `java:` prerequisite that the `exploit` target does not pull in. Run it first when
  # present (needs a JDK on PATH); harmless if it no-ops.
  if grep -qE '^java:' "$dir/Makefile"; then
    make -C "$dir" java >/dev/null 2>&1 || true
  fi
  if ! make -C "$dir" exploit >/dev/null 2>&1; then
    echo "  build failed"; fail=$((fail + 1)); failed+=("$dir"); continue
  fi

  readme="$(cd "$dir" && pwd)/README.md"

  # Candidate binaries: prefer the host os/arch, then any other built binary. A
  # Makefile may force a non-host target -- amd64 runs under qemu on an arm64 host (and
  # is native on the amd64 CI), while windows/other targets that can't exec here are
  # tried and skipped. `--details` only prints static metadata, so no live target needed.
  shopt -s nullglob
  host_bins=( "$dir"/build/*_"${goos}-${goarch}" "$dir"/build/*_"${goos}-${goarch}".exe )
  rest_bins=( "$dir"/build/* )
  shopt -u nullglob
  candidates=()
  for b in "${host_bins[@]}" "${rest_bins[@]}"; do
    [ -f "$b" ] || continue
    case " ${candidates[*]} " in *" $b "*) ;; *) candidates+=("$b") ;; esac
  done
  if [ "${#candidates[@]}" -eq 0 ]; then
    echo "  no built binary in $dir/build"; fail=$((fail + 1)); failed+=("$dir"); continue
  fi

  # Use the first binary that actually runs and emits exploit details.
  dir_ok=0
  for bin in "${candidates[@]}"; do
    details="$("$bin" --details --log-json 2>/dev/null)" || continue
    printf '%s\n' "$details" | grep -qi '"ExploitType"' || continue
    if printf '%s\n' "$details" | "$tool_bin" -readme "$readme"; then dir_ok=1; break; fi
  done
  if [ "$dir_ok" -eq 1 ]; then
    ok=$((ok + 1))
  else
    echo "  meta update failed (no runnable binary emitted details)"; fail=$((fail + 1)); failed+=("$dir")
  fi
done

echo
echo "meta: $ok ok, $skip skipped, $fail failed"
if ((fail > 0)); then
  printf '  failed: %s\n' "${failed[@]}"
  [ "$keep_going" -eq 1 ] || exit 1
fi
