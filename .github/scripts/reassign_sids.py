#!/usr/bin/env python3
"""
reassign_sids.py

Assigns SIDs to new rules in <name>.suricata.rule / <name>.snort.rule files.

Rules are matched across file pairs by their msg: field (case-insensitive,
whitespace-normalised). Any rule whose SID is below SID_RANGE_START (12900000)
is treated as unassigned and will receive a new SID. Rules with a valid
in-range SID are never modified.

Pairing behaviour:
  - Both files changed: paired rules share one SID, unpaired get their own.
  - One file changed: if the unchanged partner has a valid in-range SID for
    the same msg, that SID is reused. Otherwise a new SID is allocated.
  - No partner file: SIDs are assigned independently.

Rules span multiple lines using backslash continuation and are parsed as
logical units before field extraction.

Counter file (.sid_counter):
  A single integer — the last SID assigned by this script.
  Must be >= SID_RANGE_START. Seed with your current highest SID, e.g:
    echo "12900000" > .sid_counter

Usage:
    python reassign_sids.py --sid-file .sid_counter --changed-files f1 [f2 ...]
    python reassign_sids.py --sid-file .sid_counter --changed-files f1 --dry-run

    # Print every rule file in the tree that still holds a placeholder SID.
    # This is what the push-time workflow feeds back into --changed-files, and
    # what the PR gate asserts is empty after a dry assignment.
    python reassign_sids.py --list-placeholder-files

    # Validate without writing anything: lint the PR's changed rule files, then
    # dry-run the assignment the push job will perform. Used by the PR gate.
    python reassign_sids.py --check --sid-file .sid_counter --changed-files f1 [f2 ...]
"""

from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path

SID_PATTERN = re.compile(r'\bsid\s*:\s*(\d+)\s*;')
MSG_PATTERN = re.compile(r'\bmsg\s*:\s*"([^"]+)"')
SID_RANGE_START = 12_900_000  # SIDs below this are treated as unassigned
# Upper bound of VulnCheck's allocated SID block. Mirrors sidMax in
# vulncheck/ia-feed sid_test.go, which fails the feed build for any SID outside
# [12700001, 12800001]. Keep the two in sync: this is the copy that gets to
# refuse an assignment, the other one only gets to complain after the merge.
SID_RANGE_END = 12_800_001

RULE_SUFFIXES = ('.suricata.rule', '.snort.rule')


# ---------------------------------------------------------------------------
# Counter helpers
# ---------------------------------------------------------------------------

def load_counter(sid_file: Path) -> int:
    if not sid_file.exists():
        print(
            f"Error: counter file '{sid_file}' not found.\n"
            f"Create it with your current highest SID before running, e.g.:\n"
            f"  echo '12900000' > {sid_file}",
            file=sys.stderr,
        )
        sys.exit(1)
    text = sid_file.read_text().strip()
    if not text.isdigit():
        print(f"Error: {sid_file} should contain a single integer.", file=sys.stderr)
        sys.exit(1)
    counter = int(text)
    if counter < SID_RANGE_START:
        print(
            f"Error: counter value {counter} in '{sid_file}' is below the managed "
            f"range ({SID_RANGE_START}+). Update the file with your current highest SID.",
            file=sys.stderr,
        )
        sys.exit(1)
    if counter >= SID_RANGE_END:
        print(
            f"Error: counter value {counter} in '{sid_file}' has reached the end of "
            f"the allocated range ({SID_RANGE_END}). No further SIDs can be assigned "
            f"until VulnCheck is allocated a new block.",
            file=sys.stderr,
        )
        sys.exit(1)
    return counter


def save_counter(sid_file: Path, value: int) -> None:
    sid_file.write_text(str(value) + '\n')


# ---------------------------------------------------------------------------
# Rule parsing
# ---------------------------------------------------------------------------

def normalise_msg(msg: str) -> str:
    return re.sub(r'\s+', ' ', msg).strip().lower()


def is_rule(entry: dict) -> bool:
    """A parsed entry that is an actual rule, not a comment or a blank line."""
    return not entry['comment'] and bool(''.join(entry['lines']).strip())


def is_unassigned(sid: str | None) -> bool:
    """True for a placeholder SID -- sid:1, sid:2, ... -- that needs assigning."""
    return sid is not None and int(sid) < SID_RANGE_START


def parse_rules(path: Path) -> list[dict]:
    # Rules may span multiple lines via backslash continuation.
    # Join them into logical rules before extracting fields.
    raw_lines = path.read_text().splitlines(keepends=True)
    entries = []
    i = 0
    while i < len(raw_lines):
        line = raw_lines[i]
        comment = line.lstrip().startswith('#')
        if comment:
            entries.append({'start': i, 'lines': [line], 'comment': True,
                            'sid': None, 'msg': None, 'msg_norm': None})
            i += 1
            continue
        # Collect continuation lines
        logical = line
        raw = [line]
        while logical.rstrip('\n').rstrip().endswith('\\') and i + 1 < len(raw_lines):
            i += 1
            next_line = raw_lines[i]
            raw.append(next_line)
            logical += next_line
        sid_m = SID_PATTERN.search(logical)
        msg_m = MSG_PATTERN.search(logical)
        msg_raw = msg_m.group(1) if msg_m else None
        entries.append({
            'start':    i - len(raw) + 1,
            'lines':    raw,
            'comment':  False,
            'sid':      sid_m.group(1) if sid_m else None,
            'msg':      msg_raw,
            'msg_norm': normalise_msg(msg_raw) if msg_raw else None,
        })
        i += 1
    return entries



def discover_placeholder_files(root: Path = Path('.')) -> list[Path]:
    """Every rule file under `root` that still holds at least one placeholder SID.

    This is the single definition of "needs a SID". The push workflow used to
    carry its own `grep -lE 'sid:[0-9]{1,7};'` copy of it, which disagreed with
    SID_PATTERN over whitespace: a rule written `sid: 1;` was a placeholder to
    this script but invisible to the grep, so the file was never passed in and
    the placeholder rode the merge through to ia-feed. Both callers go through
    here now so the two can no longer drift apart.
    """
    found = []
    for path in sorted(root.rglob('*.rule')):
        if not path.name.endswith(RULE_SUFFIXES):
            continue
        if any(is_unassigned(e['sid']) for e in parse_rules(path) if is_rule(e)):
            found.append(path)
    return found


def check_duplicates(entries: list[dict], path: Path) -> list[str]:
    seen: dict[str, int] = {}
    errors = []
    for e in entries:
        if e['comment'] or e['msg_norm'] is None:
            continue
        ln = e['start'] + 1
        if e['msg_norm'] in seen:
            errors.append(
                f"  {path}: duplicate msg \"{e['msg']}\" "
                f"on lines {seen[e['msg_norm']]} and {ln}"
            )
        else:
            seen[e['msg_norm']] = ln
    return errors


def rebuild(entries: list[dict], entry_sid_map: dict[int, int]) -> str:
    out = []
    for i, e in enumerate(entries):
        if i not in entry_sid_map:
            out.extend(e['lines'])
        else:
            # Apply SID replacement across all lines of this logical rule
            new_sid = entry_sid_map[i]
            rewritten = ''.join(e['lines'])
            rewritten = SID_PATTERN.sub(f'sid:{new_sid};', rewritten)
            out.append(rewritten)
    return ''.join(out)


def msg_to_sid(entries: list[dict]) -> dict[str, int]:
    """msg_norm -> current sid int for an unchanged partner file."""
    return {
        e['msg_norm']: int(e['sid'])
        for e in entries
        if not e['comment'] and e['msg_norm'] and e['sid']
    }


# ---------------------------------------------------------------------------
# Directory processor
# ---------------------------------------------------------------------------

def process_dir(
    rule_dir: Path,
    changed: dict[str, Path],   # 'suricata' | 'snort' -> actual file path
    counter: int,
    dry_run: bool = False,
) -> int:
    """
    Assigns SIDs to rules with sid:0 in the changed file(s).
    Returns the updated counter value.
    """
    sur_changed   = 'suricata' in changed
    snort_changed = 'snort'    in changed

    # Use the changed file path directly; glob for the partner if it exists
    suricata = changed.get('suricata') or next(rule_dir.glob('*.suricata.rule'), None)
    snort    = changed.get('snort')    or next(rule_dir.glob('*.snort.rule'),    None)

    sur_entries   = parse_rules(suricata) if suricata and suricata.exists() else []
    snort_entries = parse_rules(snort)    if snort    and snort.exists()    else []

    # Duplicate check only on changed files
    errors = []
    if sur_changed:
        errors.extend(check_duplicates(sur_entries, suricata))
    if snort_changed:
        errors.extend(check_duplicates(snort_entries, snort))
    if errors:
        print("ERROR: duplicate msg fields detected:", file=sys.stderr)
        for e in errors:
            print(e, file=sys.stderr)
        sys.exit(1)

    # A placeholder rule is keyed by its msg: below, so a rule that has no msg:
    # collides with every other msg-less rule in the same file under the key
    # None -- the last one wins and the rest silently keep their sid:1. Refuse
    # instead of dropping them on the floor.
    unpairable = []
    for entries, path, changed in ((sur_entries, suricata, sur_changed),
                                   (snort_entries, snort, snort_changed)):
        if not changed:
            continue
        for e in entries:
            if is_rule(e) and is_unassigned(e['sid']) and e['msg_norm'] is None:
                unpairable.append(
                    f"  {path}:{e['start'] + 1}: rule has sid:{e['sid']} but no msg: "
                    f"field, so it cannot be matched to its partner rule"
                )
    if unpairable:
        print("ERROR: placeholder rules with no msg: field:", file=sys.stderr)
        for u in unpairable:
            print(u, file=sys.stderr)
        sys.exit(1)

    # Rules needing a SID are those with any SID below the managed range.
    # Map msg_norm -> entry reference so each distinct rule is tracked individually.
    sur_new   = {e['msg_norm']: (i, e) for i, e in enumerate(sur_entries)   if sur_changed   and is_unassigned(e['sid'])}
    snort_new = {e['msg_norm']: (i, e) for i, e in enumerate(snort_entries) if snort_changed and is_unassigned(e['sid'])}

    all_new_msgs = sorted(set(sur_new) | set(snort_new))

    if not all_new_msgs:
        print(f"  {rule_dir}: no unassigned SIDs (< {SID_RANGE_START}) found, skipping")
        return counter

    # Build existing SID maps from both files, excluding rules that are
    # about to be rewritten. This ensures a new rule in one file can reuse
    # an already-assigned in-range SID from its partner even if both files
    # were touched in the same push.
    def existing_sids(entries: list[dict], new_msgs: dict) -> dict[str, int]:
        return {
            e['msg_norm']: int(e['sid'])
            for e in entries
            if not e['comment']
            and e['msg_norm']
            and e['sid']
            and e['msg_norm'] not in new_msgs
            and int(e['sid']) >= SID_RANGE_START
        }

    sur_existing   = existing_sids(sur_entries,   sur_new)
    snort_existing = existing_sids(snort_entries, snort_new)

    sur_sid_map:   dict[int, int] = {}  # entry_index -> new_sid
    snort_sid_map: dict[int, int] = {}  # entry_index -> new_sid

    for msg_norm in all_new_msgs:
        in_sur_new   = msg_norm in sur_new
        in_snort_new = msg_norm in snort_new

        partner_sid = sur_existing.get(msg_norm) or snort_existing.get(msg_norm)

        if partner_sid and partner_sid >= SID_RANGE_START:
            new_sid = partner_sid
            tag = "paired (reusing partner SID)"
        else:
            counter += 1
            if counter > SID_RANGE_END:
                print(
                    f"Error: assigning a SID for \"{msg_norm}\" would produce {counter}, "
                    f"past the end of the allocated range ({SID_RANGE_END}). ia-feed's "
                    f"sid_test.go rejects it. A new SID block is needed.",
                    file=sys.stderr,
                )
                sys.exit(1)
            new_sid = counter
            if in_sur_new and in_snort_new:
                tag = "paired (both changed)"
            else:
                tag = "suricata-only" if in_sur_new else "snort-only"

        if in_sur_new:
            entry_idx, _ = sur_new[msg_norm]
            sur_sid_map[entry_idx] = new_sid
        if in_snort_new:
            entry_idx, _ = snort_new[msg_norm]
            snort_sid_map[entry_idx] = new_sid

        print(f"  {new_sid}  [{tag}]  {msg_norm}")

    if dry_run:
        print("  [dry-run] no files written")
    else:
        if sur_changed and sur_sid_map:
            suricata.write_text(rebuild(sur_entries, sur_sid_map))
        if snort_changed and snort_sid_map:
            snort.write_text(rebuild(snort_entries, snort_sid_map))

    return counter


# ---------------------------------------------------------------------------
# Pre-merge validation
# ---------------------------------------------------------------------------

def lint_changed_files(paths: list[Path]) -> list[str]:
    """Per-rule checks on the rule files a PR touches.

    Everything here is something that, left alone, surfaces only after the merge
    -- either as a failed reassign-sids run on main (placeholders never get
    replaced) or as a red sid_test.go in ia-feed once the placeholder has been
    flattened into vulncheck.*.rules.
    """
    errors = []
    for path in paths:
        if not path.exists():           # deleted in the PR
            continue
        if not path.name.endswith(RULE_SUFFIXES):
            continue
        for e in parse_rules(path):
            if not is_rule(e):
                continue
            ln = e['start'] + 1
            if e['sid'] is None:
                errors.append(
                    f"  {path}:{ln}: rule has no sid: field. It will never be "
                    f"assigned one, and Suricata/Snort reject it in ia-feed."
                )
                continue
            sid = int(e['sid'])
            if is_unassigned(sid):
                if e['msg_norm'] is None:
                    errors.append(
                        f"  {path}:{ln}: placeholder sid:{sid} on a rule with no "
                        f"msg: field. reassign_sids.py pairs rules by msg:, so this "
                        f"one cannot be assigned a real SID."
                    )
                continue
            if sid > SID_RANGE_END:
                errors.append(
                    f"  {path}:{ln}: sid:{sid} is past the end of the allocated "
                    f"range [{SID_RANGE_START + 1}, {SID_RANGE_END}]. ia-feed's "
                    f"sid_test.go fails on it."
                )
    return errors


def run_check(changed: list[Path], sid_file: Path) -> None:
    """Assert a PR can be merged without breaking SID assignment downstream.

    Two phases, in the order the damage happens: lint what the PR changed, then
    dry-run the exact assignment reassign-sids.yml will perform on main.
    """
    print("== Phase 1: linting changed rule files ==")
    rule_files = [f for f in changed if f.name.endswith(RULE_SUFFIXES)]
    if not rule_files:
        print("  no rule files changed")
    else:
        for f in rule_files:
            print(f"  {f}")
    errors = lint_changed_files(rule_files)
    if errors:
        print("\nERROR: rule problems that block SID assignment:", file=sys.stderr)
        for e in errors:
            print(e, file=sys.stderr)
        sys.exit(1)
    print("  ok")

    # Duplicate msg: in a file that still holds a placeholder is fatal, and
    # phase 2 fails on it below -- that is the case that breaks assignment on
    # main. A duplicate in a file whose SIDs are all assigned breaks nothing
    # today, because reassign-sids.yml never passes such a file to
    # check_duplicates() either. It is still worth saying out loud: the next PR
    # that adds a placeholder SID to that file cannot be assigned until the
    # duplicate is gone, and existing_sids() pairs by msg, so the placeholder
    # could reuse the wrong partner SID. Warn rather than fail -- ~54 files in
    # the corpus carry intentional duplicate msgs (the HTTP/HTTPS rule
    # variants), and blocking an unrelated edit to one of them helps nobody.
    warnings = []
    for path in rule_files:
        if not path.exists() or not path.name.endswith(RULE_SUFFIXES):
            continue
        entries = parse_rules(path)
        if any(is_unassigned(e['sid']) for e in entries if is_rule(e)):
            continue
        warnings.extend(check_duplicates(entries, path))
    if warnings:
        print("\nWARNING: duplicate msg fields in files whose SIDs are already "
              "assigned. Nothing fails now, but a future placeholder SID in "
              "these files cannot be assigned until the duplicate is resolved:")
        for w in warnings:
            print(w)

    print("\n== Phase 2: dry-run of the post-merge SID assignment ==")
    placeholder_files = discover_placeholder_files()
    if not placeholder_files:
        print("  no placeholder SIDs anywhere in the tree, nothing to assign")
        return
    print("  files holding placeholder SIDs:")
    for f in placeholder_files:
        print(f"    {f}")

    # Same grouping and the same process_dir() the push job runs, so a duplicate
    # msg:, an un-pairable rule or an exhausted counter fails here with the
    # message it would have produced on main -- except here it blocks the merge.
    dirs: dict[Path, dict[str, Path]] = {}
    for f in placeholder_files:
        f = f.resolve()
        key = 'suricata' if f.name.endswith('.suricata.rule') else 'snort'
        dirs.setdefault(f.parent, {})[key] = f

    counter = load_counter(sid_file)
    for rule_dir in sorted(dirs):
        print(f"\nProcessing: {rule_dir}  (changed: {', '.join(sorted(dirs[rule_dir]))})")
        counter = process_dir(rule_dir, dirs[rule_dir], counter, dry_run=True)
    print(f"\nOK -- assignment would succeed, counter would land at {counter}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Assign SIDs to new (sid:0) Suricata/Snort rules.')
    parser.add_argument('--sid-file', type=Path, default=Path('.sid_counter'),
                        help='Persistent SID counter file (default: .sid_counter)')
    parser.add_argument('--changed-files', nargs='+', type=Path, default=[],
                        help='The specific rule files changed in this push')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would change without writing files or updating the counter')
    parser.add_argument('--list-placeholder-files', action='store_true',
                        help='Print every rule file still holding a placeholder SID, one per '
                             'line, and exit. Used by reassign-sids.yml to build --changed-files '
                             'and by the PR gate to assert none are left.')
    parser.add_argument('--check', action='store_true',
                        help='Validate only: lint --changed-files, then dry-run the assignment '
                             'the push job will perform. Writes nothing. Used by the PR gate.')
    args = parser.parse_args()

    # Keep stdout in step with stderr. Both land in the same CI log, and a
    # block of buffered progress output arriving after the error it led up to
    # makes the log hard to read.
    sys.stdout.reconfigure(line_buffering=True)

    if args.list_placeholder_files:
        for f in discover_placeholder_files():
            print(f)
        sys.exit(0)

    if args.check:
        run_check(args.changed_files, args.sid_file)
        sys.exit(0)

    if not args.changed_files:
        parser.error('--changed-files is required unless --check or '
                     '--list-placeholder-files is given')

    if args.dry_run:
        print("DRY-RUN mode — no files will be modified\n")

    # Group changed files by directory
    dirs: dict[Path, dict[str, Path]] = {}
    for f in args.changed_files:
        f = f.resolve()
        if f.name.endswith('.suricata.rule'):
            dirs.setdefault(f.parent, {})['suricata'] = f
        elif f.name.endswith('.snort.rule'):
            dirs.setdefault(f.parent, {})['snort'] = f
        else:
            print(f"Warning: unexpected filename {f.name}, skipping", file=sys.stderr)

    if not dirs:
        print("No recognised rule files in --changed-files.")
        sys.exit(0)

    counter = load_counter(args.sid_file)

    for rule_dir in sorted(dirs):
        print(f"\nProcessing: {rule_dir}  (changed: {', '.join(sorted(dirs[rule_dir]))})")
        counter = process_dir(rule_dir, dirs[rule_dir], counter, dry_run=args.dry_run)

    if args.dry_run:
        print("\nDRY-RUN — counter not saved, no files written")
    else:
        save_counter(args.sid_file, counter)
        print(f"\nCounter saved — next run starts at SID {counter + 1}")


if __name__ == '__main__':
    main()