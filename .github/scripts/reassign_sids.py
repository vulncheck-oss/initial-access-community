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
"""

from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path

SID_PATTERN = re.compile(r'\bsid\s*:\s*(\d+)\s*;')
MSG_PATTERN = re.compile(r'\bmsg\s*:\s*"([^"]+)"')
SID_RANGE_START = 12_900_000  # SIDs below this are treated as unassigned


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
    return counter


def save_counter(sid_file: Path, value: int) -> None:
    sid_file.write_text(str(value) + '\n')


# ---------------------------------------------------------------------------
# Rule parsing
# ---------------------------------------------------------------------------

def normalise_msg(msg: str) -> str:
    return re.sub(r'\s+', ' ', msg).strip().lower()


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

    # Rules needing a SID are those with any SID below the managed range.
    # Map msg_norm -> entry reference so each distinct rule is tracked individually.
    def is_unassigned(sid: str | None) -> bool:
        return sid is not None and int(sid) < SID_RANGE_START

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
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Assign SIDs to new (sid:0) Suricata/Snort rules.')
    parser.add_argument('--sid-file', type=Path, default=Path('.sid_counter'),
                        help='Persistent SID counter file (default: .sid_counter)')
    parser.add_argument('--changed-files', nargs='+', type=Path, required=True,
                        help='The specific rule files changed in this push')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would change without writing files or updating the counter')
    args = parser.parse_args()

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