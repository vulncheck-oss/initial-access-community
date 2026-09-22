"""
Runs various checks against the IA feed to look for common
inconsistencies that are found in IA PRs to streamline self-review
"""

import os
import subprocess
from pathlib import Path
import hashlib
import sys

errorset=0

if len(sys.argv) < 2:
    print(f"Error, usage: {sys.argv[0]} <feed dir path>")
    sys.exit(1)

# setup docker and makfile constants for use in dockercheck()
example_root = Path(sys.argv[1]) / ".." / "examples" # "
if example_root.exists() is False :
    print("failed to find example path")
    sys.exit(1)

DOCKERFILE_PATH = Path(example_root / "Dockerfile")
DOCKERFILE_V_PATH = Path(example_root / "Dockerfile.verification")
DOCKERFILE_D_PATH = Path(example_root / "Dockerfile.dropper")
DOCKERFILE_DV_PATH = Path(example_root / "Dockerfile.dropper.verification")

MAKEFILE_HASH = hashlib.md5(Path(example_root / "Makefile").read_bytes()).hexdigest()
MAKEFILE_V_HASH = hashlib.md5(Path(example_root / "Makefile.verification").read_bytes()).hexdigest()
MAKEFILE_D_HASH = hashlib.md5(Path(example_root / "Makefile.dropper").read_bytes()).hexdigest()
MAKEFILE_DV_HASH = hashlib.md5(
        Path(example_root / "Makefile.dropper.verification").read_bytes()).hexdigest()

def get_changed_dirs():
    base = os.environ.get("GITHUB_BASE_REF", "main")
    result = subprocess.run(
        ["git", "diff", "--name-only", f"origin/{base}...HEAD"],
        capture_output=True, text=True
    )
    paths = result.stdout.strip().splitlines()

    # Extract unique cve-* directories
    dirs = set()
    for p in paths:
        parts = p.split("/")
        # e.g., feed/2024/cve-2024-1234/README.md -> feed/2024/cve-2024-1234
        for i, part in enumerate(parts):
            if part.startswith("cve-"):
                dirs.add("/".join(parts[:i+1]))
                break
    return dirs


def dockercheck(fpath):
    """ checks for missing Dockerfile files that should correspond to an exploit """
    global errorset

    cve = fpath.name

    readme_path = fpath / "README.md"
    if not readme_path.exists():
        print(f"ERROR no README.md found for {fpath}")
        return

    if "exploit: false" in readme_path.read_text(): # filters out exploit: false
        return

    # filters out the chains
    if "chain: " in readme_path.read_text() and "chain: []" not in readme_path.read_text():
        return

    # ignoring the weird, almost empty READMEs in our feed that
    # exist for some reason, a problem for later
    if len(readme_path.read_text().splitlines()) < 5:
        return

    if len(list(fpath.rglob("Dockerfile"))) == 0:
        print(f"ERROR: no Dockerfile found for {cve} in {fpath}")
        errorset = 1


root = Path(sys.argv[1])
if os.environ.get("GITHUB_ACTIONS"): # MUST be run from root of the repo or this will fail
    dirs_to_check = get_changed_dirs()
else:
    dirs_to_check = root.glob("cve*")

for dir_to_check in dirs_to_check:
    if "cve-" not in str(dir_to_check):
        continue
    if os.environ.get("GITHUB_ACTIONS"): # MUST be run from root of the repo or this will fail
        print("[GITHUB_ACTIONS] Checking", dir_to_check)
    fpath = Path(dir_to_check)

    dockercheck(fpath)

print("RUN COMPLETE - ERRORS FOUND:", str(bool(errorset)).upper())
sys.exit(errorset)
