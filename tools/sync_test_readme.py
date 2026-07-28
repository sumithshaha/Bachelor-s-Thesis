#!/usr/bin/env python3
"""
sync_test_readme.py -- make tests/README.md agree with the suite it describes.

WHY THIS EXISTS
---------------
tests/test_suite_hygiene.py asserts that README.md's stated total and its
per-module table match what pytest actually collects. That is a good check: a
count nobody maintains is a count nobody can trust, and the table is the first
thing a reader of the thesis looks at to see what is covered.

The trouble is that keeping it true was a manual step, and a manual step tied to
a number that changes every time a test is added is a step that gets forgotten.
It has now been missed twice, each time surfacing as two red tests that have
nothing to do with the change that caused them -- the failure names README.md,
so it reads like a documentation problem when the code was fine all along.

This script removes the manual step. It asks pytest what exists and rewrites the
numbers to match. It does NOT invent prose: a module that has no row is
reported, not silently appended with a made-up description, because the
"Covers" column is the one part of that table a human has to write.

USAGE
-----
    python tools/sync_test_readme.py            # rewrite the numbers in place
    python tools/sync_test_readme.py --check    # report drift, change nothing

--check exits 1 when the file disagrees with the suite, so it can be used as a
pre-commit or CI gate rather than waiting for the hygiene tests to fail.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS = REPO_ROOT / "tests"
README = TESTS / "README.md"

ROW = re.compile(r"\|\s*`(test_[a-z0-9_]+\.py)`\s*\|\s*(\d+)\s*\|")
TOTAL = re.compile(r"\*\*(\d+) tests across (\d+) modules\.\*\*")
PASSED = re.compile(r"`(\d+) passed`")


def collected_counts() -> dict[str, int]:
    """{module: number of tests}, straight from pytest.

    Collection is the only authority here. Counting `def test_` in the files
    would be wrong for every parametrised test in the suite -- and most of the
    large modules are parametrised, so the answer would not be close.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(TESTS), "-q", "--collect-only"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=600,
    )
    counts: dict[str, int] = {}
    for line in proc.stdout.splitlines():
        if "::" not in line:
            continue
        # Windows reports paths with backslashes; take the last component
        # either way.
        module = line.split("::", 1)[0].replace("\\", "/").split("/")[-1]
        if module.startswith("test_") and module.endswith(".py"):
            counts[module] = counts.get(module, 0) + 1
    if not counts:
        sys.exit("pytest collected nothing -- is the suite runnable from here?\n"
                 + proc.stdout[-2000:] + proc.stderr[-2000:])
    return counts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="report drift without writing")
    ap.add_argument("--allow-shrink", action="store_true",
                    help="write a total LOWER than the one documented "
                         "(refused by default; see the note below)")
    ap.add_argument("--fix-location", action="store_true",
                    help="if this script is sitting in tests/, move it to "
                         "tools/ where it belongs, then exit")
    args = ap.parse_args()

    # THIS SCRIPT MUST LIVE IN tools/, NOT tests/.
    #
    # test_suite_hygiene.py parametrises a test over every non-test .py file in
    # tests/, so a helper sitting there is itself collected as a test. The
    # script whose whole purpose is to keep the suite's total honest would then
    # be inflating that total by one -- and the symptom is two red tests naming
    # README.md, which points at the wrong file entirely. Said here as well as
    # in the suite, because whoever is reading this output is already looking
    # for the cause.
    here = Path(__file__).resolve()
    if here.parent.name == "tests":
        target = here.parent.parent / "tools" / here.name
        if args.fix_location:
            # Opt-in, because a script that silently moves itself is a script
            # nobody trusts. Asked for explicitly, it is just the file
            # operation the warning describes, done correctly.
            target.parent.mkdir(exist_ok=True)
            if target.is_file():
                here.unlink()
                print(f"Removed the duplicate at {here.parent.name}/{here.name}; "
                      f"tools/{here.name} was already in place.")
            else:
                target.write_bytes(here.read_bytes())
                here.unlink()
                print(f"Moved {here.parent.name}/{here.name} -> tools/{here.name}")
            print("Re-run as: python tools/sync_test_readme.py")
            return 0
        print("WARNING: this script is in tests/, where pytest collects it as a "
              "test of its own.\n"
              "         It therefore adds one to the very total it reports, and "
              "test_helper_scripts_are_the_known_set\n"
              "         will fail until it is moved. Fix it with:\n"
              "             python tests/sync_test_readme.py --fix-location\n")
    elif args.fix_location:
        print(f"Nothing to do: this script is already in "
              f"{here.parent.name}/, which is where it belongs.")
        return 0

    if not README.exists():
        sys.exit(f"{README} does not exist. If this is a source archive, the "
                 f"tests/*.md guides were left out of it -- the suite is not "
                 f"self-contained without them.")

    counts = collected_counts()
    total, modules = sum(counts.values()), len(counts)
    text = original = README.read_text(encoding="utf-8")

    # A FALLING TOTAL IS NOT ROUTINE.
    #
    # This script exists to stop a stale number causing a red test, and the
    # obvious way to write it is to trust the tree and overwrite. That is right
    # when the total goes up, and dangerous when it goes down.
    #
    # Both parametrised families in test_suite_hygiene.py enumerate FILES:
    # one over the scripts in tests/, one over the guides. Delete a guide and
    # the suite does not fail -- it collects one test fewer. So a total that has
    # dropped can mean tests were retired, or it can mean files have gone
    # missing, and those two want opposite responses: update the number, or put
    # the files back. It has already been the second one once. Writing the
    # smaller number would have made three deleted documents permanent and
    # green.
    #
    # So a drop stops and asks. Growth is written without ceremony.
    claimed = [int(m.group(1)) for m in TOTAL.finditer(text)]
    if claimed and total < max(claimed) and not (args.check or args.allow_shrink):
        print(f"REFUSING to write a smaller total.\n"
              f"  tests/README.md documents {max(claimed)} tests; "
              f"the suite collects {total}.\n"
              f"  {max(claimed) - total} test(s) have gone. Check first whether "
              f"files are missing rather than\n"
              f"  tests retired -- the guides and the helper scripts are each "
              f"counted one per file, so a\n"
              f"  deleted file silently shrinks the suite. `git status` and "
              f"`ls tests/*.md` answer it.\n"
              f"  If the removal was deliberate, re-run with --allow-shrink.")
        return 1

    drift: list[str] = []

    # 1. The per-module table.
    def fix_row(m: re.Match) -> str:
        name, stated = m.group(1), int(m.group(2))
        actual = counts.get(name)
        if actual is not None and actual != stated:
            drift.append(f"{name}: {stated} -> {actual}")
            return m.group(0).replace(f"| {stated} |", f"| {actual} |", 1)
        return m.group(0)

    text = ROW.sub(fix_row, text)

    # 2. The headline total.
    def fix_total(m: re.Match) -> str:
        if (int(m.group(1)), int(m.group(2))) != (total, modules):
            drift.append(f"headline: {m.group(1)} tests across {m.group(2)} "
                         f"modules -> {total} across {modules}")
        return f"**{total} tests across {modules} modules.**"

    text = TOTAL.sub(fix_total, text)

    # 3. Every quoted "N passed" line the guide tells the reader to expect.
    def fix_passed(m: re.Match) -> str:
        if int(m.group(1)) != total:
            drift.append(f"expected output: `{m.group(1)} passed` -> "
                         f"`{total} passed`")
        return f"`{total} passed`"

    text = PASSED.sub(fix_passed, text)

    # 4. Modules with no row at all. Reported, never invented: the "Covers"
    #    column is a sentence about intent, and a generated one would be worse
    #    than an obvious gap.
    listed = {m.group(1) for m in ROW.finditer(text)}
    missing = sorted(set(counts) - listed)

    if args.check:
        for d in drift:
            print(f"  drift: {d}")
        for m in missing:
            print(f"  missing row: {m} ({counts[m]} tests)")
        if drift or missing:
            print(f"\ntests/README.md disagrees with the suite "
                  f"({total} tests across {modules} modules).")
            return 1
        print(f"tests/README.md agrees with the suite "
              f"({total} tests across {modules} modules).")
        return 0

    if text != original:
        README.write_text(text, encoding="utf-8")
        for d in drift:
            print(f"  fixed: {d}")
        print(f"tests/README.md updated: {total} tests across {modules} modules.")
    else:
        print(f"tests/README.md already agrees with the suite "
              f"({total} tests across {modules} modules).")

    for m in missing:
        print(f"  NOTE: {m} has {counts[m]} tests and no row in the table. "
              f"Add one with a description of what it covers.")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
