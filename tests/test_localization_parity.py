"""
test_localization_parity.py -- every visible string exists in every language.

WHY THIS MODULE EXISTS
----------------------
client/src/localization.cpp holds three tables -- English, Finnish, Swedish --
and the UI looks each string up by key. Adding a string means adding it three
times, and nothing checked that it had been. Localization::tIn falls back to
English and then to the raw key, so the failure of a forgotten entry is not a
crash: the Finnish user is quietly shown English, or, if the key was missed
everywhere, the literal string "recover.close" appears in the interface. Both
survive a full test run and a manual click-through in the developer's own
language.

That fallback is the right runtime behaviour -- better a legible English word
than an empty button -- but it means the mistake is invisible precisely where it
matters, so it needs catching at the source instead.

The tables are read from the C++ rather than from a running application because
they ARE the C++: three brace-initialised literals delimited by the section
comments the file already carries.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCALIZATION = REPO_ROOT / "client" / "src" / "localization.cpp"

# The comment banners that open each table in localization.cpp.
SECTIONS = (
    ("English", "---- English"),
    ("Finnish", "---- Finnish"),
    ("Swedish", "---- Swedish"),
)

ENTRY = re.compile(r'\{\s*"([A-Za-z0-9_.]+)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*\}')


def _tables() -> dict[str, dict[str, str]]:
    """{language: {key: value}} parsed from the three literals."""
    text = LOCALIZATION.read_text(encoding="utf-8", errors="replace")

    starts = []
    for name, banner in SECTIONS:
        idx = text.find(banner)
        assert idx != -1, (
            f"localization.cpp has no '{banner}' section banner. If the tables "
            f"were reorganised, update SECTIONS in this test to match."
        )
        starts.append((name, idx))
    starts.sort(key=lambda pair: pair[1])

    tables: dict[str, dict[str, str]] = {}
    for i, (name, start) in enumerate(starts):
        end = starts[i + 1][1] if i + 1 < len(starts) else len(text)
        tables[name] = {m.group(1): m.group(2)
                        for m in ENTRY.finditer(text[start:end])}
    return tables


@pytest.fixture(scope="module")
def tables() -> dict[str, dict[str, str]]:
    return _tables()


def test_all_three_tables_were_found(tables):
    """Guard the parser itself: an empty table would make everything below
    pass vacuously, which is the failure mode a source-reading test is most
    prone to."""
    for name, entries in tables.items():
        assert len(entries) > 50, (
            f"only {len(entries)} entries parsed for {name} -- the parser has "
            f"lost track of the table boundaries, not the file"
        )


@pytest.mark.parametrize("language", [name for name, _ in SECTIONS[1:]])
def test_every_english_key_is_translated(tables, language):
    """English is the fallback map, so it defines the full set of keys."""
    missing = sorted(set(tables["English"]) - set(tables[language]))
    assert not missing, (
        f"{language} is missing {len(missing)} string(s): {missing}. "
        f"Localization::tIn falls back to English, so these would appear "
        f"untranslated rather than failing visibly."
    )


@pytest.mark.parametrize("language", [name for name, _ in SECTIONS[1:]])
def test_no_translation_is_orphaned(tables, language):
    """A key present in a translation but not in English can never be looked
    up -- the UI asks for keys the English table defines."""
    orphans = sorted(set(tables[language]) - set(tables["English"]))
    assert not orphans, (
        f"{language} defines {orphans}, which English does not. Either the "
        f"English entry was dropped or the key is misspelt in one table."
    )


def test_no_translation_is_left_as_the_english_placeholder(tables):
    """A copied-but-untranslated entry is worth knowing about.

    Not every identical string is a mistake -- proper nouns, "OK", and short
    tokens are legitimately the same in all three -- so this only reports keys
    whose value is identical across ALL THREE tables AND long enough to be a
    sentence rather than a label.
    """
    suspect = []
    for key, english in tables["English"].items():
        if len(english) < 25:
            continue
        if all(tables[lang].get(key) == english for lang in ("Finnish", "Swedish")):
            suspect.append(key)
    assert not suspect, (
        f"these long strings are byte-identical in all three languages, which "
        f"usually means an English value was pasted in and not translated: "
        f"{suspect}"
    )


def test_no_key_is_defined_twice_in_one_table():
    """A duplicate key silently wins or loses depending on insertion order."""
    text = LOCALIZATION.read_text(encoding="utf-8", errors="replace")
    starts = sorted((text.find(b), n) for n, b in SECTIONS)
    for i, (start, name) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        keys = [m.group(1) for m in ENTRY.finditer(text[start:end])]
        dupes = sorted({k for k in keys if keys.count(k) > 1})
        assert not dupes, f"{name} defines these keys more than once: {dupes}"


def test_the_recovery_sheet_can_be_closed_in_every_language(tables):
    """The close control added to the recovery dialog carries a tooltip, and a
    tooltip that falls back to a raw key reads as a defect to the user."""
    for language in tables:
        assert "recover.close" in tables[language], (
            f"{language} has no 'recover.close' string"
        )
        assert "recover.back" in tables[language], (
            f"{language} has no 'recover.back' string"
        )
