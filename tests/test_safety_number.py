"""
Tests for the conversation safety number (anti-man-in-the-middle feature).

The safety number is the application's answer to the one attack that
end-to-end encryption alone cannot stop: a malicious key server that hands out
the wrong public key. These tests pin down the three properties the feature
depends on to be useful:

  1. Symmetry - both participants compute the SAME number, so they have
     something to compare. (Without this the feature is pointless.)
  2. Sensitivity - if either key changes, the number changes, so a substituted
     key is revealed.
  3. Format - six groups of five digits, stable and readable.

Run with:  pytest -v test_safety_number.py
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from crypto_core import Identity, safety_number  # noqa: E402


def test_both_parties_compute_the_same_number():
    """Alice's view (mine, Bob's) and Bob's view (mine, Alice's) must match."""
    alice = Identity.generate().public_bytes()
    bob = Identity.generate().public_bytes()
    alice_view = safety_number(alice, bob)
    bob_view = safety_number(bob, alice)
    assert alice_view == bob_view


def test_substituted_key_changes_the_number():
    """A man-in-the-middle who swaps one key produces a different number, which
    is exactly how the two users would detect the attack."""
    alice = Identity.generate().public_bytes()
    bob = Identity.generate().public_bytes()
    mallory = Identity.generate().public_bytes()

    genuine = safety_number(alice, bob)
    intercepted = safety_number(alice, mallory)  # what Alice sees under attack
    assert genuine != intercepted


def test_format_is_six_groups_of_five_digits():
    alice = Identity.generate().public_bytes()
    bob = Identity.generate().public_bytes()
    number = safety_number(alice, bob)
    groups = number.split(" ")
    assert len(groups) == 6
    assert all(len(g) == 5 and g.isdigit() for g in groups)


def test_rejects_wrong_length_keys():
    with pytest.raises(ValueError):
        safety_number(b"\x00" * 10, b"\x00" * 32)
