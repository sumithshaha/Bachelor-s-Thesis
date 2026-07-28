# Does this suite actually test anything?

A suite of 497 passing tests is a claim, not evidence. Tests can pass because
the code is correct, or because they never exercised it — a fixture that
silently no-ops, an assertion that can only be true, a module that skips itself
when a file is missing. All three have happened in this project.

This document describes how the suite was checked for that failure mode, so a
reviewer can repeat the check rather than take the pass count on trust.

---

## The method: deliberate mutation

Break the code on purpose. If no test notices, the test that was supposed to
cover it does not.

This is cheap and it is decisive. A test that passes both with and against the
behaviour it names is worse than no test, because it also removes the suspicion
that would otherwise lead someone to look.

### Worked example

`server.py` refuses a binary file chunk sent for a transfer belonging to another
user. Find the guard in `_handle_binary`:

```python
if sender != nick:
    await self._send_error(ws, "unauthorised file id")
    return
```

Disable it:

```python
if False:
    await self._send_error(ws, "unauthorised file id")
    return
```

Then run the module that claims to cover it:

```bash
python -m pytest tests/test_untrusted_frames.py -v
```

**Expected:** `test_binary_chunk_for_another_users_file_is_refused` **fails**.

Restore the line and confirm it passes again. If it had passed while the guard
was disabled, the test would be checking something other than what its name
says.

---

## Mutations that were run, and what they caught

Each of these was applied, the suite was run, and the *named* test was confirmed
to fail — not merely some test somewhere.

| Mutation | Test that must fail |
|---|---|
| Disable the file-chunk authorisation check | `test_untrusted_frames.py::test_binary_chunk_for_another_users_file_is_refused` |
| Let the relay forward a self-addressed frame | `test_self_addressing.py` |
| Restore the original dual-deque log path, which delivered some lines twice | `test_log_stream.py` |
| Narrow the handshake noise filter back to `InvalidMessage` only | `test_handshake_noise_filter.py` |
| Store a published identity key without the Ed25519→X25519 conversion | `test_identity_key_type.py` |
| Drop `popupType: Popup.Item` from a QML dialog | `test_qml_shadowing.py` |

The last two are worth noting because both reproduce defects that actually
shipped and were found by hand — an identity-key type confusion that broke
safety numbers on both devices, and a Qt 6.10 popup-default change that rendered
a dialog off-screen on Android. Both are now pinned.

The `test_qml_shadowing.py` mutation also caught a fault in the *test*: the first
implementation matched the string `popupType` anywhere in the file, including
inside comments, so a file that merely *mentioned* the property passed. Mutation
testing found that, not review.

---

## Skips are the other failure mode

A skipped test reports neither pass nor fail, and a run that ends
`465 passed, 14 skipped` looks like success at a glance.

The suite's TLS module skips itself when `pki/` is absent — reasonable, since it
cannot handshake without a certificate — which means forgetting to generate the
lab authority silently removes 14 tests. `run_tests.sh` therefore generates the
PKI itself when it is missing, so the default path cannot skip them by accident.

**When reading any result, read the skip count first.** The only skip expected in
a normal run is one in `test_schema_migration.py`, and only when running as root
on Linux, because that test needs the filesystem to honour the read-only bit.

---

## Tests that read source rather than run it

Two modules — `test_qml_shadowing.py` and `test_build_sources.py` — parse the
C++ and QML source instead of executing it, because the Qt client cannot be
compiled inside a Python test run.

This is weaker evidence than running the code, and is worth stating plainly
rather than letting the count imply otherwise. It is not, however, cosmetic:
both guard failure modes that stopped the application from starting on both
platforms, with the cause visible only in `logcat`. A source-level check that
catches a real class of defect is worth having, provided nobody mistakes it for
an integration test.

---

## Repeating the check yourself

1. Pick a security-relevant guard — an authorisation check, a length validation,
   a signature verification.
2. Disable it, minimally: change the condition rather than deleting the block,
   so the diff is one token.
3. Run the module you believe covers it.
4. Confirm the *named* test fails, not merely that something fails.
5. Restore the line and confirm green.

Use `git diff` before restoring, and `git checkout --` to restore, so a mutation
cannot survive into a commit.

Good candidates in this codebase:

- the nonce-length and hex validation in `_require_hex`
- the 64 KiB chunk size cap
- the `from`-field override that stops a client claiming another identity
- the one-time prekey consumption that makes a replayed X3DH opener fail
- the bound on retained skipped-message keys

---

## What this does not establish

Mutation testing shows the suite reacts to the specific faults injected. It does
not show the suite would catch faults nobody thought of, and it does not measure
coverage in any formal sense. It is a floor, not a ceiling: evidence that the
tests are connected to the code, rather than proof that they are sufficient.

For what each module covers, see [README.md](README.md). For the cross-language
conformance strategy, see [RATCHET_TESTING.md](RATCHET_TESTING.md). For the
attack experiments, see [E2EE_REDTEAM_PLAN.md](E2EE_REDTEAM_PLAN.md).
