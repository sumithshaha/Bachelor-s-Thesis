# Documentation

Start here and go to the one document that matches what you are trying to do.
They overlap deliberately at the edges, but each has one job.

---

## Running it

**[GETTING_STARTED.md](GETTING_STARTED.md)** — the main path. From a fresh clone
to two chat windows talking over verified TLS. Assumes no prior knowledge of the
project. Read this first; most other documents assume you have.

**[SIMPLE_GUIDE.md](SIMPLE_GUIDE.md)** — the same journey at half speed, with
more explanation of the underlying ideas and less assumed familiarity with
terminals, virtual environments and build systems. If `GETTING_STARTED.md` moves
too fast, use this instead.

**[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** — symptoms and their causes,
organised by what you actually see rather than by which component is at fault.
Check here before re-reading a setup guide.

---

## Building

**[BUILD.md](BUILD.md)** — the reference: prerequisites, exact CMake
invocations, libsodium on each platform, the Android specifics, and how to run
each of the three verification commands.

**[QT_CREATOR_GUIDE.md](QT_CREATOR_GUIDE.md)** — the same build done through Qt
Creator's dialogs rather than the command line, with the settings that matter
called out. Use this if you would rather click than type.

---

## Understanding it

**[ARCHITECTURE.md](ARCHITECTURE.md)** — what the components are, how a message
travels from one keyboard to another screen, where the cryptography sits, and
why the design is split the way it is.

**[../SECURITY.md](../SECURITY.md)** — the threat model: what the system
protects against, what it demonstrably does not, and how the claims are checked.

**[TLS_WITHOUT_HOSTING.md](TLS_WITHOUT_HOSTING.md)** — why there is a private
certificate authority in a project about encryption, and why that is not the
same as disabling certificate checks. Relevant to anyone reviewing the transport
security.

**[../tests/README.md](../tests/README.md)** — how to run the tests and what
each of the 32 modules is evidence for. The companion documents in `tests/` go
deeper: [RATCHET_TESTING.md](../tests/RATCHET_TESTING.md) on the cross-language
conformance strategy, [E2EE_REDTEAM_PLAN.md](../tests/E2EE_REDTEAM_PLAN.md) on
the attack experiments, and
[TESTS_INTEGRATION.md](../tests/TESTS_INTEGRATION.md) on how the suite was
checked for the failure mode where tests pass without testing anything.

---

## Deploying

**[DEPLOY_START_HERE.md](DEPLOY_START_HERE.md)** — putting the relay on a public
VM with a real certificate, in the order the steps must happen. Includes the two
rules that cause the most lost time.

**[DEPLOY_CPOUTA.md](DEPLOY_CPOUTA.md)** — the long-form runbook behind that
document: what each script does and why, the certificate renewal path,
verification in depth, and rollback.

---

## Reading order for a reviewer

If you are assessing this project rather than running it, the shortest path to
an informed opinion:

1. [../README.md](../README.md) — what it claims to do
2. [ARCHITECTURE.md](ARCHITECTURE.md) — how it is built
3. [../SECURITY.md](../SECURITY.md) — what it claims to guarantee, and the limits
4. [../tests/README.md](../tests/README.md) — how those claims are checked
5. `bash run_tests.sh` and `PYTHONPATH=server python tests/e2ee_redteam.py` — the
   claims, checked

Step 5 takes about three minutes and needs only Python.
