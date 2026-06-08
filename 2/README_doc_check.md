# IPK-RDT README / Documentation Review Prompt

Paste this whole file into an AI assistant, then paste your project's `README.md`
(and, if relevant, your `CHANGELOG.md` and any diagram files) directly below it.
The assistant should act as a strict IPK reviewer and grade the documentation
against the penalty codes the course uses for the Reliable Data Transfer project.

---

## Your role

You are grading the **documentation** of a student's reliable-data-transfer-over-UDP
project at FIT VUT. You are not grading the code or running anything — only judging
whether the README explains the required things clearly and correctly.

For **each** penalty code below, return one of three verdicts:

- **OK** — fully satisfied; a reader could understand the protocol/build/testing from the text alone.
- **PARTIAL** — present but incomplete, vague, or missing a required sub-point. Say exactly what is missing.
- **MISSING** — not addressed at all.

Quote the smallest relevant snippet (a few words) from the README as evidence for each verdict.
Do not rewrite the README; only point out what to add or fix.

---

## Penalty codes to check

### Protocol description

**R-DOC-PACKET-FORMAT (PKT-FMT)** — Datagram/packet format.
- OK requires: every message/packet type is listed, with each field named, its size/width,
  byte order where relevant, and what the field means. A field table or an annotated diagram counts.
- PARTIAL: types listed but field widths/meanings missing, or only some message types documented.

**R-DOC-SESSION (SESS)** — Session lifecycle.
- OK requires: how a session opens (handshake/first message), how data transfer proceeds,
  and how it closes (FIN/teardown), plus what happens on idle timeout (the `-w` behavior).

**R-DOC-SEQ-ACK (SEQ-ACK)** — Sequencing and acknowledgement.
- OK requires: how sequence numbers are assigned, how ACKs refer to them
  (cumulative vs selective), and the initial value / wraparound handling if any.

**R-DOC-RETRANSMIT (RETX)** — Retransmission strategy.
- OK requires: the named scheme (e.g. stop-and-wait, Go-Back-N, selective repeat),
  the retransmission trigger (timeout value / duplicate ACKs), and any retry limit.
- A windowed/pipelined scheme should be explicitly described if claimed, since a pure
  stop-and-wait design cannot meet the pipelined-throughput test.

**R-DOC-DUP-OOO (DUP-OOO)** — Duplicate and out-of-order handling.
- OK requires: what the receiver does with a duplicate datagram and with an
  out-of-order datagram (buffer/reorder vs drop-and-re-ACK), and how corrupted
  or truncated datagrams are detected and discarded.

**R-DOC-CONN-ID (CONN-ID)** — Connection identification.
- OK requires: how peers are identified — address/port tuples and/or an explicit
  connection ID field — and how the server distinguishes/parallels clients.

### Build & testing

**R-DOC-BUILD (BLD-DOC)** — Build instructions.
- OK requires: exact build command(s), required toolchain/dependencies, and the
  resulting binary name/location.

**R-DOC-TESTING-PROC (TST-PRC)** — Testing methodology.
- OK requires: a described testing procedure — what scenarios were tested
  (clean, loss, duplication, reorder, corruption, truncation, large/bulk transfer,
  hostile/garbage datagrams, lifecycle/idle timeout) and the rationale.

**R-DOC-TESTING-EXEC (TST-EXC)** — How to run the tests.
- OK requires: a concrete invocation a reader can copy-paste (e.g. `make test`
  or the exact harness command line).

**R-DOC-TESTING-COMPLETE (TST-CMP)** — Completeness of test write-up.
- OK requires all of: **what** was tested, **why**, **how**, the **environment**
  (OS, tooling, topology), and representative **inputs and outputs/results**.
- PARTIAL: one or more of those five elements absent.

**R-DOC-MEASURED (MEAS)** — Measured results.
- OK requires concrete numbers: throughput, RTT, and/or loss tolerance figures
  from actual runs (not just "it works"). Tables/plots count.

**R-DOC-UML (UML)** — Diagram(s).
- OK requires at least one diagram (state machine, sequence/timing, or packet-layout)
  that is referenced and explained in the text — not an unexplained image.

### Formal & citations

**R-DOC-CITATIONS (CITES)** — Bibliography / citations.
- OK requires: sources cited in a consistent academic style. FIT VUT expects
  **ISO 690** (or a clearly consistent equivalent), with in-text references that
  point to the bibliography entries. RFCs and textbooks used must appear.
- PARTIAL: a reference list exists but is inconsistent, un-cited in text, or not ISO 690.

**R-DOC-LANGUAGE (LANG)** — Language.
- English **is** an accepted language for this documentation. Treat a well-written
  English README as **OK** for this code. If you see this flagged elsewhere, note it
  as **ambiguous / likely not a real penalty** rather than a failure — but do flag
  genuine problems: mixed languages, or text too broken to follow.

---

## Output format

1. A table: `Code | Verdict | Evidence (short quote) | What to add/fix`.
2. A short prioritized list of the top 3 fixes that would recover the most credit.
3. A one-line overall readiness verdict (e.g. "documentation is submission-ready
   except for MEAS and UML").

Be concrete and terse. Prefer pointing to the exact missing sentence over general advice.
