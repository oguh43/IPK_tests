# IPK-RDT Test Harness

Spawns your `ipk-rdt` binary as both a client and server, routes traffic through a **UDP impairment proxy** that can simulate packet loss, duplication, reordering, corruption, **truncation**, jitter, delay, and **hostile/oversized garbage injection**, then verifies that the received data matches the sent data using SHA-256. It also includes a **submission-structure checker** and a companion prompt for AI-assisted README review.

---

## Building

```bash
make
# or
gcc -D_XOPEN_SOURCE=700 -Wall -Wextra -std=c99 -pedantic -Werror -Wconversion -Wsign-conversion -Wdouble-promotion -Wpadded -Wpacked -Wunsafe-loop-optimizations -Wstack-usage=2048 test_ipk_rdt.c -o test_ipk_rdt -lpthread
```

Requires only a C99 compiler (gcc) and pthreads - no external libraries needed. The submission checker additionally shells out to `unzip` and `make` when invoked.

---

## Usage

```
./test_ipk_rdt [OPTIONS]

  -b, --binary PATH      Path to ipk-rdt binary  (default: ./ipk-rdt)
  -t, --test LIST        Comma-separated test names to run
  -l, --list             List available tests and exit
  -v, --verbose          Show stderr from ipk-rdt processes
      --port-base N      Base UDP port  (default: 20000)
  -f, --fast             Skip slow tests (large files, high loss)
      --submission ZIP   Validate submission archive structure and exit
  -h, --help             Show this help
```

### Examples

```bash
# Run all tests (assumes ./ipk-rdt exists)
./test_ipk_rdt

# Specify a custom binary path
./test_ipk_rdt -b ./build/ipk-rdt

# Run a single test
./test_ipk_rdt -t normal

# Run multiple specific tests
./test_ipk_rdt -t loss_5,reorder,combined

# Run all tests but skip the slow ones (faster CI loop)
./test_ipk_rdt --fast

# Debug mode - show stderr output from your binary
./test_ipk_rdt -t loss_30 -v

# If ports 20000+ are in use on your machine
./test_ipk_rdt --port-base 30000

# List all available tests
./test_ipk_rdt --list

# Validate a packaged submission archive (does NOT run the binary tests)
./test_ipk_rdt --submission xbohach00.zip
```

---

## How It Works

```
your binary (client) --UDP--> proxy --UDP--> your binary (server)
                     <--UDP--       <--UDP--
```

The harness:

1. Finds free UDP ports automatically.
2. Starts your binary in server mode.
3. Starts a UDP impairment proxy between the client and server ports.
4. Starts your binary in client mode, feeding it generated test data.
5. Waits for the transfer to complete (with a per-test timeout).
6. Compares SHA-256 of the sent and received files.
7. Prints **PASS** / **FAIL** / **SKIP** with proxy statistics (packets forwarded, dropped, duplicated, reordered, corrupted, truncated, injected).

---

## Test Reference

### Original suite

| Test           | Description                                                  |
|----------------|--------------------------------------------------------------|
| `normal`       | Clean channel, ~50 KB file                                   |
| `normal_large` | Clean channel, 200 KB file                                   |
| `empty`        | Empty file (0 bytes) - edge case                             |
| `tiny`         | Single byte - edge case                                      |
| `binary`       | All 256 byte values - tests binary safety                    |
| `loss_5`       | 5% packet loss                                               |
| `loss_15`      | 15% packet loss                                              |
| `loss_30`      | 30% packet loss - stress test                                |
| `reorder`      | 20% packets reordered, 80 ms extra delay                     |
| `dup`          | 15% packet duplication                                       |
| `corrupt`      | 10% payload corruption                                       |
| `jitter`       | ±50 ms jitter, 20 ms base delay                              |
| `delay`        | Fixed 100 ms delay each direction                            |
| `combined`     | loss=10% dup=8% reorder=10% corrupt=5% jitter=±30 ms         |
| `timeout_test` | 40% loss + 200 ms delay - exercises retransmission timeouts  |
| `large_1mb`    | 1 MB file, 5% loss                                           |
| `large_5mb`    | 5 MB file, 3% loss                                           |
| `stdin_stdout` | Transfer via stdin/stdout pipes instead of files             |
| `ipv6`         | Transfer over IPv6 loopback (skipped if unavailable)         |
| `signal`       | SIGTERM during idle - checks for clean exit                  |
| `bad_args`     | Invalid CLI arguments - checks non-zero exit code            |

### Extended suite (mirrors the official 2025/2026 grading buckets)

| Test            | Bucket / behavior exercised                                                            |
|-----------------|----------------------------------------------------------------------------------------|
| `corrupt_only`  | A-CORRUPT: 3% payload corruption over a 96 KiB transfer                                |
| `truncate_only` | A-CORRUPT: 2% of datagrams delivered with trailing bytes chopped off                   |
| `corrupt_trunc` | A-CORRUPT: 3% corruption + 2% truncation combined                                      |
| `pipeline`      | A-PIPELINE: 100 ms RTT, 256 KB within a **5 s** deadline (stop-and-wait will time out) |
| `hostile`       | A-HOSTILE: random garbage datagrams injected toward the server; must be ignored        |
| `oversized`     | A-OVERSIZED-IGNORE: ~60 KB garbage datagrams injected; must be ignored                 |
| `lifecycle`     | A-LIFECYCLE: server `-w` idle self-exit; `-w 3` must outlast `-w 1` by ≥1 s            |
| `bulk_32m`      | A-BULK: 32 MiB clean transfer                                                          |
| `help`          | `--help` must exit 0 with non-empty stdout                                             |

`bad_args` now additionally checks that non-positive `-w` values (`-w 0`, `-w -1`) are rejected (R-CLI-CONFORM).

Slow tests (skipped by `--fast`): `large_1mb`, `large_5mb`, `timeout_test`, `loss_30`, `bulk_32m`, `corrupt_only`, `truncate_only`, `corrupt_trunc`.

> **Note on `pipeline`:** this test intentionally fails for a pure stop-and-wait implementation — 256 KB of 1 KB datagrams over a 100 ms RTT cannot finish within 5 s without windowing/pipelining. A correct windowed implementation passes it.

---

## Submission Structure Check

`./test_ipk_rdt --submission ARCHIVE.zip` validates packaging rules **without** running the binary tests:

- **Archive name** must match `xlogin00.zip` (e.g. `xbohach00.zip`) or `259760.zip` — **not** `x259760.zip`.
- **No nested wrapper directory**: files must sit at the archive root, not inside a single wrapping folder.
- **Makefile present** at the archive root.
- **`make environment`** must print exactly one valid nix shell name — one of `c`, `clisp`, `csharp`, `go`, `java`, `python`, `rust`, `zig` — using `@echo` (the `@` prefix is required; without it `make` echoes the literal command line and the check fails).
- Warns (does not fail) if `LICENSE` or `CHANGELOG.md` are absent at the root.

All filename checks are case-sensitive.

---

## Documentation Review

`README_doc_check.md` is a ready-to-paste prompt for an AI assistant. Paste it followed by your own `README.md`; it grades the documentation against the README penalty codes (packet format, session lifecycle, sequencing/ACK, retransmission, duplicate/out-of-order handling, connection identification, build/testing write-up, measured results, UML, and ISO 690 citations).

---

## Troubleshooting

**`FAIL: timed out`** - Your binary didn't finish within the time budget. Common causes: missing retransmission logic, the server never receiving all data, the client not detecting end-of-transfer, or (for `pipeline`) a stop-and-wait design that is too slow.

**`FAIL: SHA-256 mismatch`** - Data was corrupted in transit and your implementation didn't catch it. Check your corruption/truncation detection (checksums, length validation) and retransmission.

**`FAIL` on `hostile` / `oversized`** - Your binary accepted an injected garbage datagram as real data. Validate every datagram (type, length, checksum) and silently drop anything that doesn't parse.

**`FAIL` on `lifecycle`** - Your `-w` idle timeout isn't honored. The server should self-exit after roughly `-w` seconds of inactivity, so `-w 3` visibly outlasts `-w 1`.

**`FAIL: exit code N` on `bad_args`** - Your binary exits 0 on invalid arguments (including `-w 0` / `-w -1`). It should print a usage error and return a non-zero code.

**`FAIL: exit code N` on `signal`** - Your binary doesn't handle SIGTERM gracefully. Install a signal handler that closes sockets and exits cleanly.

**`FAIL: Mismatch: sent N B, got N+X B` on `stdin_stdout`** - The server is writing more bytes than it received. A common cause is accidentally writing protocol header bytes to stdout alongside the payload, or flushing a FIN/control packet as data. Make sure you write only the payload portion of each datagram to the output.

**`FAIL` on `loss_30` / `timeout_test` with `client=1, server=0`** - Your client is timing out before the transfer completes. Check that your `-w` idle timer is only reset by genuine protocol progress (new ACK covering previously unacknowledged data, or new non-duplicate data arriving) — not by retransmissions. Also verify your retransmission timeout (`RTO`) is long enough to account for the round-trip time; a fixed short RTO will cause unnecessary failures under high delay.

**`FAIL` on `combined` with server exit 143** - The server was killed by the harness after the session timeout expired, meaning it never finished. Under combined loss + corruption + reorder, a sliding window implementation can deadlock if cumulative ACK numbers get out of sync. Enable `-v` (verbose) and check whether client and server agree on which sequence numbers have been acknowledged.

**Port conflicts** - If you see bind errors, another process may be using ports in the 20000 range. Use `--port-base` to pick a different range.

**Binary not found** - Make sure your binary is compiled and the path is correct. The default is `./ipk-rdt` in the current directory.