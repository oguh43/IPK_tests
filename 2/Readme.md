# IPK-RDT Test Harness

Spawns your `ipk-rdt` binary as both a client and server, routes traffic through a **UDP impairment proxy** that can simulate packet loss, duplication, reordering, corruption, jitter, and delay, then verifies that the received data matches the sent data using SHA-256.

---

## Building

```bash
make
# or
gcc -D_XOPEN_SOURCE=700 -Wall -Wextra -std=c99 -pedantic -Werror -Wconversion -Wsign-conversion -Wdouble-promotion -Wpadded -Wpacked -Wunsafe-loop-optimizations -Wstack-usage=2048 test_ipk_rdt.c -o test_ipk_rdt -lpthread
```

Requires only a C99 compiler (gcc) and pthreads - no external libraries needed.

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
7. Prints **PASS** / **FAIL** / **SKIP** with proxy statistics (packets forwarded, dropped, duplicated, reordered, corrupted).

---

## Test Reference

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
| `combined`     | loss=10% dup=8% reorder=10% corrupt=5% jitter=+-30 ms        |
| `timeout_test` | 40% loss + 200 ms delay - exercises retransmission timeouts  |
| `large_1mb`    | 1 MB file, 5% loss                                           |
| `large_5mb`    | 5 MB file, 3% loss                                           |
| `stdin_stdout` | Transfer via stdin/stdout pipes instead of files             |
| `ipv6`         | Transfer over IPv6 loopback (skipped if unavailable)         |
| `signal`       | SIGTERM during idle - checks for clean exit                  |
| `bad_args`     | Invalid CLI arguments - checks non-zero exit code            |

Slow tests (skipped by `--fast`): `large_1mb`, `large_5mb`, `timeout_test` and `loss_30`.


---


## Troubleshooting

**`FAIL: timed out`** - Your binary didn't finish within the time budget. Common causes: missing retransmission logic, the server never receiving all data, or the client not detecting end-of-transfer.

**`FAIL: SHA-256 mismatch`** - Data was corrupted in transit and your implementation didn't catch it. Check your corruption detection (checksums, CRC, etc.) and retransmission on NAK.

**`FAIL: exit code N` on `bad_args`** - Your binary exits 0 on invalid arguments. It should print a usage error and return a non-zero code.

**`FAIL: exit code N` on `signal`** - Your binary doesn't handle SIGTERM gracefully. Install a signal handler that closes sockets and exits cleanly.

**Port conflicts** - If you see bind errors, another process may be using ports in the 20000 range. Use `--port-base` to pick a different range.

**Binary not found** - Make sure your binary is compiled and the path is correct. The default is `./ipk-rdt` in the current directory.
