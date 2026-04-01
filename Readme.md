# IPK Tests

Repository with testing utilities for two IPK assignments:

- L4 scanner test environment (project 1)
- RDT-over-UDP test harness (project 2)

## Repository Layout

- [1](1) - L4 scanner web test environment
- [2](2) - `ipk-rdt` C test harness and Makefile

## Project 1: L4 Scanner Test Environment

Detailed README: [1/Readme.md](1/Readme.md)

This service is intended for validating L4 scanner behavior, including IPv6 testing support.

### Connectivity Notes

- Preferred and supported setup is FITVPN.
- IPv6 support requires FITVPN.
- Kolejnet-only setup is deprecated.

### Platform Notes

- Linux: use FITVPN and interface `tun0`.
- Windows + WSL2: install FITVPN on host and in WSL; use `tun0`. UDP may be broken due to VPN configuration.
- Windows + QEMU VM: install FITVPN on host only; VM interface name may vary. **Preferred!**

## Project 2: IPK-RDT Test Harness

Detailed README: [2/Readme.md](2/Readme.md)

The harness starts your `ipk-rdt` binary in client/server modes, routes traffic through a UDP impairment proxy, and validates transfer correctness with SHA-256.

### What Is Tested

- Clean transfers (small and large payloads)
- Loss, duplication, reordering, corruption, jitter, delay
- Stdin/stdout mode
- IPv6 loopback mode
- Signal handling and bad-arguments behavior

## Support

For issues with project 1 environment, contact the maintainer as noted in [1/Readme.md](1/Readme.md).

Unsupported configurations may work, but support is limited.

## Related Resources

- [VUT FIT Coursework Repository](https://github.com/oguh43/VUT_FIT)