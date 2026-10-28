# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-10-28

### Fixed

- The HTTP check connects to the address the TCP check verified, instead of resolving the name
  again. The `Host` header, SNI and certificate check still use the name the user typed.
- The HTTP check requests the path of the URL when one is given (`/` otherwise).
- A TLS handshake that completes without a server certificate is reported as a failure,
  instead of stopping the program.

### Added

- Layer 0 on Linux: default gateway (IPv4 and IPv6) from `/proc/net/route` and
  `/proc/net/ipv6_route`, DNS servers from `/etc/resolv.conf`. No external command is run.
- `--json` output includes, for each target, the addresses tried and the checks skipped with
  their cause, as the `--report` text does.
- Type checking with mypy in CI; the package ships a `py.typed` marker.
- Dependabot keeps the GitHub Actions up to date.

### Changed

- `--help` describes every layer, from local configuration to HTTP, and the escalation report.

## [0.1.0] - 2026-10-28

### Added

- First release: layer-by-layer checks of a network service with plain-language hints.
- Layer 0 (local): source address, outgoing interface, default gateway and DNS servers on
  Windows; APIPA addresses and missing routes are reported.
- DNS resolution, TCP over IPv4 and IPv6, TLS certificate validation and an HTTP request.
- On Windows, a TLS failure caused by a root CA missing from the local certificate store
  explains that Python does not download it on demand, and how to fix it.
- Text and JSON output; exit codes 0, 1 and 2 for scripts and monitoring.
- `--report`: a plain-text escalation report for tickets, with a verdict and a suggested team.
- Tests without internet access; CI on Linux, Windows and macOS with Python 3.10, 3.13 and 3.14.

[0.1.1]: https://github.com/eduardo-cozzolino/layerwise/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/eduardo-cozzolino/layerwise/releases/tag/v0.1.0
