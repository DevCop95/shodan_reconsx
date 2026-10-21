# Changelog

All notable changes to this project are documented here.

## [Unreleased]

## [1.1.0] - 2026-10-20

### Added

- Per-domain JSON provenance, completion/error state, and phase timings.
- Concurrent certificate detail downloads controlled by `--certificate-workers`.
- Progress for CTL index lookups, including elapsed time.
- `RECONS101X_PYTHON` override in shell launchers.

### Fixed

- Validate CTL hostnames against the requested domain before any DNS or active checks.
- Prevent HTTP probes from following redirects outside the selected hostname.
- Retry only transient HTTP statuses, honor `Retry-After`, and use bounded jittered backoff.
- Replace output files atomically after serialization.
- Preserve partial domain results with explicit errors and a nonzero exit status.

## [1.0.5] - 2026-08-17

### Added

- Optional certificate enrichment through the Shodan CTL domain and certificate endpoints.
- Active-node status based on DNS resolution, with green terminal output.
- Opt-in TCP reachability probes and an `--active-only` filter for stale CT names.
- High-level `--live` mode for the common active-host workflow.
- Reachability states and per-domain DNS/TCP/HTTP/stale summaries.

## [1.0.0] - 2026-07-28

### Added

- Passive hostname enumeration through Shodan CTL.
- Single-domain and batch input modes.
- TXT and JSON output formats.
- Optional concurrent DNS resolution.
- Linux, Termux, and Windows launchers.
- Domain validation, retries, timeout controls, and IDN support.
- Cross-platform tests and automated GitHub releases.

[Unreleased]: https://github.com/DevCop95/shodan_reconsx/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/DevCop95/shodan_reconsx/compare/v1.0.5...v1.1.0
[1.0.0]: https://github.com/DevCop95/shodan_reconsx/releases/tag/v1.0.0
[1.0.5]: https://github.com/DevCop95/shodan_reconsx/releases/tag/v1.0.5
