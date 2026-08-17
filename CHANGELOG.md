# Changelog

All notable changes to this project are documented here.

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

[1.0.0]: https://github.com/DevCop95/shodan_reconsx/releases/tag/v1.0.0
[1.0.5]: https://github.com/DevCop95/shodan_reconsx/releases/tag/v1.0.5
