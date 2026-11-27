# Changelog

All notable changes to this project are documented here.

## [Unreleased]

## [1.2.0] - 2026-11-27

### Added

- Opt-in `-k`/`--insecure` flag for HTTPS probes against hosts with self-signed, expired, or mismatched TLS certificates, plus `tls_error` reporting in JSON when strict verification fails.
- JSON truncation and filtering metadata: `discovered_hostnames`, `truncated`, `skipped_hostnames` (when nonzero), `discovered_certificates`, and `certificates_truncated`.
- `Accept-Encoding: gzip` support and transparent gzip decompression in CTL JSON requests.
- Early validation of `--output` destination before network requests begin, and a `stderr` warning when `--certificates` is used with `--format txt`.

### Changed

- Normalize single-wildcard CT entries (`*.sub.example.com` -> `sub.example.com`) and skip invalid or out-of-scope hostnames with a warning instead of aborting the entire domain scan.
- Reuse resolved IPs during TCP probing to reduce redundant DNS lookups and reuse one HTTP opener per host.
- Enable ANSI escape sequences on Windows via `ctypes` `SetConsoleMode` instead of `os.system("")`.
- Use `tempfile.NamedTemporaryFile` with `fsync` in `write_output_atomic` to avoid predictable temporary filenames.

### Fixed

- Render reachable ports in the `IP / PORT` column of the interactive table, show `-` for empty IP lists, and keep narrow terminal widths (e.g., 60 columns) from overflowing.
- Ignore non-finite `Retry-After` values (`nan`/`inf`) and parse HTTP-date headers with locale-independent `email.utils.parsedate_to_datetime`.
- Report empty CTL `HTTP 200` responses clearly instead of a raw JSON decoder error.

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

[Unreleased]: https://github.com/DevCop95/shodan_reconsx/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/DevCop95/shodan_reconsx/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/DevCop95/shodan_reconsx/compare/v1.0.5...v1.1.0
[1.0.0]: https://github.com/DevCop95/shodan_reconsx/releases/tag/v1.0.0
[1.0.5]: https://github.com/DevCop95/shodan_reconsx/releases/tag/v1.0.5
