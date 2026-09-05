# Recons101x

[![CI](https://github.com/DevCop95/shodan_reconsx/actions/workflows/ci.yml/badge.svg)](https://github.com/DevCop95/shodan_reconsx/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/DevCop95/shodan_reconsx)](https://github.com/DevCop95/shodan_reconsx/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)

![Recons101x blood-red banner](assets/shodanx.png)

Recons101x is a portable, passive-by-default reconnaissance tool that enumerates hostnames
published by `ctl.shodan.io`. It runs on Linux, Termux, and Windows using only
Python 3. No Shodan API key or third-party packages are required.

Use this tool only against assets you own or are explicitly authorized to test.
The examples use `example.com` as a placeholder; replace it with an authorized domain.

The latest GitHub release is [v1.0.5](https://github.com/DevCop95/shodan_reconsx/releases/tag/v1.0.5)
(2026-08-17). The limits, progress, and reliability changes below are
[Unreleased](CHANGELOG.md#unreleased); the version remains `1.0.5`.

## Requirements

- Python 3.10 or newer
- Internet access to `ctl.shodan.io`

## Installation

Clone and enter the repository:

```sh
git clone https://github.com/DevCop95/shodan_reconsx.git
cd shodan_reconsx
```

The launchers work without installation. To install the `recons101x` command:

```sh
python -m pip install .
recons101x example.com
```

## Quick Start

Linux or Termux:

```sh
chmod +x scan.sh
./scan.sh example.com
```

Windows PowerShell:

```powershell
.\scan.ps1 example.com
```

Any platform:

```sh
python src/recons101x.py example.com
```

The TXT output contains `domain<TAB>hostname`. Status messages and the banner
are written to stderr, keeping stdout safe for pipes and redirection.
The banner uses ANSI bright red when stderr is an interactive terminal.
`--no-color` disables color in the banner, summary, and text output. The standard
`NO_COLOR` environment variable also disables color, overriding `--color`.
`--help` and `--version` do not print a banner.

## Batch Scanning

Create a `domains.txt` file:

```text
# One domain per line
example.com
example.org
```

Run the batch:

```sh
./scan.sh --input domains.txt --output results.txt
```

Blank lines and lines beginning with `#` are ignored. Duplicate domains are
removed automatically.

## JSON Output

```sh
./scan.sh example.com --format json --output results.json
```

## Optional DNS Resolution

```sh
./scan.sh example.com --resolve --workers 20
```

With `--resolve`, TXT output becomes
`domain<TAB>hostname<TAB>ip1,ip2`. Add `--status` to append the more precise
state. `DNS_ONLY` means that the hostname resolves but no web service was
verified; `TCP_REACHABLE` means that 443/80 accepted a connection;
`HTTP_REACHABLE` means that HTTP/HTTPS returned a response, including 4xx/5xx
errors, not that the service is healthy; and `STALE` means that DNS did not
resolve. Reachable states are shown in green in an
interactive terminal. Without `--probe`, resolution only distinguishes
`DNS_ONLY` and `STALE`.

Because certificate transparency can contain old names, DNS activity is only a
first filter. To check TCP and HTTP reachability and keep only active results:

```sh
./scan.sh example.com --probe --active-only --status --probe-timeout 3
```

`--probe` makes TCP and HTTP/HTTPS checks on ports 443 and 80 and records the
reachable ports and HTTP status codes in JSON as `ports` and `http`. It is
intentionally opt-in and should only be used on domains you own or are
authorized to test. With `--probe`, `--active-only` removes `STALE` and
`DNS_ONLY` names from the output; with `--resolve` alone it keeps names that
resolve in DNS. Without the filter, the tool reports every state.

When resolving or probing, stderr prints DNS/TCP/HTTP/stale counters, also
included in each domain's JSON `summary` object. These cover only the hostnames
selected by `--max-hosts`, before `--active-only` filtering, not the full CTL
inventory when capped. JSON retains selected hostname details unless filtered.

In an interactive terminal, status output uses a fixed-width table and
truncates long hostnames or IPv6 lists so rows do not wrap. Redirected output
and files keep the complete tab-separated values.

For a bounded live scan:

```sh
./scan.sh example.com --live --max-hosts 50 --max-time 60 --progress
```

`--live` (two hyphens) enables `--resolve --probe --active-only --status`.
It is opt-in active traffic, not passive enumeration. TCP reachability alone
is sufficient to keep a hostname; an HTTP response is not required. The
individual switches remain available for automation and advanced tuning.

## Certificate enrichment

For bounded passive certificate enrichment (CTL requests only, no target probes):

```sh
./scan.sh example.com --certificates --max-certificates 5 --max-time 60 --progress --format json --output results.json
```

The JSON result keeps the existing `domain` and `hostnames` fields, adds an
`active` boolean to each hostname when `--resolve` is used, and adds a
`certificates` array containing each SHA-256 hash and its response from
`/api/v1/cert/{sha256}`. Fetching requires `--certificates`; a limit alone does
not enable it. Use `--format json` to display certificate data: TXT output does
not include it, even though `--certificates` still performs the requests.

## Limits and Progress

Limits are optional; scans remain unlimited unless a limit is supplied.

| Option | Scope |
| --- | --- |
| `--max-hosts N` | Positive integer, per domain in all modes, including passive. Selects the first N sorted unique names after the full CTL hostname index fetch; does not limit that query. |
| `--max-certificates N` | Positive integer, per domain. Limits certificate detail downloads after the full certificate index query, selecting the first N sorted SHA-256 hashes, not the newest certificates. |
| `--max-time SECONDS` | Overall scan deadline across all domains, CTL queries, DNS, TCP, HTTP, retries, and certificate requests. |
| `--progress` | Off by default. Reports the first, every tenth, and final completed hostname check or certificate detail request per domain, including failures, to stderr only. |

Progress does not contaminate stdout and is not a heartbeat during index queries
or stalled work. Passive enumeration without certificate enrichment has no
hostname checks to report.

`--max-time` runs the scan in a separate spawned process, terminated on expiry
even if DNS is stuck. The worker also exits if its supervisor is terminated.
Arguments and input are validated before timing; process
startup and cleanup can add minor overhead. A deadline returns exit code `1`.
Regular output is produced at the end; results in progress are not checkpointed,
and unfinished scan output is not guaranteed. Do not treat a previous or existing
output file as a new successful result after a timeout.

## Options

```sh
./scan.sh --help
```

- `--workers` (default `10`) bounds combined per-host DNS -> TCP -> HTTP workers.
  HTTP checks need not wait for all DNS lookups; DNS-failed names skip probes.
  Result ordering is unchanged.
- `--timeout` (default `15` seconds) applies per CTL network operation;
  `--probe-timeout` (default `3` seconds) applies per probe. Neither is an overall
  DNS deadline; use `--max-time` for that. All three timeout options require
  positive finite seconds within the platform's supported range; NaN and infinity
  are rejected.
- `--retries` (default `2`) controls CTL retries. Network `HTTPException`
  (including `IncompleteRead`) and `OSError` failures are retried or reported
  as controlled query errors; malformed HTTP probe responses are ignored.

Exit codes: `0` success; `1` query, output-write, or deadline error; `2` invalid
arguments/input; `130` interrupt. Check the exit code before consuming results.

## Project Structure

```text
recons101x/
|-- assets/
|   `-- shodanx.png
|-- src/
|   `-- recons101x.py
|-- tests/
|   `-- test_recons101x.py
|-- .gitignore
|-- CHANGELOG.md
|-- CONTRIBUTING.md
|-- LICENSE
|-- MANIFEST.in
|-- README.md
|-- SECURITY.md
|-- pyproject.toml
|-- scan.ps1
`-- scan.sh
```

## Running Tests

The test suite uses Python's standard library and requires no additional
packages:

```sh
python -m unittest discover -s tests -v
```

## Contributing and Security

See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a change. Report
security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Released under the [MIT License](LICENSE).
