# Recons101x

[![CI](https://github.com/DevCop95/shodan_reconsx/actions/workflows/ci.yml/badge.svg)](https://github.com/DevCop95/shodan_reconsx/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/DevCop95/shodan_reconsx)](https://github.com/DevCop95/shodan_reconsx/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)

![Recons101x blood-red banner](assets/shodanx.png)

Recons101x is a portable passive reconnaissance tool that enumerates hostnames
published by `ctl.shodan.io`. It runs on Linux, Termux, and Windows using only
Python 3. No Shodan API key or third-party packages are required.

Use this tool only against assets you own or are explicitly authorized to test.

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
The banner uses ANSI bright red when stderr is an interactive terminal. Set the
standard `NO_COLOR` environment variable to disable color.

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
`HTTP_REACHABLE` means that HTTP/HTTPS returned a response; and `STALE` means
that DNS did not resolve. Reachable states are shown in green in an
interactive terminal. Without `--probe`, resolution only distinguishes
`DNS_ONLY` and `STALE`.

Because certificate transparency can contain old names, DNS activity is only a
first filter. To verify that a web service is reachable, use the explicit
probe and keep only active results:

```sh
./scan.sh example.com --probe --active-only --status --probe-timeout 3
```

`--probe` makes TCP and HTTP/HTTPS checks on ports 443 and 80 and records the
reachable ports and HTTP status codes in JSON as `ports` and `http`. It is
intentionally opt-in and should only be used on domains you own or are
authorized to test. With `--probe`, `--active-only` removes `STALE` and
`DNS_ONLY` names from the output; with `--resolve` alone it keeps names that
resolve in DNS. Without the filter, the tool reports every state.

When resolving or probing, stderr also prints a compact summary such as:

```text
[+] Summary: 312 DNS | 86 TCP | 54 HTTP | 936 stale
```

The JSON output contains the same counters in each domain's `summary` object,
while retaining the complete hostname details unless `--active-only` is used.

In an interactive terminal, status output uses a fixed-width table and
truncates long hostnames or IPv6 lists so rows do not wrap. Redirected output
and files keep the complete tab-separated values.

For normal use, the concise equivalent is:

```sh
./scan.sh example.com --live
```

`--live` is the high-level mode: it resolves names, checks web reachability,
keeps only active names, and displays their status. The individual switches
remain available for automation and advanced tuning.

## Certificate enrichment

Use `--certificates` with JSON output to query all three Shodan CTL resources:

```sh
./scan.sh example.com --resolve --status --certificates --format json --output results.json
```

The JSON result keeps the existing `domain` and `hostnames` fields, adds an
`active` boolean to each hostname when `--resolve` is used, and adds a
`certificates` array containing each SHA-256 hash and its response from
`/api/v1/cert/{sha256}`. The extra certificate requests are opt-in.

## Options

```sh
./scan.sh --help
```

Available controls include HTTP timeout, retry count, concurrent DNS workers,
input files, output files, TXT or JSON formatting, active-node status, color
control, and optional certificate enrichment.

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
