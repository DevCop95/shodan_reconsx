# Recons101x

[![CI](https://github.com/DevCop95/shodan_reconsx/actions/workflows/ci.yml/badge.svg)](https://github.com/DevCop95/shodan_reconsx/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/DevCop95/shodan_reconsx)](https://github.com/DevCop95/shodan_reconsx/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)

![Recons101x blood-red ASCII banner](assets/banner.svg)

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
`domain<TAB>hostname<TAB>ip1,ip2`. This option performs DNS lookups only. It
does not scan ports or send requests to discovered hostnames.

## Options

```sh
./scan.sh --help
```

Available controls include HTTP timeout, retry count, concurrent DNS workers,
input files, output files, and TXT or JSON formatting.

## Project Structure

```text
recons101x/
|-- assets/
|   `-- banner.svg
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
