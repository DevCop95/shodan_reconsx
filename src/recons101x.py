#!/usr/bin/env python3
"""Passive subdomain enumeration through Shodan CTL."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable


API_URL = "https://ctl.shodan.io/api/v1/domain/{domain}/hostnames"
__version__ = "1.0.0"
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
BANNER = r"""
 ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █   ██████    ████     █████    ████   ▒██   ██▒
▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ ▒██    ▒  ░░███   ███░░░███ ░░███   ▒▒ █ █ ▒░
▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒░ ▓██▄      ░███  ███   ░░███ ░███   ░░  █   ░
▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒  ▒   ██▒   ░███ ░███    ░███ ░███    ░ █ █ ▒
░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░▒██████▒▒   ░███ ░███    ░███ ░███   ▒██▒ ▒██▒
░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░   ░███ ░░███   ███  ░███   ▒▒ ░ ░▓ ░
  ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░░ ░▒  ░ ░   █████ ░░░█████░   █████  ░░   ░▒ ░
  ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░ ░  ░  ░    ░░░░░    ░░░░░░   ░░░░░    ░    ░
   ░        ░  ░░ ░          ░ ░           ░       ░                       ░    ░
                ░
"""


def print_banner() -> None:
    use_color = sys.stderr.isatty() and "NO_COLOR" not in os.environ
    if os.name == "nt":
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
        if use_color:
            os.system("")  # Enable ANSI processing in supported Windows terminals.
    if use_color:
        print(f"\033[1;31m{BANNER}\033[0m", file=sys.stderr)
    else:
        print(BANNER, file=sys.stderr)


def normalize_domain(value: str) -> str:
    domain = value.strip().rstrip(".").lower()
    if not domain or "://" in domain or "/" in domain:
        raise ValueError(f"invalid domain: {value!r}")

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid domain: {value!r}") from exc

    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(not LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError(f"invalid domain: {value!r}")
    return domain


def fetch_hostnames(domain: str, timeout: float, retries: int) -> list[str]:
    request = urllib.request.Request(
        API_URL.format(domain=domain),
        headers={"Accept": "application/json", "User-Agent": "shodan-domain-recon/1.0"},
    )
    last_error: Exception | None = None

    for attempt in range(retries + 1):
        try:
            # The request always uses the fixed HTTPS API_URL and a validated domain.
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
                payload = json.load(response)
            if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
                raise ValueError("unexpected API response")
            return sorted(set(payload))
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(2**attempt)

    raise RuntimeError(f"could not query {domain}: {last_error}")


def resolve_hostname(hostname: str) -> list[str]:
    try:
        addresses = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    return sorted({address[4][0] for address in addresses})


def read_domains(values: Iterable[str], input_file: Path | None) -> list[str]:
    candidates = list(values)
    if input_file:
        try:
            candidates.extend(
                line.strip()
                for line in input_file.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
        except OSError as exc:
            raise ValueError(f"could not read {input_file}: {exc}") from exc

    if not candidates:
        raise ValueError("provide at least one domain or use --input")
    return list(dict.fromkeys(normalize_domain(value) for value in candidates))


def format_text(results: list[dict[str, object]], include_ips: bool) -> str:
    lines = []
    for result in results:
        domain = str(result["domain"])
        for entry in result["hostnames"]:
            hostname = str(entry["hostname"])
            fields = [domain, hostname]
            if include_ips:
                fields.append(",".join(entry["ips"]))
            lines.append("\t".join(fields))
    return "\n".join(lines) + ("\n" if lines else "")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Enumerate hostnames for one or more domains through Shodan CTL."
    )
    parser.add_argument("domains", nargs="*", metavar="DOMAIN")
    parser.add_argument("-i", "--input", type=Path, help="file containing one domain per line")
    parser.add_argument("-o", "--output", type=Path, help="output file (default: stdout)")
    parser.add_argument("-f", "--format", choices=("txt", "json"), default="txt")
    parser.add_argument("--resolve", action="store_true", help="resolve A/AAAA records for each hostname")
    parser.add_argument("--workers", type=int, default=10, help="concurrent DNS lookups (10)")
    parser.add_argument("--timeout", type=float, default=15, help="HTTP timeout in seconds (15)")
    parser.add_argument("--retries", type=int, default=2, help="HTTP retries (2)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    print_banner()
    args = build_parser().parse_args(argv)
    if args.workers < 1 or args.timeout <= 0 or args.retries < 0:
        print("error: workers must be >= 1, timeout > 0, and retries >= 0", file=sys.stderr)
        return 2

    try:
        domains = read_domains(args.domains, args.input)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    results: list[dict[str, object]] = []
    failed = False
    for domain in domains:
        print(f"[+] Querying {domain}", file=sys.stderr)
        try:
            hostnames = fetch_hostnames(domain, args.timeout, args.retries)
        except RuntimeError as exc:
            print(f"[-] {exc}", file=sys.stderr)
            failed = True
            continue

        ips_by_hostname: dict[str, list[str]] = {}
        if args.resolve and hostnames:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
                ips_by_hostname = dict(zip(hostnames, executor.map(resolve_hostname, hostnames)))

        results.append(
            {
                "domain": domain,
                "hostnames": [
                    {"hostname": hostname, "ips": ips_by_hostname.get(hostname, [])}
                    for hostname in hostnames
                ],
            }
        )
        print(f"[+] Found {len(hostnames)} hostnames", file=sys.stderr)

    content = (
        json.dumps(results, ensure_ascii=True, indent=2) + "\n"
        if args.format == "json"
        else format_text(results, args.resolve)
    )
    if args.output:
        try:
            args.output.write_text(content, encoding="utf-8")
        except OSError as exc:
            print(f"error: could not write {args.output}: {exc}", file=sys.stderr)
            return 1
    else:
        sys.stdout.write(content)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
