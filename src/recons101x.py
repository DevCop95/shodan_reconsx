#!/usr/bin/env python3
"""Passive subdomain enumeration through Shodan CTL."""

from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import json
import math
import multiprocessing
import multiprocessing.connection
import os
import re
import socket
import shutil
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable


DOMAIN_API_URL = "https://ctl.shodan.io/api/v1/domain/{domain}"
HOSTNAMES_API_URL = "https://ctl.shodan.io/api/v1/domain/{domain}/hostnames"
CERT_API_URL = "https://ctl.shodan.io/api/v1/cert/{sha256}"
API_URL = HOSTNAMES_API_URL  # Backwards-compatible name for integrations.
__version__ = "1.0.5"
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
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


def print_banner(no_color: bool = False) -> None:
    use_color = not no_color and color_enabled(stream=sys.stderr)
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
    payload = fetch_json(
        HOSTNAMES_API_URL.format(domain=domain), timeout=timeout, retries=retries
    )
    if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
        raise RuntimeError(f"could not query {domain}: unexpected API response")
    return sorted(set(payload))


def fetch_json(url: str, timeout: float, retries: int) -> object:
    """Fetch and decode one CTL JSON response with the same retry policy."""
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "shodan-domain-recon/1.0.5"},
    )
    last_error: Exception | None = None

    for attempt in range(retries + 1):
        try:
            # URLs are assembled only from validated domains or SHA-256 hashes.
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
                payload = json.load(response)
            return payload
        except (OSError, http.client.HTTPException, ValueError) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(2**attempt)

    raise RuntimeError(f"could not query {url}: {last_error}")


def _certificate_hash(item: object) -> str | None:
    if isinstance(item, str):
        candidate = item.strip().lower()
    elif isinstance(item, dict):
        candidate = next(
            (
                str(item[key]).strip().lower()
                for key in ("sha256", "sha-256", "hash", "id")
                if item.get(key)
            ),
            "",
        )
    else:
        candidate = ""
    return candidate if SHA256_RE.fullmatch(candidate) else None


def fetch_certificate_hashes(domain: str, timeout: float, retries: int) -> list[str]:
    payload = fetch_json(
        DOMAIN_API_URL.format(domain=domain), timeout=timeout, retries=retries
    )
    items: object = payload
    if isinstance(payload, dict):
        for key in ("certificates", "hashes", "data", "results"):
            if isinstance(payload.get(key), list):
                items = payload[key]
                break
    if not isinstance(items, list):
        raise RuntimeError(f"could not query certificates for {domain}: unexpected API response")
    return sorted({certificate_hash for item in items if (certificate_hash := _certificate_hash(item))})


def fetch_certificate(sha256: str, timeout: float, retries: int) -> object:
    if not SHA256_RE.fullmatch(sha256):
        raise ValueError("invalid certificate SHA-256")
    return fetch_json(CERT_API_URL.format(sha256=sha256.lower()), timeout=timeout, retries=retries)


def resolve_hostname(hostname: str) -> list[str]:
    try:
        addresses = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    return sorted({address[4][0] for address in addresses})


def probe_hostname(hostname: str, timeout: float) -> list[int]:
    """Return reachable web ports; this is opt-in because it makes network probes."""
    reachable_ports = []
    for port in (443, 80):
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                reachable_ports.append(port)
        except (OSError, TimeoutError):
            continue
    return reachable_ports


def probe_http_services(hostname: str, ports: list[int], timeout: float) -> dict[str, int]:
    """Return HTTP status codes for reachable HTTPS/HTTP services."""
    statuses: dict[str, int] = {}
    for port in ports:
        scheme = "https" if port == 443 else "http"
        request = urllib.request.Request(
            f"{scheme}://{hostname}/",
            method="HEAD",
            headers={"User-Agent": "shodan-domain-recon/1.0.5"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
                statuses[scheme] = int(getattr(response, "status", 200))
        except urllib.error.HTTPError as exc:
            # An HTTP error still proves that an HTTP server answered.
            statuses[scheme] = exc.code
        except (OSError, http.client.HTTPException):
            continue
    return statuses


def classify_state(ips: list[str], ports: list[int], http: dict[str, int]) -> str:
    if http:
        return "HTTP_REACHABLE"
    if ports:
        return "TCP_REACHABLE"
    if ips:
        return "DNS_ONLY"
    return "STALE"


def summarize_entries(entries: list[dict[str, object]]) -> dict[str, int]:
    states = [str(entry.get("state", "STALE")) for entry in entries]
    return {
        "total": len(entries),
        "dns": sum(state != "STALE" for state in states),
        "tcp": sum(state in {"TCP_REACHABLE", "HTTP_REACHABLE"} for state in states),
        "http": sum(state == "HTTP_REACHABLE" for state in states),
        "stale": sum(state == "STALE" for state in states),
    }


def build_hostname_entry(
    hostname: str,
    ips: list[str],
    ports: list[int],
    http: dict[str, int],
    include_ips: bool,
    resolve: bool,
    probe: bool,
) -> dict[str, object]:
    entry: dict[str, object] = {
        "hostname": hostname,
        "ips": ips if include_ips else [],
    }
    if resolve or probe:
        state = classify_state(ips, ports, http)
        entry["state"] = state
        entry["active"] = (
            state in {"TCP_REACHABLE", "HTTP_REACHABLE"}
            if probe
            else bool(ips)
        )
    if probe:
        entry["ports"] = ports
        entry["http"] = http
    return entry


def check_hostname(hostname: str, resolve: bool, probe: bool, timeout: float) -> dict[str, object]:
    ips = resolve_hostname(hostname) if resolve or probe else []
    ports = probe_hostname(hostname, timeout) if probe and ips else []
    http = probe_http_services(hostname, ports, timeout) if ports else {}
    return build_hostname_entry(hostname, ips, ports, http, resolve, resolve, probe)


def report_progress(label: str, completed: int, total: int, enabled: bool) -> None:
    if enabled and (completed == 1 or completed == total or completed % 10 == 0):
        print(f"[+] {label}: {completed}/{total}", file=sys.stderr, flush=True)


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


def format_text(
    results: list[dict[str, object]],
    include_ips: bool,
    include_status: bool = False,
    color: bool = False,
    pretty: bool = False,
    width: int = 120,
) -> str:
    if pretty:
        return format_pretty(results, include_ips, include_status, color, width)

    lines = []
    for result in results:
        domain = str(result["domain"])
        for entry in result["hostnames"]:
            hostname = str(entry["hostname"])
            fields = [domain, hostname]
            if include_ips:
                fields.append(",".join(entry["ips"]))
            if include_status:
                active = bool(entry.get("active"))
                status = str(entry.get("state", "ACTIVE" if active else "INACTIVE"))
                state_colors = {
                    "HTTP_REACHABLE": "1;32",
                    "TCP_REACHABLE": "1;32",
                    "DNS_ONLY": "1;33",
                    "STALE": "2;31",
                    "ACTIVE": "1;32",
                    "INACTIVE": "2;31",
                }
                if color and status in state_colors:
                    status = f"\033[{state_colors[status]}m{status}\033[0m"
                fields.append(status)
            lines.append("\t".join(fields))
    return "\n".join(lines) + ("\n" if lines else "")


def shorten(value: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return value[: width - 3] + "..."


def format_pretty(
    results: list[dict[str, object]],
    include_ips: bool,
    include_status: bool,
    color: bool,
    width: int,
) -> str:
    """Render a fixed-width human table without wrapping long hostnames/IPs."""
    rows: list[tuple[str, str, str, str]] = []
    for result in results:
        domain = str(result["domain"])
        for entry in result["hostnames"]:
            ips = ",".join(str(ip) for ip in entry.get("ips", [])) if include_ips else "-"
            if len(ips) > 1 and "," in ips:
                ips = ips.split(",", 1)[0] + ",..."
            status = ""
            if include_status:
                active = bool(entry.get("active"))
                status = str(entry.get("state", "ACTIVE" if active else "INACTIVE"))
            rows.append((domain, str(entry["hostname"]), ips, status))

    if not rows:
        return ""

    state_width = max(7, max(len(row[3]) for row in rows)) if include_status else 0
    domain_width = min(24, max(len("DOMAIN"), max(len(row[0]) for row in rows)))
    ip_width = min(38, max(len("IP / PORT"), max(len(row[2]) for row in rows)))
    separators = 9 if include_status else 7
    host_width = max(18, width - domain_width - ip_width - state_width - separators)
    if include_status:
        header = (
            f"{'DOMAIN':<{domain_width}}  {'HOSTNAME':<{host_width}}  "
            f"{'IP / PORT':<{ip_width}}  {'STATE':<{state_width}}"
        )
    else:
        header = f"{'DOMAIN':<{domain_width}}  {'HOSTNAME':<{host_width}}  {'IP / PORT':<{ip_width}}"

    lines = [header, "-" * min(width, len(header))]
    state_colors = {
        "HTTP_REACHABLE": "1;32",
        "TCP_REACHABLE": "1;32",
        "DNS_ONLY": "1;33",
        "STALE": "2;31",
        "ACTIVE": "1;32",
        "INACTIVE": "2;31",
    }
    for domain, hostname, ips, status in rows:
        fields = [
            shorten(domain, domain_width).ljust(domain_width),
            shorten(hostname, host_width).ljust(host_width),
            shorten(ips, ip_width).ljust(ip_width),
        ]
        if include_status:
            visible_status = shorten(status, state_width).ljust(state_width)
            if color and status in state_colors:
                visible_status = f"\033[{state_colors[status]}m{visible_status}\033[0m"
            fields.append(visible_status)
        lines.append("  ".join(fields).rstrip())
    return "\n".join(lines) + "\n"


def color_enabled(force: bool = False, stream: object | None = None) -> bool:
    stream = sys.stdout if stream is None else stream
    return bool(
        "NO_COLOR" not in os.environ
        and (force or (hasattr(stream, "isatty") and stream.isatty()))
    )


def colorize(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Enumerate hostnames for one or more domains through Shodan CTL."
    )
    parser.add_argument("domains", nargs="*", metavar="DOMAIN")
    parser.add_argument("-i", "--input", type=Path, help="file containing one domain per line")
    parser.add_argument("-o", "--output", type=Path, help="output file (default: stdout)")
    parser.add_argument("-f", "--format", choices=("txt", "json"), default="txt")
    parser.add_argument(
        "--live",
        action="store_true",
        help="show only hostnames with TCP or HTTP reachability on ports 443/80",
    )
    parser.add_argument("--resolve", action="store_true", help="resolve A/AAAA records for each hostname")
    parser.add_argument(
        "--probe",
        action="store_true",
        help="probe TCP and HTTP(S) on ports 443/80 (opt-in)",
    )
    parser.add_argument(
        "--active-only",
        action="store_true",
        help="output only active hostnames (requires --resolve or --probe)",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="add reachability state to text output (requires --resolve or --probe)",
    )
    parser.add_argument(
        "--certificates",
        action="store_true",
        help="include matching certificate hashes and CTL certificate data in JSON output",
    )
    color = parser.add_mutually_exclusive_group()
    color.add_argument("--color", action="store_true", help="force color in text status output")
    color.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--workers", type=int, default=10, help="concurrent hostname checks (10)")
    parser.add_argument("--timeout", type=float, default=15, help="HTTP timeout in seconds (15)")
    parser.add_argument(
        "--probe-timeout",
        type=float,
        default=3,
        help="network timeout per probe in seconds (3)",
    )
    parser.add_argument("--retries", type=int, default=2, help="HTTP retries (2)")
    parser.add_argument("--max-hosts", type=int, help="maximum hostnames per domain (default: all)")
    parser.add_argument(
        "--max-certificates", type=int,
        help="maximum certificate details per domain (default: all; requires --certificates to fetch)",
    )
    parser.add_argument(
        "--max-time", type=float,
        help="maximum scan duration in seconds, including DNS and retries (default: unlimited)",
    )
    parser.add_argument("--progress", action="store_true", help="report completed checks on stderr")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def apply_mode(args: argparse.Namespace) -> argparse.Namespace:
    """Expand user-facing modes into the existing low-level switches."""
    if args.live:
        args.resolve = True
        args.probe = True
        args.active_only = True
        args.status = True
    return args


def main(argv: list[str] | None = None) -> int:
    args = apply_mode(build_parser().parse_args(argv))
    timeouts = [args.timeout, args.probe_timeout]
    if args.max_time is not None:
        timeouts.append(args.max_time)
    if args.workers < 1 or args.retries < 0:
        print("error: workers must be >= 1 and retries >= 0", file=sys.stderr)
        return 2
    if any(not math.isfinite(value) or not 0 < value <= threading.TIMEOUT_MAX for value in timeouts):
        print(
            f"error: timeouts must be finite and > 0, up to {threading.TIMEOUT_MAX:g} seconds",
            file=sys.stderr,
        )
        return 2
    if any(value is not None and value < 1 for value in (args.max_hosts, args.max_certificates)):
        print("error: --max-hosts and --max-certificates must be >= 1", file=sys.stderr)
        return 2
    if args.status and not (args.resolve or args.probe):
        print("error: --status requires --resolve or --probe", file=sys.stderr)
        return 2
    if args.active_only and not (args.resolve or args.probe):
        print("error: --active-only requires --resolve or --probe", file=sys.stderr)
        return 2

    try:
        domains = read_domains(args.domains, args.input)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print_banner(args.no_color)
    process = None
    try:
        if args.max_time is None:
            return scan_domains(args, domains)
        # A separate process can stop blocked system DNS calls and all worker threads.
        process = multiprocessing.get_context("spawn").Process(
            target=_scan_process, args=(args, domains)
        )
        process.start()
        remaining = args.max_time
        deadline = time.monotonic() + remaining
        while True:
            # Some platforms cannot represent very large process-wait timeouts.
            process.join(timeout=min(remaining, 3600))
            if not process.is_alive():
                return process.exitcode or 0
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                print(f"error: scan exceeded --max-time {args.max_time:g} seconds", file=sys.stderr)
                return 1
    except KeyboardInterrupt:
        print("error: scan interrupted", file=sys.stderr)
        return 130
    finally:
        if process is not None and process.is_alive():
            process.kill()
            process.join()


def _watch_parent() -> None:
    parent = multiprocessing.parent_process()
    if parent is not None:
        multiprocessing.connection.wait([parent.sentinel])
        # Do not leave probes running if the supervisor is forcibly terminated.
        os._exit(1)


def _scan_process(args: argparse.Namespace, domains: list[str]) -> None:
    threading.Thread(target=_watch_parent, daemon=True).start()
    try:
        raise SystemExit(scan_domains(args, domains))
    except KeyboardInterrupt:
        raise SystemExit(130)


def scan_domains(args: argparse.Namespace, domains: list[str]) -> int:
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

        if args.max_hosts is not None and len(hostnames) > args.max_hosts:
            print(
                f"[!] Limiting {domain} to {args.max_hosts} of {len(hostnames)} hostnames",
                file=sys.stderr,
            )
            hostnames = hostnames[:args.max_hosts]

        if (args.resolve or args.probe) and hostnames:
            entries_by_hostname = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = {
                    executor.submit(
                        check_hostname, hostname, args.resolve, args.probe, args.probe_timeout
                    ): hostname
                    for hostname in hostnames
                }
                for completed, future in enumerate(concurrent.futures.as_completed(futures), 1):
                    entries_by_hostname[futures[future]] = future.result()
                    report_progress(
                        f"{domain} hostnames", completed, len(hostnames), args.progress
                    )
            all_hostname_entries = [entries_by_hostname[hostname] for hostname in hostnames]
        else:
            all_hostname_entries = [
                build_hostname_entry(hostname, [], [], {}, args.resolve, args.resolve, args.probe)
                for hostname in hostnames
            ]
        summary = summarize_entries(all_hostname_entries)
        active_count = sum(1 for entry in all_hostname_entries if entry.get("active"))
        hostname_entries = (
            [entry for entry in all_hostname_entries if entry.get("active")]
            if args.active_only
            else all_hostname_entries
        )
        result: dict[str, object] = {"domain": domain, "hostnames": hostname_entries}
        if args.resolve or args.probe:
            result["summary"] = summary

        if args.certificates:
            try:
                certificate_hashes = fetch_certificate_hashes(domain, args.timeout, args.retries)
                if args.max_certificates is not None and len(certificate_hashes) > args.max_certificates:
                    print(
                        f"[!] Limiting {domain} to {args.max_certificates} of "
                        f"{len(certificate_hashes)} certificates",
                        file=sys.stderr,
                    )
                    certificate_hashes = certificate_hashes[:args.max_certificates]
                certificates = []
                for completed, certificate_hash in enumerate(certificate_hashes, 1):
                    try:
                        certificates.append(
                            {"sha256": certificate_hash, "data": fetch_certificate(certificate_hash, args.timeout, args.retries)}
                        )
                    except (RuntimeError, ValueError) as exc:
                        print(f"[!] Could not fetch certificate {certificate_hash}: {exc}", file=sys.stderr)
                        failed = True
                    report_progress(
                        f"{domain} certificates", completed, len(certificate_hashes), args.progress
                    )
                result["certificates"] = certificates
                print(f"[+] Found {len(certificates)} related certificates", file=sys.stderr)
            except RuntimeError as exc:
                print(f"[!] Certificate enrichment failed for {domain}: {exc}", file=sys.stderr)
                result["certificates"] = []
                failed = True

        results.append(result)
        if args.resolve or args.probe:
            active_label = colorize(
                f"{active_count} active",
                "1;32",
                not args.no_color and color_enabled(args.color, sys.stderr),
            )
            filtered_label = (
                f"; kept {len(hostname_entries)}"
                if args.active_only
                else ""
            )
            print(
                f"[+] Found {len(hostnames)} hostnames ({active_label}{filtered_label})",
                file=sys.stderr,
            )
            print(
                "[+] Summary: "
                f"{summary['dns']} DNS | {summary['tcp']} TCP | "
                f"{summary['http']} HTTP | {summary['stale']} stale",
                file=sys.stderr,
            )
        else:
            print(f"[+] Found {len(hostnames)} hostnames", file=sys.stderr)

    content = (
        json.dumps(results, ensure_ascii=True, indent=2) + "\n"
        if args.format == "json"
        else format_text(
            results,
            args.resolve,
            include_status=args.status,
            color=not args.no_color and color_enabled(args.color),
            pretty=(args.output is None and args.status and sys.stdout.isatty()),
            width=shutil.get_terminal_size(fallback=(120, 24)).columns,
        )
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
