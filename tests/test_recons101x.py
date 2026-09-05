import contextlib
import http.client
import io
import json
import multiprocessing
import multiprocessing.connection
import os
import signal
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import recons101x


class FakeTTY(io.StringIO):
    def isatty(self):
        return True


# Spawn must import these targets by name; neither child can access the network.
def slow_scan_process(args, domains):
    def slow_scan(args, domains):
        if os.name != "nt":
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        args.ready.set()
        time.sleep(5)
        return 0

    with mock.patch.object(recons101x, "scan_domains", side_effect=slow_scan):
        recons101x._scan_process(args, domains)


def quick_scan_process(args, domains):
    raise SystemExit(7)


class DomainTests(unittest.TestCase):
    def test_version(self):
        self.assertEqual(recons101x.__version__, "1.0.5")

    def test_normalizes_domain(self):
        self.assertEqual(recons101x.normalize_domain(" Example.COM. "), "example.com")

    def test_supports_idn(self):
        self.assertEqual(recons101x.normalize_domain("caf\u00e9.com"), "xn--caf-dma.com")

    def test_rejects_urls_and_invalid_labels(self):
        for value in ("https://example.com", "localhost", "-bad.example"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                recons101x.normalize_domain(value)

    def test_reads_unique_domains_and_ignores_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "domains.txt"
            path.write_text("# comment\nexample.com\nEXAMPLE.COM\nexample.org\n", encoding="utf-8")
            self.assertEqual(
                recons101x.read_domains([], path), ["example.com", "example.org"]
            )

    @mock.patch("recons101x.urllib.request.urlopen")
    def test_fetches_sorted_unique_hostnames(self, urlopen):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = json.dumps(
            ["www.example.com", "example.com", "www.example.com"]
        ).encode()
        urlopen.return_value = response

        self.assertEqual(
            recons101x.fetch_hostnames("example.com", timeout=1, retries=0),
            ["example.com", "www.example.com"],
        )

    def test_formats_text_with_ips(self):
        results = [
            {
                "domain": "example.com",
                "hostnames": [{"hostname": "www.example.com", "ips": ["1.2.3.4"]}],
            }
        ]
        self.assertEqual(
            recons101x.format_text(results, include_ips=True),
            "example.com\twww.example.com\t1.2.3.4\n",
        )

    @mock.patch("recons101x.fetch_json")
    def test_fetches_certificate_hashes_from_domain_endpoint(self, fetch_json):
        fetch_json.return_value = [
            "A" * 64,
            {"sha256": "b" * 64},
            "not-a-sha256",
            "A" * 64,
        ]
        self.assertEqual(
            recons101x.fetch_certificate_hashes("example.com", timeout=1, retries=0),
            ["a" * 64, "b" * 64],
        )

    def test_formats_active_status_and_keeps_green_for_active_nodes(self):
        results = [
            {
                "domain": "example.com",
                "hostnames": [
                    {"hostname": "online.example.com", "ips": ["1.2.3.4"], "active": True},
                    {"hostname": "offline.example.com", "ips": [], "active": False},
                ],
            }
        ]
        output = recons101x.format_text(results, include_ips=True, include_status=True, color=True)
        self.assertIn("\033[1;32mACTIVE\033[0m", output)
        self.assertIn("INACTIVE", output)

    def test_pretty_output_is_fixed_width_and_truncates_long_values(self):
        results = [
            {
                "domain": "example.com",
                "hostnames": [
                    {
                        "hostname": "very-long-hostname-" + "x" * 100 + ".example.com",
                        "ips": ["2001:db8::1", "2001:db8::2"],
                        "state": "DNS_ONLY",
                        "active": True,
                    }
                ],
            }
        ]
        output = recons101x.format_text(
            results, include_ips=True, include_status=True, pretty=True, width=80
        )
        self.assertIn("DOMAIN", output)
        self.assertIn("DNS_ONLY", output)
        self.assertIn("...", output)
        self.assertLessEqual(max(map(len, output.rstrip().splitlines())), 80)

    def test_classifies_reachability_and_builds_summary(self):
        entries = [
            recons101x.build_hostname_entry("stale.example.com", [], [], {}, False, True, True),
            recons101x.build_hostname_entry("dns.example.com", ["1.2.3.4"], [], {}, True, True, True),
            recons101x.build_hostname_entry("tcp.example.com", ["1.2.3.5"], [443], {}, True, True, True),
            recons101x.build_hostname_entry(
                "http.example.com", ["1.2.3.6"], [443], {"https": 200}, True, True, True
            ),
        ]
        self.assertEqual(
            [entry["state"] for entry in entries],
            ["STALE", "DNS_ONLY", "TCP_REACHABLE", "HTTP_REACHABLE"],
        )
        self.assertEqual(
            recons101x.summarize_entries(entries),
            {"total": 4, "dns": 3, "tcp": 2, "http": 1, "stale": 1},
        )

    @mock.patch("recons101x.socket.create_connection")
    def test_probe_hostname_reports_reachable_web_ports(self, create_connection):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        create_connection.side_effect = [connection, OSError("closed")]

        self.assertEqual(recons101x.probe_hostname("online.example.com", timeout=1), [443])
        self.assertEqual(
            [call.args for call in create_connection.call_args_list],
            [(('online.example.com', 443),), (('online.example.com', 80),)],
        )

    def test_live_mode_is_a_single_high_level_switch(self):
        args = recons101x.apply_mode(
            recons101x.build_parser().parse_args(["example.com", "--live"])
        )
        self.assertTrue(args.resolve)
        self.assertTrue(args.probe)
        self.assertTrue(args.active_only)
        self.assertTrue(args.status)


class NetworkIsolatedTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for target in (
            "recons101x.urllib.request.urlopen",
            "recons101x.socket.getaddrinfo",
            "recons101x.socket.create_connection",
        ):
            self.stack.enter_context(
                mock.patch(target, side_effect=AssertionError("unexpected network access"))
            )


class ReliabilityTests(NetworkIsolatedTests):
    def test_fetch_json_retries_transport_and_decode_errors(self):
        for error in (
            http.client.IncompleteRead(b'{"partial"', 10),
            http.client.HTTPException("bad response"),
            OSError("connection reset"),
            ValueError("invalid JSON"),
        ):
            with self.subTest(error=type(error).__name__):
                response = mock.MagicMock()
                response.__enter__.return_value = response
                response.read.side_effect = [error, b'{"ok": true}']
                with mock.patch("recons101x.urllib.request.urlopen", return_value=response) as open_url, \
                        mock.patch("recons101x.time.sleep") as sleep:
                    self.assertEqual(
                        recons101x.fetch_json("https://example.com/", timeout=1, retries=1),
                        {"ok": True},
                    )
                self.assertEqual(open_url.call_count, 2)
                self.assertEqual(open_url.call_args.kwargs["timeout"], 1)
                sleep.assert_called_once_with(1)

    def test_fetch_json_wraps_final_failure_and_preserves_retry_backoff(self):
        for error in (
            http.client.IncompleteRead(b"partial", 10),
            http.client.HTTPException("bad response"),
            OSError("connection reset"),
            ValueError("invalid JSON"),
        ):
            for retries in (0, 2):
                with self.subTest(error=type(error).__name__, retries=retries), \
                        mock.patch("recons101x.urllib.request.urlopen", side_effect=error) as open_url, \
                        mock.patch("recons101x.time.sleep") as sleep:
                    with self.assertRaisesRegex(RuntimeError, "could not query"):
                        recons101x.fetch_json("https://example.com/", timeout=1, retries=retries)
                    self.assertEqual(open_url.call_count, retries + 1)
                    self.assertEqual(sleep.call_args_list, [mock.call(2**i) for i in range(retries)])

    def test_http_protocol_failures_are_ignored_but_http_error_status_is_kept(self):
        for error in (http.client.HTTPException("bad response"), http.client.IncompleteRead(b"", 1)):
            with self.subTest(error=type(error).__name__), mock.patch(
                "recons101x.urllib.request.urlopen",
                side_effect=[error, urllib.error.HTTPError("http://example.com/", 503, "busy", {}, None)],
            ) as open_url:
                self.assertEqual(
                    recons101x.probe_http_services("example.com", [443, 80], timeout=1),
                    {"http": 503},
                )
                self.assertEqual(open_url.call_count, 2)

    def test_check_hostname_runs_only_applicable_stages_in_order(self):
        cases = (
            (False, False, [], [], {}),
            (True, False, ["192.0.2.1"], [], {}),
            (False, True, [], [], {}),
            (True, True, [], [], {}),
            (True, True, ["192.0.2.1"], [], {}),
            (False, True, ["192.0.2.1"], [443], {}),
            (True, True, ["192.0.2.1"], [443], {"https": 200}),
        )
        for resolve, probe, ips, ports, http in cases:
            with self.subTest(resolve=resolve, probe=probe, ips=ips, ports=ports, http=http):
                stages = mock.Mock()
                stages.resolve.return_value = ips
                stages.probe.return_value = ports
                stages.http.return_value = http
                with mock.patch.multiple(
                    recons101x,
                    resolve_hostname=stages.resolve,
                    probe_hostname=stages.probe,
                    probe_http_services=stages.http,
                ):
                    entry = recons101x.check_hostname("example.com", resolve, probe, 0.5)
                expected_calls = []
                if resolve or probe:
                    expected_calls.append(mock.call.resolve("example.com"))
                if probe and ips:
                    expected_calls.append(mock.call.probe("example.com", 0.5))
                if probe and ports:
                    expected_calls.append(mock.call.http("example.com", ports, 0.5))
                self.assertEqual(stages.mock_calls, expected_calls)
                self.assertEqual(
                    entry,
                    recons101x.build_hostname_entry(
                        "example.com", ips, ports, http, resolve, resolve, probe
                    ),
                )


class ScanTests(NetworkIsolatedTests):
    def setUp(self):
        super().setUp()
        self.stdout = self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stderr = self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.stack.enter_context(mock.patch("recons101x.os.system"))
        self.stack.enter_context(mock.patch.dict(os.environ))
        os.environ.pop("NO_COLOR", None)
        self.hostnames = ["z.example.com", "a.example.com", "m.example.com"]
        self.hashes = ["c" * 64, "a" * 64, "b" * 64]
        for name, value in (
            ("fetch_hostnames", self.hostnames),
            ("fetch_certificate_hashes", self.hashes),
            ("fetch_certificate", {"subject": "example.com"}),
            ("resolve_hostname", ["192.0.2.1"]),
            ("probe_hostname", [443]),
            ("probe_http_services", {"https": 200}),
        ):
            setattr(self, name, self.stack.enter_context(mock.patch.object(recons101x, name, return_value=value)))

    def test_new_options_default_to_unlimited_and_progress_off(self):
        args = recons101x.build_parser().parse_args(["example.com"])
        self.assertIsNone(args.max_hosts)
        self.assertIsNone(args.max_certificates)
        self.assertIsNone(args.max_time)
        self.assertFalse(args.progress)

    def test_invalid_timeouts_are_rejected_before_network(self):
        for option in ("--timeout", "--probe-timeout", "--max-time"):
            for value in ("nan", "inf", "-inf", "0", "-1"):
                with self.subTest(option=option, value=value), mock.patch(
                    "multiprocessing.get_context", side_effect=AssertionError("invalid timeout spawned a child")
                ):
                    self.fetch_hostnames.reset_mock()
                    self.assertEqual(recons101x.main(["example.com", f"{option}={value}"]), 2)
                    self.fetch_hostnames.assert_not_called()
                    self.fetch_certificate_hashes.assert_not_called()
                    self.resolve_hostname.assert_not_called()
                    self.probe_hostname.assert_not_called()

    def test_nonpositive_caps_are_rejected_before_network(self):
        for option in ("--max-hosts", "--max-certificates"):
            for value in ("0", "-1"):
                with self.subTest(option=option, value=value):
                    self.fetch_hostnames.reset_mock()
                    self.assertEqual(recons101x.main(["example.com", option, value]), 2)
                    self.fetch_hostnames.assert_not_called()
                    self.fetch_certificate_hashes.assert_not_called()

    def test_help_and_version_exit_without_banner(self):
        for option in ("--help", "--version"):
            with self.subTest(option=option), mock.patch.object(recons101x, "print_banner") as banner:
                with self.assertRaises(SystemExit) as raised:
                    recons101x.main([option])
                self.assertEqual(raised.exception.code, 0)
                banner.assert_not_called()
                self.fetch_hostnames.assert_not_called()
        self.assertIn("1.0.5", self.stdout.getvalue())

    def test_no_color_suppresses_all_ansi_on_ttys(self):
        for options, env in ((["--no-color"], {}), (["--color"], {"NO_COLOR": ""})):
            with self.subTest(options=options), mock.patch.dict(os.environ, env), \
                    contextlib.redirect_stdout(FakeTTY()) as stdout, \
                    contextlib.redirect_stderr(FakeTTY()) as stderr:
                self.assertEqual(recons101x.main(["example.com", "--live", *options]), 0)
                self.assertIn("HTTP_REACHABLE", stdout.getvalue())
                self.assertIn("Summary:", stderr.getvalue())
                self.assertNotIn("\033[", stdout.getvalue())
                self.assertNotIn("\033[", stderr.getvalue())

    def test_color_enabled_uses_current_stdout_and_honors_no_color(self):
        with contextlib.redirect_stdout(FakeTTY()):
            self.assertTrue(recons101x.color_enabled())
            with mock.patch.dict(os.environ, {"NO_COLOR": ""}):
                self.assertFalse(recons101x.color_enabled(force=True))
        self.assertFalse(recons101x.color_enabled())

    def test_pipeline_does_not_wait_for_all_dns_and_keeps_input_order(self):
        self.fetch_hostnames.return_value = self.hostnames[:2]
        second_probed = threading.Event()

        def resolve(hostname):
            if hostname == self.hostnames[0]:
                self.assertTrue(second_probed.wait(2), "HTTP must not wait for every DNS lookup")
            return ["192.0.2.1"]

        def http(hostname, ports, timeout):
            if hostname == self.hostnames[1]:
                second_probed.set()
            return {"https": 200}

        self.resolve_hostname.side_effect = resolve
        self.probe_http_services.side_effect = http
        with mock.patch(
            "recons101x.concurrent.futures.ThreadPoolExecutor",
            wraps=recons101x.concurrent.futures.ThreadPoolExecutor,
        ) as executor:
            self.assertEqual(recons101x.main(["example.com", "--live", "--workers", "2", "--format", "json"]), 0)
        self.assertEqual(executor.call_count, 1)
        result = json.loads(self.stdout.getvalue())[0]
        self.assertEqual([entry["hostname"] for entry in result["hostnames"]], self.hostnames[:2])

    def test_live_filters_dns_only_hosts_but_summary_counts_all_selected_hosts(self):
        self.resolve_hostname.side_effect = lambda hostname: [] if hostname == self.hostnames[0] else ["192.0.2.1"]
        self.probe_hostname.side_effect = lambda hostname, timeout: [443] if hostname == self.hostnames[2] else []
        self.assertEqual(recons101x.main(["example.com", "--live", "--format", "json"]), 0)
        result = json.loads(self.stdout.getvalue())[0]
        self.assertEqual([entry["hostname"] for entry in result["hostnames"]], self.hostnames[2:])
        self.assertEqual(result["summary"], {"total": 3, "dns": 2, "tcp": 1, "http": 1, "stale": 1})
        self.assertEqual({call.args[0] for call in self.probe_hostname.call_args_list}, set(self.hostnames[1:]))
        self.probe_http_services.assert_called_once()

    def test_max_hosts_limits_active_work_and_summary(self):
        self.assertEqual(recons101x.main(["example.com", "--live", "--max-hosts", "2", "--format", "json"]), 0)
        result = json.loads(self.stdout.getvalue())[0]
        self.assertEqual([entry["hostname"] for entry in result["hostnames"]], self.hostnames[:2])
        self.assertEqual(result["summary"], {"total": 2, "dns": 2, "tcp": 2, "http": 2, "stale": 0})
        for stage in (self.resolve_hostname, self.probe_hostname, self.probe_http_services):
            self.assertCountEqual([call.args[0] for call in stage.call_args_list], self.hostnames[:2])
        self.assertRegex(self.stderr.getvalue().lower(), r"(?m).*host.*(?:limit|truncat)|.*(?:limit|truncat).*host")

    def test_max_hosts_limits_passive_text_without_enabling_active_work(self):
        self.assertEqual(recons101x.main(["example.com", "--max-hosts", "1"]), 0)
        self.assertEqual(self.stdout.getvalue(), "example.com\tz.example.com\n")
        self.resolve_hostname.assert_not_called()
        self.probe_hostname.assert_not_called()
        self.probe_http_services.assert_not_called()
        self.fetch_certificate_hashes.assert_not_called()

    def test_default_scan_is_unlimited_passive_and_does_not_spawn(self):
        with mock.patch("multiprocessing.get_context") as context:
            self.assertEqual(recons101x.main(["example.com", "--format", "json"]), 0)
        result = json.loads(self.stdout.getvalue())[0]
        self.assertEqual([entry["hostname"] for entry in result["hostnames"]], self.hostnames)
        self.assertNotIn("certificates", result)
        self.resolve_hostname.assert_not_called()
        self.probe_hostname.assert_not_called()
        self.fetch_certificate_hashes.assert_not_called()
        context.assert_not_called()
        self.assertNotRegex(self.stderr.getvalue(), r": \d+/\d+")

    def test_certificate_cap_limits_detail_requests_in_input_order(self):
        self.assertEqual(recons101x.main([
            "example.com", "--certificates", "--max-certificates", "2", "--format", "json",
        ]), 0)
        result = json.loads(self.stdout.getvalue())[0]
        self.assertEqual([item["sha256"] for item in result["certificates"]], self.hashes[:2])
        self.assertEqual([call.args[0] for call in self.fetch_certificate.call_args_list], self.hashes[:2])
        self.assertRegex(self.stderr.getvalue().lower(), r"(?m).*cert.*(?:limit|truncat)|.*(?:limit|truncat).*cert")

    def test_certificates_remain_unlimited_and_txt_behavior_is_unchanged(self):
        self.assertEqual(recons101x.main(["example.com", "--certificates", "--format", "txt"]), 0)
        self.assertEqual([call.args[0] for call in self.fetch_certificate.call_args_list], self.hashes)
        self.assertEqual(self.stdout.getvalue(), "".join(f"example.com\t{host}\n" for host in self.hostnames))

    def test_certificate_cap_does_not_enable_certificate_queries(self):
        self.assertEqual(recons101x.main(["example.com", "--max-certificates", "1"]), 0)
        self.fetch_certificate_hashes.assert_not_called()
        self.fetch_certificate.assert_not_called()

    def test_progress_reports_first_every_tenth_and_final_completion_only_on_stderr(self):
        self.fetch_hostnames.return_value = [f"h{i}.example.com" for i in range(12)]
        self.fetch_certificate_hashes.return_value = [f"{i:064x}" for i in range(12)]
        self.assertEqual(recons101x.main([
            "example.com", "--resolve", "--certificates", "--progress", "--format", "json",
        ]), 0)
        result = json.loads(self.stdout.getvalue())[0]
        self.assertEqual(len(result["hostnames"]), 12)
        self.assertEqual(len(result["certificates"]), 12)
        progress = [line for line in self.stderr.getvalue().splitlines() if line.endswith("/12")]
        self.assertEqual(len(progress), 6)
        for offset in (0, 3):
            group = progress[offset:offset + 3]
            self.assertEqual([line.rsplit(": ", 1)[1] for line in group], ["1/12", "10/12", "12/12"])
            self.assertEqual(len({line.rsplit(": ", 1)[0] for line in group}), 1)
            self.assertTrue(all(line.startswith("[+] ") for line in group))

    def test_progress_text_is_parseable_and_single_completion_is_not_duplicated(self):
        self.assertEqual(recons101x.main(["example.com", "--resolve", "--max-hosts", "1", "--progress"]), 0)
        self.assertEqual(self.stdout.getvalue(), "example.com\tz.example.com\t192.0.2.1\n")
        self.assertEqual(sum(line.endswith(": 1/1") for line in self.stderr.getvalue().splitlines()), 1)

    def test_keyboard_interrupt_returns_130(self):
        self.fetch_hostnames.side_effect = KeyboardInterrupt
        try:
            self.assertEqual(recons101x.main(["example.com"]), 130)
        except KeyboardInterrupt:
            self.fail("main must return 130 rather than propagate KeyboardInterrupt")

    def test_scan_process_starts_parent_watcher_before_scan_and_forwards_return_code(self):
        args = recons101x.build_parser().parse_args(["example.com"])
        steps = mock.Mock()
        steps.scan.return_value = 7
        with mock.patch.object(recons101x, "scan_domains", steps.scan), \
                mock.patch("recons101x.threading.Thread", steps.thread):
            with self.assertRaises(SystemExit) as raised:
                recons101x._scan_process(args, ["example.com"])
        self.assertEqual(raised.exception.code, 7)
        self.assertEqual(steps.mock_calls, [
            mock.call.thread(target=recons101x._watch_parent, daemon=True),
            mock.call.thread().start(),
            mock.call.scan(args, ["example.com"]),
        ])

    def test_parent_watcher_exits_only_after_parent_sentinel_is_ready(self):
        for parent in (None, mock.Mock()):
            with self.subTest(has_parent=parent is not None):
                steps = mock.Mock()
                steps.parent.return_value = parent
                with mock.patch("multiprocessing.parent_process", steps.parent), \
                        mock.patch("multiprocessing.connection.wait", steps.wait), \
                        mock.patch("recons101x.os._exit", steps.exit):
                    recons101x._watch_parent()
                expected = [mock.call.parent()]
                if parent is not None:
                    expected += [mock.call.wait([parent.sentinel]), mock.call.exit(1)]
                self.assertEqual(steps.mock_calls, expected)

    def test_timeout_uses_spawn_and_kills_then_joins_child(self):
        with mock.patch("multiprocessing.get_context") as context, \
                mock.patch("recons101x.time.monotonic", side_effect=[0, 1]):
            process = context.return_value.Process.return_value
            process.is_alive.return_value = True
            self.assertEqual(recons101x.main(["example.com", "--max-time", "0.1"]), 1)
        context.assert_called_once_with("spawn")
        process_factory = context.return_value.Process
        self.assertIs(process_factory.call_args.kwargs["target"], recons101x._scan_process)
        args, domains = process_factory.call_args.kwargs["args"]
        self.assertEqual(args.max_time, 0.1)
        self.assertEqual(domains, ["example.com"])
        process.start.assert_called_once_with()
        self.assertEqual(process.join.call_args_list, [mock.call(timeout=0.1), mock.call()])
        process.kill.assert_called_once_with()
        process.terminate.assert_not_called()
        self.assertEqual(process.mock_calls[-2:], [mock.call.kill(), mock.call.join()])
        self.assertIn("error", self.stderr.getvalue().lower())
        self.fetch_hostnames.assert_not_called()

    def test_large_deadline_chunks_joins_and_forwards_exit_code(self):
        with mock.patch("multiprocessing.get_context") as context, \
                mock.patch("recons101x.time.monotonic", side_effect=[0, 3600, 2147483]):
            process = context.return_value.Process.return_value
            process.is_alive.side_effect = [True, True, False, False]
            process.exitcode = 7
            self.assertEqual(recons101x.main(["example.com", "--max-time", "2147484"]), 7)
        self.assertEqual(process.join.call_args_list, [
            mock.call(timeout=3600), mock.call(timeout=3600), mock.call(timeout=1),
        ])
        process.kill.assert_not_called()
        process.terminate.assert_not_called()
        self.fetch_hostnames.assert_not_called()

    def test_keyboard_interrupt_kills_and_reaps_child(self):
        with mock.patch("multiprocessing.get_context") as context:
            process = context.return_value.Process.return_value
            process.is_alive.return_value = True
            process.join.side_effect = [KeyboardInterrupt, None]
            try:
                self.assertEqual(recons101x.main(["example.com", "--max-time", "5"]), 130)
            except KeyboardInterrupt:
                self.fail("main must return 130 rather than propagate KeyboardInterrupt")
        process.kill.assert_called_once_with()
        process.terminate.assert_not_called()
        self.assertEqual(process.join.call_count, 2)

    def test_real_spawn_timeout_kills_ready_worker_and_leaves_no_child(self):
        context = multiprocessing.get_context("spawn")
        ready = context.Event()
        parser = recons101x.build_parser()
        parser.set_defaults(ready=ready)
        original_start = context.Process.start
        original_children = {child.pid for child in multiprocessing.active_children()}
        started = None

        def start_ready(process):
            nonlocal started
            original_start(process)
            self.addCleanup(process.join, 5)
            self.addCleanup(lambda: process.kill() if process.is_alive() else None)
            self.assertTrue(ready.wait(5), "worker did not reach the synthetic scan")
            started = time.monotonic()

        # Exclude spawn startup from the short deadline, but exercise the real worker entry point.
        with mock.patch.object(recons101x, "_scan_process", slow_scan_process), \
                mock.patch.object(recons101x, "build_parser", return_value=parser), \
                mock.patch.object(context.Process, "start", start_ready):
            self.assertEqual(recons101x.main(["example.com", "--max-time", "0.1"]), 1)
        self.assertTrue(ready.is_set())
        self.assertIsNotNone(started)
        self.assertLess(time.monotonic() - started, 4)
        self.assertFalse({child.pid for child in multiprocessing.active_children()} - original_children)
        self.fetch_hostnames.assert_not_called()

    def test_real_spawn_forwards_nonzero_exit_code(self):
        with mock.patch.object(recons101x, "_scan_process", quick_scan_process):
            self.assertEqual(recons101x.main(["example.com", "--max-time", "5"]), 7)
        self.fetch_hostnames.assert_not_called()


if __name__ == "__main__":
    unittest.main()
