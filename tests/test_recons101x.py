import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import recons101x


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


if __name__ == "__main__":
    unittest.main()
