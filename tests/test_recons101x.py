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
        self.assertEqual(recons101x.__version__, "1.0.0")

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


if __name__ == "__main__":
    unittest.main()
