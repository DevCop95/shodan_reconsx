# Security Policy

## Supported Versions

Security fixes are provided for the latest release.

| Version | Supported |
| ------- | --------- |
| 1.2.x   | Yes       |
| 1.1.x   | No        |
| 1.0.x   | No        |
| < 1.0   | No        |

## Safe Use

Passive enumeration queries Shodan CTL. DNS resolution and TCP/HTTP checks are
opt-in and must only be used for domains you own or are authorized to assess.
Active checks are limited to ports 80 and 443, use HTTP `HEAD`, validate CTL
hostnames against the requested domain (skipping invalid or out-of-scope
entries), verify TLS certificates by default (unless `-k`/`--insecure` is
explicitly passed with `--probe` or `--live`), and do not follow HTTP
redirects.

## Reporting a Vulnerability

Report vulnerabilities privately through GitHub's **Security** tab by opening
a private vulnerability report. Include reproduction steps, impact, affected
versions, and any suggested remediation.

Do not disclose a vulnerability publicly until a fix is available. Reports
will be acknowledged as soon as practical.
