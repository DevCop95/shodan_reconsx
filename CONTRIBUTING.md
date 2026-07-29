# Contributing

Contributions that improve reliability, portability, documentation, or test
coverage are welcome.

## Development Setup

1. Fork and clone the repository.
2. Create a focused branch from `main`.
3. Use Python 3.10 or newer.
4. Install the project locally with `python -m pip install --editable .`.
5. Make the smallest change that solves the problem.

No runtime dependencies are required.

## Validation

Run the complete local validation before opening a pull request:

```sh
python -m compileall -q src tests
python -m unittest discover -s tests -v
python src/recons101x.py --version
```

On Linux and Termux, also validate the launcher:

```sh
bash -n scan.sh
./scan.sh --help
```

On Windows PowerShell:

```powershell
.\scan.ps1 --help
```

## Pull Requests

- Keep each pull request limited to one clear concern.
- Explain the behavior change and why it is needed.
- Add or update tests for behavior changes.
- Update the README when usage or output changes.
- Do not include target lists, scan results, credentials, or personal data.
- Confirm that you are authorized to contribute the submitted code.

By submitting a contribution, you agree that it may be distributed under the
MIT License.

## Security Reports

Do not open public issues for vulnerabilities. Follow the private reporting
instructions in [SECURITY.md](SECURITY.md).
