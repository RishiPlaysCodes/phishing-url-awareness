# EWB Phishing URL Awareness Checker

A beginner-friendly Python command-line project that checks URL text for six selected phishing warning signs. It does **not** visit URLs, make network requests, or collect credentials.

![Demo terminal output](screenshots/sample_run.png)

## Features
- Detects an `@` symbol in the URL.
- Flags URLs longer than 100 characters.
- Flags IPv4-looking hostnames.
- Flags hostnames with five or more dot-separated labels.
- Detects the `xn--` punycode marker.
- Flags plain HTTP.
- Checks multiple entries in one run and exits with `q`.
- Explains detected warnings and handles malformed input.
- Includes automated unit tests.

## Requirements
- Python 3.10 or later.
- No third-party packages required.

## Run
```bash
python phishing_checker.py
```
On macOS/Linux, use `python3 phishing_checker.py` if needed.

## Test
```bash
python -m unittest discover -s tests -v
```

## Demo image and test evidence
The image above is a **generated illustrative preview of the program's sample output**, not a screenshot captured from a user's computer. Run the commands above to reproduce the output locally. The automated test suite is included in `tests/test_checker.py`.

## Improvements
1. Interactive loop for checking multiple URLs.
2. `REVIEW CAREFULLY` summary with warning count.
3. Graceful malformed-input handling.
4. Plain-language explanation for each warning.
5. Automated tests for normal, suspicious, empty, and malformed input.

## Limitations
This is an educational pattern checker, not a complete phishing-detection system. It does not use domain reputation, DNS, certificate validation, threat-intelligence feeds, or machine learning. A URL with no listed warning signs can still be malicious, and a URL with warnings can be legitimate.

**No listed warning signs found does NOT mean a URL is safe.** HTTPS also does not prove that a website is trustworthy.

## Ethical use
- Use harmless sample URLs for testing.
- Do not open suspicious links just to test them.
- Do not send phishing messages or collect credentials.
- Do not test systems without permission.
- Never commit passwords, API keys, access tokens, or private information.

## Author
**Rishi Gurdatta**  
EWB Courses — Cybersecurity Mini Project
