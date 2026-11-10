import re
from urllib.parse import urlparse


INFO_MESSAGES = (
    "No URL entered.",
    "Could not identify a hostname.",
    "This text is not a valid URL format.",
    "No listed warning signs found.",
)

WARNING_REASONS = {
    "Contains an @ symbol; inspect carefully.": (
        "Text before @ can make a link look like one site while the browser "
        "uses the part after @ as the hostname."
    ),
    "Unusually long URL (over 100 characters).": (
        "A long address can make the real destination harder to notice."
    ),
    "Uses an IP address instead of a familiar domain.": (
        "A numeric hostname can hide the identity normally communicated by a domain name."
    ),
    "Contains many hostname segments/subdomains.": (
        "Several nested hostname labels can make the address confusing or misleading."
    ),
    "Contains a punycode-style hostname.": (
        "Punycode can represent international characters; look-alike characters may be confusing."
    ),
    "Uses HTTP. HTTPS alone does not prove trust.": (
        "HTTP does not encrypt the connection. HTTPS protects transport but does not prove honesty."
    ),
}


def inspect_url(raw_url):
    """Inspect URL text for six selected warning signs; never visit the URL."""
    url = raw_url.strip()
    findings = []

    if not url:
        return ["No URL entered."]

    # The workbook treats a URL without a scheme as HTTP.
    candidate = url if "://" in url else "http://" + url

    # urlparse can raise ValueError for malformed bracketed hosts or ports.
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return ["This text is not a valid URL format."]

    if not host:
        return ["Could not identify a hostname."]

    # 1. @ symbol
    if "@" in candidate:
        findings.append("Contains an @ symbol; inspect carefully.")

    # 2. URL longer than 100 characters
    if len(url) > 100:
        findings.append("Unusually long URL (over 100 characters).")

    # 3. IPv4-looking hostname (same pattern as the workbook)
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        findings.append("Uses an IP address instead of a familiar domain.")

    # 4. Five or more hostname labels
    labels = [part for part in host.split(".") if part]
    if len(labels) >= 5:
        findings.append("Contains many hostname segments/subdomains.")

    # 5. Punycode marker
    if "xn--" in host:
        findings.append("Contains a punycode-style hostname.")

    # 6. Plain HTTP
    if parsed.scheme.lower() == "http":
        findings.append("Uses HTTP. HTTPS alone does not prove trust.")

    if not findings:
        findings.append(
            "No listed warning signs found. This does NOT prove safety."
        )

    return findings


def has_warnings(findings):
    """Return True only when at least one actual warning was detected."""
    if not findings:
        return False
    return not findings[0].startswith(INFO_MESSAGES)


def main():
    print("EWB Phishing URL Awareness Checker")
    print("Text checks only - this program does not open URLs.")
    print("Enter sample URL text only. Type q to quit.")

    while True:
        raw_url = input("\nEnter a sample URL (or q to quit): ")

        if raw_url.strip().lower() in ("q", "quit", "exit"):
            print("Goodbye! Stay alert online.")
            break

        findings = inspect_url(raw_url)

        print("\nResult:")
        for number, item in enumerate(findings, start=1):
            print(f"{number}. {item}")
            reason = WARNING_REASONS.get(item)
            if reason:
                print(f"   Why it matters: {reason}")

        if has_warnings(findings):
            print(
                f"\nREVIEW CAREFULLY: {len(findings)} warning sign(s) found."
            )
        elif findings[0].startswith("No listed warning signs"):
            print("\nNo listed warning signs were detected.")
        else:
            print("\nPlease enter a URL in a recognisable format.")

        print("Reminder: no warning signs does NOT mean a URL is safe.")
        print("Never enter passwords or OTPs from unexpected links.")


if __name__ == "__main__":
    main()
