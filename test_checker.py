import unittest
from phishing_checker import inspect_url, has_warnings


class PhishingCheckerTests(unittest.TestCase):
    def test_clean_example_url(self):
        result = inspect_url("https://www.example.com/login")
        self.assertIn("No listed warning signs found. This does NOT prove safety.", result)
        self.assertFalse(has_warnings(result))

    def test_ip_and_http(self):
        result = inspect_url("http://192.0.2.10/account")
        self.assertIn("Uses an IP address instead of a familiar domain.", result)
        self.assertIn("Uses HTTP. HTTPS alone does not prove trust.", result)
        self.assertTrue(has_warnings(result))

    def test_at_symbol_and_http(self):
        result = inspect_url("http://example.com@sample.invalid/login")
        self.assertIn("Contains an @ symbol; inspect carefully.", result)
        self.assertIn("Uses HTTP. HTTPS alone does not prove trust.", result)

    def test_many_hostname_segments(self):
        result = inspect_url("https://a.b.c.d.e.example.invalid/path")
        self.assertIn("Contains many hostname segments/subdomains.", result)

    def test_punycode(self):
        result = inspect_url("https://xn--example.invalid/")
        self.assertIn("Contains a punycode-style hostname.", result)

    def test_empty_input(self):
        self.assertEqual(inspect_url("   "), ["No URL entered."])

    def test_malformed_url_does_not_crash(self):
        self.assertEqual(
            inspect_url("http://[bad"),
            ["This text is not a valid URL format."]
        )

    def test_missing_scheme_defaults_to_http(self):
        result = inspect_url("www.example.com")
        self.assertIn("Uses HTTP. HTTPS alone does not prove trust.", result)


if __name__ == "__main__":
    unittest.main()
