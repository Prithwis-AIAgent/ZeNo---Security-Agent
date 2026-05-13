"""
SecureAgent — Quick smoke tests (no API keys needed)

Run with:
    python -m pytest tests/ -v
or:
    python tests/test_smoke.py
"""
from __future__ import annotations

import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from utils.github_fetcher import parse_github_url, GitHubFetchError
from utils.osv_client import query_package
from agents.code_scanner import scan_files, CodeFinding
from agents.dep_auditor import parse_requirements, parse_package_json, audit_dependencies
from agents.report_writer import generate_report, ReportMetadata
from utils.github_fetcher import FileContent


class TestGitHubURLParser(unittest.TestCase):
    def test_simple_url(self):
        owner, repo = parse_github_url("https://github.com/psf/requests")
        self.assertEqual(owner, "psf")
        self.assertEqual(repo, "requests")

    def test_url_with_git_suffix(self):
        owner, repo = parse_github_url("https://github.com/psf/requests.git")
        self.assertEqual(repo, "requests")

    def test_url_with_tree(self):
        owner, repo = parse_github_url("https://github.com/psf/requests/tree/main")
        self.assertEqual(owner, "psf")
        self.assertEqual(repo, "requests")

    def test_invalid_url(self):
        with self.assertRaises(GitHubFetchError):
            parse_github_url("https://gitlab.com/owner/repo")

    def test_short_path(self):
        with self.assertRaises(GitHubFetchError):
            parse_github_url("https://github.com/owner")


class TestCodeScanner(unittest.TestCase):
    def _scan(self, code: str, filename: str = "test.py") -> list[CodeFinding]:
        files = [FileContent(path=filename, content=code, size_bytes=len(code))]
        return scan_files(files)

    def test_hardcoded_aws_key(self):
        code = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
        findings = self._scan(code)
        self.assertTrue(any(f.severity == "Critical" for f in findings))
        self.assertTrue(any("AWS" in f.vuln_name for f in findings))

    def test_sql_injection(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        findings = self._scan(code)
        self.assertTrue(any("SQL" in f.vuln_name for f in findings))

    def test_eval_usage(self):
        code = "result = eval(user_input)"
        findings = self._scan(code)
        self.assertTrue(any("eval" in f.vuln_name.lower() for f in findings))

    def test_pickle_loads(self):
        code = "import pickle\ndata = pickle.loads(user_data)"
        findings = self._scan(code)
        self.assertTrue(any("Pickle" in f.vuln_name for f in findings))

    def test_clean_code(self):
        code = "def add(a, b):\n    return a + b\n"
        findings = self._scan(code)
        self.assertEqual(findings, [])

    def test_shell_true(self):
        code = "subprocess.run(cmd, shell=True)"
        findings = self._scan(code)
        self.assertTrue(any("Shell" in f.vuln_name for f in findings))

    def test_ssl_verify_false(self):
        code = "requests.get(url, verify=False)"
        findings = self._scan(code)
        self.assertTrue(any("SSL" in f.vuln_name for f in findings))

    def test_innerHTML_xss(self):
        code = "element.innerHTML = userInput;"
        findings = self._scan(code, filename="app.js")
        self.assertTrue(any("XSS" in f.vuln_name for f in findings))

    def test_line_number_accuracy(self):
        code = "x = 1\ny = 2\neval(bad)\nz = 3"
        findings = self._scan(code)
        eval_findings = [f for f in findings if "eval" in f.vuln_name.lower()]
        self.assertTrue(any(f.line == 3 for f in eval_findings))


class TestDependencyParser(unittest.TestCase):
    def test_parse_requirements_pinned(self):
        content = "requests==2.18.0\nflask>=1.0\ndjango"
        pkgs = parse_requirements(content)
        names = [p[0] for p in pkgs]
        self.assertIn("requests", names)
        self.assertIn("flask", names)
        self.assertIn("django", names)

    def test_parse_requirements_comments(self):
        content = "# This is a comment\nrequests==2.18.0\n\n# Another comment"
        pkgs = parse_requirements(content)
        self.assertEqual(len(pkgs), 1)
        self.assertEqual(pkgs[0][0], "requests")

    def test_parse_package_json(self):
        content = '{"dependencies": {"express": "^4.18.0", "lodash": "~4.17.21"}}'
        pkgs = parse_package_json(content)
        names = [p[0] for p in pkgs]
        self.assertIn("express", names)
        self.assertIn("lodash", names)

    def test_parse_package_json_version_stripping(self):
        content = '{"dependencies": {"express": "^4.18.0"}}'
        pkgs = parse_package_json(content)
        self.assertEqual(pkgs[0][1], "4.18.0")

    def test_parse_invalid_package_json(self):
        pkgs = parse_package_json("not valid json")
        self.assertEqual(pkgs, [])


class TestReportWriter(unittest.TestCase):
    def _make_code_finding(self, severity="Critical"):
        from agents.code_scanner import CodeFinding
        return CodeFinding(
            file="app.py",
            line=10,
            vuln_name="Test Vuln",
            severity=severity,
            category="test",
            description="Test description",
            fix="Test fix",
            matched_text="test code",
        )

    def test_report_with_findings(self):
        meta = ReportMetadata(target="https://github.com/test/repo", scanned_files=1)
        finding = self._make_code_finding("High")
        report, summary = generate_report([finding], [], meta)
        self.assertIn("SecureAgent", report)
        self.assertIn("High", report)
        self.assertEqual(summary.high, 1)
        self.assertEqual(summary.total, 1)

    def test_empty_report(self):
        meta = ReportMetadata(target="test", scanned_files=0)
        report, summary = generate_report([], [], meta)
        self.assertIn("No vulnerabilities detected", report)
        self.assertEqual(summary.total, 0)

    def test_severity_counts(self):
        meta = ReportMetadata(target="test", scanned_files=2)
        findings = [
            self._make_code_finding("Critical"),
            self._make_code_finding("Critical"),
            self._make_code_finding("High"),
            self._make_code_finding("Low"),
        ]
        _, summary = generate_report(findings, [], meta)
        self.assertEqual(summary.critical, 2)
        self.assertEqual(summary.high, 1)
        self.assertEqual(summary.low, 1)


class TestOSVClient(unittest.TestCase):
    """Live integration tests — requires internet access."""

    def test_known_vulnerable_package(self):
        """requests 2.18.0 has known CVEs."""
        findings = query_package("requests", "2.18.0", "PyPI")
        # This is a live API call — just check it returns a list
        self.assertIsInstance(findings, list)

    def test_unknown_package(self):
        findings = query_package("definitely-not-a-real-package-xyz123", "1.0.0", "PyPI")
        self.assertEqual(findings, [])

    def test_network_error_returns_empty(self):
        """Bad ecosystem should return empty list, not crash."""
        findings = query_package("requests", "2.18.0", "NotAnEcosystem")
        self.assertIsInstance(findings, list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
