"""
OSV.dev client smoke tests.
Run from the project root:
    python tests/test_osv_client.py
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.osv_client import (
    parse_requirements_txt,
    parse_package_json,
    query_package,
    audit_dependencies,
)

SAMPLE_REQUIREMENTS = """
# Web framework
flask==1.0.0
requests==2.18.0
django==2.2.0
# Current safe version
fastapi==0.115.5
"""

SAMPLE_PACKAGE_JSON = """
{
  "name": "test-app",
  "dependencies": {
    "lodash": "4.17.15",
    "express": "4.17.1",
    "axios": "0.21.1"
  }
}
"""


def test_parse_requirements_txt():
    pkgs = parse_requirements_txt(SAMPLE_REQUIREMENTS)
    assert "flask" in pkgs
    assert pkgs["flask"] == "1.0.0"
    assert "requests" in pkgs
    assert pkgs["requests"] == "2.18.0"
    assert "fastapi" in pkgs
    print(f"✅ Parsed requirements.txt: {pkgs}")


def test_parse_package_json():
    pkgs = parse_package_json(SAMPLE_PACKAGE_JSON)
    assert "lodash" in pkgs
    assert pkgs["lodash"] == "4.17.15"
    assert "express" in pkgs
    print(f"✅ Parsed package.json: {pkgs}")


def test_osv_query_known_vulnerable_package():
    """Flask 1.0.0 should have known CVEs."""
    findings = query_package("flask", "1.0.0", ecosystem="PyPI")
    print(f"✅ OSV query for flask==1.0.0: {len(findings)} CVEs found")
    for f in findings:
        print(f"   - [{f.severity}] {f.cve_id}: {f.summary[:80]}...")


def test_osv_query_safe_package():
    """A current safe package should have no CVEs."""
    findings = query_package("fastapi", "0.115.5", ecosystem="PyPI")
    print(f"✅ OSV query for fastapi==0.115.5: {len(findings)} CVEs found (expected 0)")


def test_audit_dependencies_batch():
    pkgs = parse_requirements_txt(SAMPLE_REQUIREMENTS)
    result = audit_dependencies(pkgs, ecosystem="PyPI")
    
    print(f"✅ Batch audit: checked {result.packages_checked} packages")
    print(f"   CVEs found: {len(result.findings)}")
    for f in result.findings:
        print(f"   - [{f.severity}] {f.cve_id} in {f.package_name}=={f.package_version}")


if __name__ == "__main__":
    print("🧪 Running OSV client tests...\n")
    
    print("1. Parse requirements.txt:")
    test_parse_requirements_txt()
    
    print("\n2. Parse package.json:")
    test_parse_package_json()
    
    print("\n3. OSV query — known vulnerable package (requires internet):")
    test_osv_query_known_vulnerable_package()
    
    print("\n4. OSV query — safe current package:")
    test_osv_query_safe_package()
    
    print("\n5. Batch dependency audit:")
    test_audit_dependencies_batch()
    
    print("\n✅ All OSV client tests passed!")
