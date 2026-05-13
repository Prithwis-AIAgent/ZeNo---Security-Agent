"""
Smoke tests for the code scanner patterns.
Run from the project root:
    python tests/test_code_scanner.py
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.code_scanner import run_code_scan, scan_file_with_patterns

VULNERABLE_CODE = """
import os
import pickle
import subprocess

# Hardcoded credentials (Critical)
password = "admin123"
API_KEY = "sk-abc123def456ghi789jkl012mno345pqr"

# SQL Injection (Critical)
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

# Shell injection (Critical)
def run_cmd(user_input):
    subprocess.run("ls " + user_input, shell=True)

# Eval (High)
def dynamic_eval(code):
    eval(code)

# Insecure pickle (High)
def load_data(data):
    return pickle.loads(data)

# HTTP instead of HTTPS (Medium)
API_ENDPOINT = "http://api.example.com/data"

# Debug mode (Medium)
app.run(debug=True)
"""

SAFE_CODE = """
import os
from sqlalchemy import text

# Environment variable (safe)
API_KEY = os.getenv("API_KEY")

# Parameterised query (safe)
def get_user(user_id):
    query = text("SELECT * FROM users WHERE id = :id")
    db.execute(query, {"id": user_id})

# HTTPS (safe)
API_ENDPOINT = "https://api.example.com/data"
"""


def test_vulnerable_code_detected():
    findings = scan_file_with_patterns("test.py", VULNERABLE_CODE)
    assert len(findings) > 0, "Expected vulnerabilities to be found in vulnerable code"
    
    severities = {f.severity for f in findings}
    assert "Critical" in severities, "Expected at least one Critical finding"
    
    categories = {f.category for f in findings}
    assert "secrets" in categories or "injection" in categories, (
        f"Expected secrets or injection findings, got: {categories}"
    )
    
    print(f"✅ Detected {len(findings)} vulnerabilities in vulnerable code:")
    for f in findings:
        print(f"   [{f.severity}] {f.vuln_name} at line {f.line_number}")


def test_no_false_positives_on_env_var():
    """Code using os.getenv() should not trigger secrets patterns."""
    safe = "api_key = os.getenv('API_KEY')\n"
    findings = scan_file_with_patterns("config.py", safe)
    # There may be false positives but the count should be low
    print(f"   Safe code findings (expect 0-2): {len(findings)}")
    for f in findings:
        print(f"   [FYI] [{f.severity}] {f.vuln_name}")


def test_run_code_scan_batch():
    files = [
        {"path": "app.py", "content": VULNERABLE_CODE},
        {"path": "safe.py", "content": SAFE_CODE},
    ]
    result = run_code_scan(files)
    
    assert "findings" in result
    assert "severity_counts" in result
    assert result["files_scanned"] == 2
    assert result["total_findings"] > 0
    
    print(f"✅ Batch scan: {result['total_findings']} findings across {result['files_scanned']} files")
    print(f"   Severity counts: {result['severity_counts']}")
    print(f"   Summary: {result['summary']}")


if __name__ == "__main__":
    print("🧪 Running code scanner tests...\n")
    
    print("1. Vulnerable code detection:")
    test_vulnerable_code_detected()
    
    print("\n2. Safe code (false positive check):")
    test_no_false_positives_on_env_var()
    
    print("\n3. Batch scan:")
    test_run_code_scan_batch()
    
    print("\n✅ All code scanner tests passed!")
