"""
Quick smoke-test for the GitHub fetcher.
Run from the project root:
    python tests/test_github_fetcher.py
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.github_fetcher import fetch_files_as_dict, parse_github_url

# ── Unit tests ──────────────────────────────────────────────────────────────

def test_parse_github_url():
    owner, repo, branch = parse_github_url("https://github.com/pallets/flask")
    assert owner == "pallets"
    assert repo == "flask"
    assert branch == "HEAD"

    owner, repo, branch = parse_github_url("https://github.com/pallets/flask/tree/main")
    assert owner == "pallets"
    assert repo == "flask"
    assert branch == "main"

    print("✅ parse_github_url tests passed")


def test_fetch_real_repo():
    """Fetch a real small public repo and verify structure."""
    # Using a small, stable repo for testing
    result = fetch_files_as_dict("https://github.com/psf/requests")
    
    assert "files" in result
    assert "manifests" in result
    assert "errors" in result
    assert result["owner"] == "psf"
    assert result["repo"] == "requests"
    assert result["files_fetched"] > 0, "Expected at least one file to be fetched"

    print(f"✅ Fetched {result['files_fetched']} / {result['total_files_found']} scannable files")
    print(f"   Manifests found: {list(result['manifests'].keys())}")
    if result["errors"]:
        print(f"   ⚠️  Non-fatal errors: {result['errors']}")


def test_private_repo_error():
    """Should return an error, not crash."""
    result = fetch_files_as_dict("https://github.com/definitely-private-org-xyz/secret-repo")
    assert result["files_fetched"] == 0
    assert any("not found or is private" in e.lower() or "404" in e.lower() 
               for e in result["errors"]), f"Expected 404 error, got: {result['errors']}"
    print("✅ Private/missing repo handled gracefully")


if __name__ == "__main__":
    print("🧪 Running GitHub fetcher tests...\n")
    
    test_parse_github_url()
    
    print("\n🌐 Testing real repo fetch (requires internet)...")
    test_fetch_real_repo()
    
    print("\n🔒 Testing private/missing repo handling...")
    test_private_repo_error()
    
    print("\n✅ All tests passed!")
