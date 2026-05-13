"""
SecureAgent — GitHub REST API fetcher.

Fetches source files from a public GitHub repository using the
GitHub Trees API (no auth needed for public repos, but a token
dramatically increases rate limits).

Usage
-----
    from utils.github_fetcher import fetch_repo_files, FileContent

    files = fetch_repo_files("https://github.com/owner/repo")
    for f in files:
        print(f.path, len(f.content))
"""
from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from mcp_server.config import get_settings

logger = logging.getLogger(__name__)

# File extensions we care about for security scanning
SCAN_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".sh", ".rb", ".php"}
# Dependency manifests
DEP_FILES = {"requirements.txt", "package.json", "Pipfile", "pyproject.toml", "yarn.lock"}

GITHUB_API_BASE = "https://api.github.com"


@dataclass
class FileContent:
    """A single file fetched from GitHub."""
    path: str
    content: str
    size_bytes: int = 0


@dataclass
class RepoFiles:
    """All files fetched from a repository."""
    owner: str
    repo: str
    source_files: list[FileContent]      # code files (SCAN_EXTENSIONS)
    dep_files: dict[str, str]            # filename → raw content


class GitHubFetchError(Exception):
    """Raised when we cannot fetch from GitHub."""


def parse_github_url(url: str) -> tuple[str, str]:
    """
    Extract (owner, repo) from a GitHub URL.

    Accepts:
      https://github.com/owner/repo
      https://github.com/owner/repo.git
      https://github.com/owner/repo/tree/main
    """
    parsed = urlparse(url.strip())
    if parsed.hostname not in ("github.com", "www.github.com"):
        raise GitHubFetchError(f"Not a GitHub URL: {url!r}")

    # Strip leading slash and split path segments
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise GitHubFetchError(f"Cannot extract owner/repo from URL: {url!r}")

    owner = parts[0]
    repo = parts[1].removesuffix(".git")
    return owner, repo


def _build_client() -> httpx.Client:
    settings = get_settings()
    return httpx.Client(
        headers=settings.github_headers,
        timeout=30.0,
        follow_redirects=True,
    )


def _get_default_branch(client: httpx.Client, owner: str, repo: str) -> str:
    """Fetch the default branch name for a repo."""
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
    resp = client.get(url)
    if resp.status_code == 404:
        raise GitHubFetchError(f"Repository '{owner}/{repo}' not found (404). Is it public?")
    if resp.status_code == 401:
        raise GitHubFetchError("GitHub returned 401 Unauthorized. The repository may be private.")
    resp.raise_for_status()
    return resp.json().get("default_branch", "main")


def _get_file_tree(
    client: httpx.Client, owner: str, repo: str, branch: str
) -> list[dict]:
    """Return the recursive file tree for a repository."""
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    resp = client.get(url)
    if resp.status_code == 403:
        raise GitHubFetchError(
            "GitHub rate limit exceeded. Add a GITHUB_TOKEN to .env to increase limit."
        )
    resp.raise_for_status()
    data = resp.json()
    if data.get("truncated"):
        logger.warning("Repository tree was truncated by GitHub — very large repo.")
    return [item for item in data.get("tree", []) if item.get("type") == "blob"]


def _fetch_file_content(client: httpx.Client, owner: str, repo: str, path: str) -> str | None:
    """Download a single file via the Contents API. Returns None on error."""
    settings = get_settings()
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}"
    try:
        resp = client.get(url, timeout=20.0)
        if resp.status_code != 200:
            logger.warning("Skipping %s — HTTP %s", path, resp.status_code)
            return None
        data = resp.json()
        size_kb = data.get("size", 0) / 1024
        if size_kb > settings.max_file_size_kb:
            logger.info("Skipping %s — size %.1f KB exceeds limit", path, size_kb)
            return None
        encoded = data.get("content", "")
        return base64.b64decode(encoded).decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to fetch %s: %s", path, exc)
        return None


def fetch_repo_files(github_url: str) -> RepoFiles:
    """
    Main entry point: fetch all scannable files from a public GitHub repo.

    Parameters
    ----------
    github_url:
        Full GitHub repository URL, e.g. ``https://github.com/owner/repo``.

    Returns
    -------
    RepoFiles
        Dataclass containing source files and dependency manifests.

    Raises
    ------
    GitHubFetchError
        If the repo cannot be accessed or the URL is invalid.
    """
    settings = get_settings()
    owner, repo = parse_github_url(github_url)
    logger.info("Fetching repo: %s/%s", owner, repo)

    with _build_client() as client:
        branch = _get_default_branch(client, owner, repo)
        logger.info("Default branch: %s", branch)

        tree = _get_file_tree(client, owner, repo, branch)
        logger.info("Total blobs in tree: %d", len(tree))

        source_files: list[FileContent] = []
        dep_files: dict[str, str] = {}
        fetched = 0

        for item in tree:
            path: str = item["path"]
            filename = path.split("/")[-1]
            ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""

            is_scan_target = ext in SCAN_EXTENSIONS
            is_dep_file = filename in DEP_FILES

            if not (is_scan_target or is_dep_file):
                continue

            if fetched >= settings.max_files:
                logger.warning("Reached MAX_FILES limit (%d). Stopping early.", settings.max_files)
                break

            content = _fetch_file_content(client, owner, repo, path)
            if content is None:
                continue

            fetched += 1
            size = item.get("size", len(content.encode()))

            if is_dep_file:
                dep_files[filename] = content
                logger.debug("Dep file: %s (%d bytes)", path, size)
            else:
                source_files.append(FileContent(path=path, content=content, size_bytes=size))
                logger.debug("Source file: %s (%d bytes)", path, size)

        logger.info(
            "Fetched %d source files, %d dep files from %s/%s",
            len(source_files), len(dep_files), owner, repo,
        )

    return RepoFiles(
        owner=owner,
        repo=repo,
        source_files=source_files,
        dep_files=dep_files,
    )
