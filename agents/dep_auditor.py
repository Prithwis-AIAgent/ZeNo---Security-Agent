"""
SecureAgent — Agent 2: Dependency Auditor

Parses requirements.txt / package.json from a repository and queries
OSV.dev for known CVEs on each package.

This module exposes:
  - parse_requirements(content)   → list of (name, version) pairs
  - parse_package_json(content)   → list of (name, version) pairs
  - audit_dependencies(dep_files) → list[DepFinding]
  - build_dep_auditor()           → CrewAI Agent
  - build_dep_task()              → CrewAI Task
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass

from crewai import Agent, Task

from utils.osv_client import CVEFinding, query_packages_batch

logger = logging.getLogger(__name__)


@dataclass
class DepFinding:
    """A dependency with one or more CVEs."""
    package: str
    version: str
    ecosystem: str
    cve_id: str
    severity: str
    description: str
    affected_versions: list[str]
    references: list[str]

    def to_markdown_row(self) -> str:
        refs = ", ".join(self.references[:3]) if self.references else "N/A"
        return (
            f"- **{self.package}=={self.version}** → `{self.cve_id}` ({self.severity})\n"
            f"  - {self.description}\n"
            f"  - **References**: {refs}\n"
        )


# ── Parsers ──────────────────────────────────────────────────────────────────

def parse_requirements(content: str) -> list[tuple[str, str, str]]:
    """
    Parse a requirements.txt file into (name, version, ecosystem) tuples.

    Handles:
      - ``package==1.2.3``
      - ``package>=1.0,<2.0`` (uses the lower bound version)
      - ``# comments`` and blank lines
      - ``-r other_file.txt`` (skipped)
      - ``package[extra]==1.0``
    """
    results: list[tuple[str, str, str]] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        # Strip extras: requests[security] → requests
        line = re.sub(r"\[.*?\]", "", line)
        # Try pinned version first: name==version
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s,;]+)", line)
        if m:
            results.append((m.group(1), m.group(2), "PyPI"))
            continue
        # Try lower bound: name>=version
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*>=\s*([^\s,;]+)", line)
        if m:
            results.append((m.group(1), m.group(2), "PyPI"))
            continue
        # Package with no version — query all known vulns
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*$", line)
        if m:
            results.append((m.group(1), "", "PyPI"))
    return results


def parse_package_json(content: str) -> list[tuple[str, str, str]]:
    """
    Parse a package.json file into (name, version, ecosystem) tuples.

    Extracts ``dependencies`` and ``devDependencies``.
    Strips semver range prefixes (^, ~, >=, etc.).
    """
    results: list[tuple[str, str, str]] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse package.json: %s", exc)
        return results

    dep_sections = ["dependencies", "devDependencies", "peerDependencies"]
    for section in dep_sections:
        for name, version_raw in data.get(section, {}).items():
            # Strip semver range operators
            version = re.sub(r"^[\^~>=<]+ *", "", str(version_raw)).split(" ")[0]
            results.append((name, version, "npm"))
    return results


def parse_pyproject_toml(content: str) -> list[tuple[str, str, str]]:
    """
    Best-effort parser for pyproject.toml dependencies.
    Handles PEP 621 [project.dependencies] format.
    """
    results: list[tuple[str, str, str]] = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "[project.dependencies]" or stripped == "dependencies = [":
            in_deps = True
            continue
        if in_deps:
            if stripped.startswith("[") and stripped != "dependencies = [":
                in_deps = False
                continue
            # Match quoted dependency strings
            m = re.search(r'"([A-Za-z0-9_.\-]+)\s*([><=!]+\s*[^\s,"]+)?', stripped)
            if m:
                name = m.group(1)
                ver_part = (m.group(2) or "").strip()
                ver_match = re.search(r"[\d.]+", ver_part)
                version = ver_match.group(0) if ver_match else ""
                results.append((name, version, "PyPI"))
    return results


# ── Main audit function ───────────────────────────────────────────────────────

def audit_dependencies(dep_files: dict[str, str]) -> list[DepFinding]:
    """
    Parse all dependency manifests and query OSV.dev for CVEs.

    Parameters
    ----------
    dep_files:
        Dict mapping filename → file content (e.g. ``{"requirements.txt": "..."}``)

    Returns
    -------
    list[DepFinding]
        All CVE findings across all packages.
    """
    packages: list[tuple[str, str, str]] = []

    for filename, content in dep_files.items():
        if filename == "requirements.txt":
            pkgs = parse_requirements(content)
            logger.info("Parsed %d packages from requirements.txt", len(pkgs))
            packages.extend(pkgs)
        elif filename == "package.json":
            pkgs = parse_package_json(content)
            logger.info("Parsed %d packages from package.json", len(pkgs))
            packages.extend(pkgs)
        elif filename == "pyproject.toml":
            pkgs = parse_pyproject_toml(content)
            logger.info("Parsed %d packages from pyproject.toml", len(pkgs))
            packages.extend(pkgs)
        else:
            logger.debug("Skipping dep file: %s", filename)

    if not packages:
        logger.info("No parseable dependency files found.")
        return []

    logger.info("Querying OSV.dev for %d packages...", len(packages))
    cve_findings: list[CVEFinding] = query_packages_batch(packages)

    dep_findings: list[DepFinding] = [
        DepFinding(
            package=c.package,
            version=c.version,
            ecosystem=next((eco for _, _, eco in packages if _ == c.package), "PyPI"),
            cve_id=c.cve_id,
            severity=c.severity,
            description=c.description,
            affected_versions=c.affected_versions,
            references=c.references,
        )
        for c in cve_findings
    ]

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    dep_findings.sort(key=lambda d: SEVERITY_ORDER.get(d.severity.upper(), 9))

    logger.info("Dependency audit complete: %d CVE(s) found", len(dep_findings))
    return dep_findings


def findings_to_text(findings: list[DepFinding]) -> str:
    """Serialize dependency findings to text for LLM consumption."""
    if not findings:
        return "No dependency vulnerabilities detected."
    lines = [f"DEPENDENCY FINDINGS ({len(findings)} total):"]
    for f in findings:
        lines.append(
            f"  [{f.severity}] {f.package}=={f.version} → {f.cve_id}: {f.description[:120]}"
        )
    return "\n".join(lines)


# ── CrewAI Agent/Task ─────────────────────────────────────────────────────────

def build_dep_auditor(llm=None) -> Agent:
    """Create the Dependency Auditor CrewAI agent."""
    kwargs = {}
    if llm is not None:
        kwargs["llm"] = llm

    return Agent(
        role="Software Supply Chain Security Specialist",
        goal=(
            "Analyse dependency vulnerability scan results and identify packages "
            "with critical CVEs that pose real risk to the application. "
            "Provide clear upgrade recommendations."
        ),
        backstory=(
            "You are a software supply chain security expert who has tracked hundreds "
            "of CVEs and understands their real-world exploitability. You know how to "
            "assess whether a vulnerability in a transitive dependency is actually "
            "reachable, and you give developers actionable upgrade paths."
        ),
        verbose=True,
        allow_delegation=False,
        **kwargs,
    )


def build_dep_task(agent: Agent, dep_results_text: str) -> Task:
    """Create the CrewAI Task for the dependency auditor agent."""
    return Task(
        description=(
            f"You have received the following dependency vulnerability scan results:\n\n"
            f"{dep_results_text}\n\n"
            f"Your job:\n"
            f"1. Review each CVE and assess its real-world impact.\n"
            f"2. For critical/high CVEs, explain the attack vector clearly.\n"
            f"3. Provide specific upgrade recommendations (e.g. 'upgrade requests to >=2.31.0').\n"
            f"4. Note if a package appears abandoned or unmaintained.\n"
            f"Return your analysis as a markdown section titled "
            f"'## Dependency Vulnerability Findings'."
        ),
        expected_output=(
            "A markdown section '## Dependency Vulnerability Findings' with CVE findings "
            "sorted by severity. Each entry: package==version, CVE ID, description, "
            "attack vector, and specific upgrade/fix recommendation."
        ),
        agent=agent,
    )
