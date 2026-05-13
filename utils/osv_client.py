"""
SecureAgent — OSV.dev CVE query client.

Queries https://api.osv.dev/v1/query for each package/version pair.
No API key required — fully public.

Usage
-----
    from utils.osv_client import query_package, CVEFinding

    findings = query_package("requests", "2.18.0", "PyPI")
    for f in findings:
        print(f.cve_id, f.severity)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


@dataclass
class CVEFinding:
    """A single CVE / vulnerability finding for a dependency."""
    package: str
    version: str
    cve_id: str
    severity: str           # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    description: str
    affected_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


def _parse_severity(vuln: dict[str, Any]) -> str:
    """Extract the highest severity from an OSV vulnerability record."""
    # Try database_specific.severity first (common in NVD-enriched records)
    db_sev = vuln.get("database_specific", {}).get("severity", "")
    if db_sev:
        return db_sev.upper()

    # Try CVSS from severity list
    for sev in vuln.get("severity", []):
        score = sev.get("score", "")
        sev_type = sev.get("type", "")
        if sev_type in ("CVSS_V3", "CVSS_V2") and score:
            # Parse CVSS base score
            try:
                base_score = float(score.split("/")[0].split(":")[-1])
                if base_score >= 9.0:
                    return "CRITICAL"
                elif base_score >= 7.0:
                    return "HIGH"
                elif base_score >= 4.0:
                    return "MEDIUM"
                else:
                    return "LOW"
            except (ValueError, IndexError):
                pass

    return "UNKNOWN"


def _extract_affected_versions(vuln: dict[str, Any]) -> list[str]:
    """Pull version strings from the affected[] list."""
    versions: list[str] = []
    for affected in vuln.get("affected", []):
        for ver in affected.get("versions", []):
            versions.append(ver)
    # Deduplicate, truncate for readability
    unique = list(dict.fromkeys(versions))
    return unique[:20]  # cap at 20


def _parse_vuln(package: str, version: str, vuln: dict[str, Any]) -> CVEFinding:
    """Convert a raw OSV vuln dict into a CVEFinding."""
    vuln_id = vuln.get("id", "UNKNOWN")
    aliases = vuln.get("aliases", [])
    # Prefer CVE IDs from aliases
    cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

    summary = vuln.get("summary", "")
    details = vuln.get("details", "")
    description = summary or details[:300] or "No description available."

    return CVEFinding(
        package=package,
        version=version,
        cve_id=cve_id,
        severity=_parse_severity(vuln),
        description=description,
        affected_versions=_extract_affected_versions(vuln),
        references=[r.get("url", "") for r in vuln.get("references", [])[:5]],
    )


def query_package(
    name: str,
    version: str,
    ecosystem: str = "PyPI",
    timeout: float = 15.0,
) -> list[CVEFinding]:
    """
    Query OSV.dev for vulnerabilities in a specific package version.

    Parameters
    ----------
    name:
        Package name (e.g. ``requests``).
    version:
        Package version string (e.g. ``2.18.0``). Pass ``""`` to query
        all known vulns for the package regardless of version.
    ecosystem:
        Package ecosystem — ``PyPI``, ``npm``, ``Go``, ``Maven``, etc.
    timeout:
        HTTP request timeout in seconds.

    Returns
    -------
    list[CVEFinding]
        Empty list if no vulnerabilities found or on error.
    """
    payload: dict[str, Any] = {
        "package": {"name": name, "ecosystem": ecosystem}
    }
    if version:
        payload["version"] = version

    try:
        resp = httpx.post(OSV_API_URL, json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulns", [])
        findings = [_parse_vuln(name, version, v) for v in vulns]
        if findings:
            logger.info("%s==%s → %d CVE(s) found", name, version, len(findings))
        return findings
    except httpx.HTTPStatusError as exc:
        logger.warning("OSV API error for %s==%s: HTTP %s", name, version, exc.response.status_code)
        return []
    except httpx.RequestError as exc:
        logger.warning("OSV network error for %s==%s: %s", name, version, exc)
        return []
    except Exception as exc:  # noqa: BLE001
        logger.warning("Unexpected OSV error for %s==%s: %s", name, version, exc)
        return []


def query_packages_batch(
    packages: list[tuple[str, str, str]],
    timeout: float = 30.0,
) -> list[CVEFinding]:
    """
    Query multiple packages in a single OSV batch request.

    Parameters
    ----------
    packages:
        List of (name, version, ecosystem) tuples.

    Returns
    -------
    list[CVEFinding]
        Flat list of all findings across all packages.
    """
    if not packages:
        return []

    queries = [
        {
            "package": {"name": name, "ecosystem": ecosystem},
            **({"version": version} if version else {}),
        }
        for name, version, ecosystem in packages
    ]

    try:
        resp = httpx.post(
            OSV_BATCH_URL,
            json={"queries": queries},
            timeout=timeout,
        )
        resp.raise_for_status()
        results = resp.json().get("results", [])
    except Exception as exc:  # noqa: BLE001
        logger.warning("OSV batch request failed: %s — falling back to sequential", exc)
        # Fallback: query one by one
        all_findings: list[CVEFinding] = []
        for name, version, ecosystem in packages:
            all_findings.extend(query_package(name, version, ecosystem))
        return all_findings

    all_findings = []
    for (name, version, ecosystem), result in zip(packages, results):
        for vuln in result.get("vulns", []):
            all_findings.append(_parse_vuln(name, version, vuln))

    logger.info("Batch OSV: %d packages → %d CVE(s)", len(packages), len(all_findings))
    return all_findings
