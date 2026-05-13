"""
SecureAgent — Agent 3: Report Writer

Takes findings from Agent 1 (code scanner) and Agent 2 (dependency auditor)
and produces a structured, prioritised markdown security report.

This module exposes:
  - generate_report(code_findings, dep_findings, metadata) → markdown str
  - build_report_writer()  → CrewAI Agent
  - build_report_task()    → CrewAI Task
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from crewai import Agent, Task

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
DEP_SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Unknown",
}


@dataclass
class ReportMetadata:
    """Contextual info about the scan target."""
    target: str                          # URL or "inline code"
    scanned_files: int = 0
    scanned_packages: int = 0
    omitted_unknowns: int = 0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    )


@dataclass
class ReportSummary:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.unknown

    def to_dict(self) -> dict:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "unknown": self.unknown,
            "total": self.total,
        }


def _severity_emoji(severity: str) -> str:
    return {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🔵",
    }.get(severity, "⚪")


def _normalise_dep_severity(raw: str) -> str:
    return DEP_SEVERITY_MAP.get(raw.upper(), "Low")


def generate_report(
    code_findings: list,
    dep_findings: list,
    metadata: ReportMetadata,
) -> tuple[str, ReportSummary]:
    """
    Generate a structured markdown security report from agent findings.

    Parameters
    ----------
    code_findings:
        List of ``CodeFinding`` objects from Agent 1.
    dep_findings:
        List of ``DepFinding`` objects from Agent 2.
    metadata:
        Scan context (target URL, file counts, timestamp).

    Returns
    -------
    tuple[str, ReportSummary]
        The full markdown report string and a summary dict.
    """
    summary = ReportSummary()

    # ── Group code findings by severity ──────────────────────────────
    code_by_sev: dict[str, list] = {s: [] for s in SEVERITY_ORDER}
    for f in code_findings:
        sev = f.severity if f.severity in code_by_sev else "Low"
        code_by_sev[sev].append(f)

    # ── Group dep findings by severity ────────────────────────────────
    dep_by_sev: dict[str, list] = {s: [] for s in SEVERITY_ORDER + ["Unknown"]}
    for f in dep_findings:
        sev = _normalise_dep_severity(f.severity)
        dep_by_sev[sev].append(f)

    # ── Tally summary ─────────────────────────────────────────────────
    for sev in SEVERITY_ORDER + ["Unknown"]:
        count = len(code_by_sev.get(sev, [])) + len(dep_by_sev.get(sev, []))
        setattr(summary, sev.lower(), count)

    # ── Build report ─────────────────────────────────────────────────
    lines: list[str] = []

    # Header
    lines += [
        "# 🔐 SecureAgent Security Audit Report",
        "",
        f"**Target**: `{metadata.target}`  ",
        f"**Scan Date**: {metadata.timestamp}  ",
        f"**Files Scanned**: {metadata.scanned_files}  ",
        f"**Packages Audited**: {metadata.scanned_packages}  ",
        "",
        "---",
        "",
    ]

    # Executive summary
    lines += [
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
        f"| 🔴 Critical | {summary.critical} |",
        f"| 🟠 High | {summary.high} |",
        f"| 🟡 Medium | {summary.medium} |",
        f"| 🔵 Low | {summary.low} |",
        f"| **Total** | **{summary.total}** |",
        "",
    ]

    if summary.total == 0:
        if metadata.omitted_unknowns > 0:
            lines += [
                f"> ℹ️ **{metadata.omitted_unknowns} unscored CVEs omitted** — run with `min_severity=unknown` to see all at the bottom.",
                ""
            ]
        lines += [
            "> ✅ **No vulnerabilities detected** in this scan. "
            "This does not guarantee the code is free of security issues — "
            "manual review is always recommended.",
            "",
        ]
        return "\n".join(lines), summary

    lines += ["---", ""]

    # ── Findings by severity ──────────────────────────────────────────
    for severity in SEVERITY_ORDER:
        emoji = _severity_emoji(severity)
        code_list = code_by_sev[severity]
        dep_list = dep_by_sev[severity]

        if not code_list and not dep_list:
            continue

        lines += [f"## {emoji} {severity}", ""]

        # Code findings
        if code_list:
            lines += [f"### Code Issues ({len(code_list)})", ""]
            for f in code_list:
                lines += [
                    f"#### {f.vuln_name}",
                    "",
                    f"| Field | Value |",
                    f"|---|---|",
                    f"| **File** | `{f.file}` |",
                    f"| **Line** | {f.line} |",
                    f"| **Category** | {f.category} |",
                    "",
                    f"**What it is**: {f.vuln_name}  ",
                    "",
                    f"**Why it's dangerous**: {f.description}  ",
                    "",
                    f"**How to fix it**: {f.fix}  ",
                    "",
                    f"**Matched code**:",
                    "```",
                    f"{f.matched_text[:200]}",
                    "```",
                    "",
                ]

        # Dependency findings
        if dep_list:
            lines += [f"### Dependency CVEs ({len(dep_list)})", ""]
            for f in dep_list:
                refs = " · ".join(f.references[:3]) if f.references else "None"
                fix_msg = f"Upgrade to version {f.fixed_version} or later." if f.fixed_version else "Upgrade to a patched version."
                lines += [
                    f"#### {f.package} — `{f.cve_id}`",
                    "",
                    f"| Field | Value |",
                    f"|---|---|",
                    f"| **Package** | `{f.package}=={f.version}` |",
                    f"| **CVE** | `{f.cve_id}` |",
                    f"| **Severity** | {f.severity} |",
                    "",
                    f"**Description**: {f.description}  ",
                    "",
                    f"**How to fix it**: {fix_msg}  ",
                    "",
                    f"**References**: {refs}  ",
                    "",
                ]

    # Handle Unknowns if any exist
    unknown_list = dep_by_sev.get("Unknown", [])
    if unknown_list:
        lines += [
            f"<details>",
            f"<summary><strong>Unscored CVEs ({len(unknown_list)})</strong></summary>",
            ""
        ]
        for f in unknown_list:
            refs = " · ".join(f.references[:3]) if f.references else "None"
            fix_msg = f"Upgrade to version {f.fixed_version} or later." if f.fixed_version else "Upgrade to a patched version."
            lines += [
                f"#### {f.package} — `{f.cve_id}`",
                "",
                f"| Field | Value |",
                f"|---|---|",
                f"| **Package** | `{f.package}=={f.version}` |",
                f"| **CVE** | `{f.cve_id}` |",
                f"| **Severity** | Unknown |",
                "",
                f"**Description**: {f.description}  ",
                "",
                f"**How to fix it**: {fix_msg}  ",
                "",
                f"**References**: {refs}  ",
                "",
            ]
        lines += ["</details>", ""]

    if metadata.omitted_unknowns > 0:
        lines += [
            f"> ℹ️ **{metadata.omitted_unknowns} unscored CVEs omitted** — run with `min_severity=unknown` to see all at the bottom.",
            ""
        ]

    # Footer disclaimer
    lines += [
        "---",
        "",
        "> ⚠️ **Disclaimer**: SecureAgent is an automated tool and may produce false positives. "
        "All findings should be reviewed by a qualified security engineer before remediation. "
        "This tool is intended for auditing code you own or have explicit permission to test.",
        "",
    ]

    return "\n".join(lines), summary


# ── CrewAI Agent/Task ─────────────────────────────────────────────────────────

def build_report_writer(llm=None) -> Agent:
    """Create the Report Writer CrewAI agent."""
    kwargs = {}
    if llm is not None:
        kwargs["llm"] = llm

    return Agent(
        role="Security Report Author",
        goal=(
            "Synthesise all security findings from code analysis and dependency audits "
            "into a clear, prioritised, actionable security report that developers can "
            "act on immediately."
        ),
        backstory=(
            "You are a security communications expert who has written hundreds of "
            "penetration test reports and audit summaries. You excel at making complex "
            "technical findings understandable to developers, translating raw scan output "
            "into prioritised, business-relevant recommendations."
        ),
        verbose=True,
        allow_delegation=False,
        **kwargs,
    )


def build_report_task(
    agent: Agent,
    code_analysis_text: str,
    dep_analysis_text: str,
    metadata: ReportMetadata,
) -> Task:
    """Create the CrewAI Task for the report writer agent."""
    return Task(
        description=(
            f"You have received security analysis results for: `{metadata.target}`\n\n"
            f"--- CODE ANALYSIS ---\n{code_analysis_text}\n\n"
            f"--- DEPENDENCY ANALYSIS ---\n{dep_analysis_text}\n\n"
            f"Your job:\n"
            f"1. Synthesise both sets of findings into a single unified security report.\n"
            f"2. Prioritise findings: Critical first, then High, Medium, Low.\n"
            f"3. For each finding include: what it is, why dangerous, how to fix it, "
            f"   and file/line or package reference.\n"
            f"4. Add an executive summary with finding counts per severity.\n"
            f"5. Keep language clear and actionable for developers.\n\n"
            f"Return the complete markdown report."
        ),
        expected_output=(
            "A complete, well-formatted markdown security report with: "
            "executive summary table, findings grouped by severity (Critical → Low), "
            "each finding with context and remediation, and a disclaimer footer."
        ),
        agent=agent,
    )
