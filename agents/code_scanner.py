"""
SecureAgent — Agent 1: Code Scanner

Scans source files using regex patterns from utils/patterns.py.
Returns structured findings with file, line number, severity, and remediation.

This module exposes:
  - scan_files(files)      → pure-Python scan (fast, no LLM)
  - build_code_scanner()   → CrewAI Agent
  - build_scan_task()      → CrewAI Task
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from crewai import Agent, Task

from utils.patterns import VULN_PATTERNS, VulnPattern

logger = logging.getLogger(__name__)


@dataclass
class CodeFinding:
    """A single vulnerability found in source code."""
    file: str
    line: int
    vuln_name: str
    severity: str       # Critical | High | Medium | Low
    category: str
    description: str
    fix: str
    matched_text: str = ""

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "vuln_name": self.vuln_name,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "fix": self.fix,
            "matched_text": self.matched_text[:200],  # truncate for safety
        }

    def to_markdown_row(self) -> str:
        return (
            f"- **{self.vuln_name}** (`{self.file}:{self.line}`)\n"
            f"  - **Why dangerous**: {self.description}\n"
            f"  - **Fix**: {self.fix}\n"
            f"  - **Matched**: `{self.matched_text[:120]}`\n"
        )


def scan_files(files: list) -> list[CodeFinding]:
    """
    Run regex-based vulnerability scan over a list of FileContent objects.

    Parameters
    ----------
    files:
        List of ``FileContent`` dataclass instances (path, content).

    Returns
    -------
    list[CodeFinding]
        All findings, sorted by severity (Critical first).
    """
    SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings: list[CodeFinding] = []

    for file_obj in files:
        path: str = file_obj.path
        content: str = file_obj.content
        lines = content.splitlines()

        for pattern_def in VULN_PATTERNS:
            for line_no, line_text in enumerate(lines, start=1):
                match = pattern_def.pattern.search(line_text)
                if match:
                    findings.append(
                        CodeFinding(
                            file=path,
                            line=line_no,
                            vuln_name=pattern_def.name,
                            severity=pattern_def.severity,
                            category=pattern_def.category,
                            description=pattern_def.description,
                            fix=pattern_def.fix,
                            matched_text=line_text.strip(),
                        )
                    )
                    logger.debug("[%s] %s → %s L%d", pattern_def.severity, pattern_def.name, path, line_no)

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line))
    logger.info("Code scan complete: %d finding(s) across %d file(s)", len(findings), len(files))
    return findings


def findings_to_text(findings: list[CodeFinding]) -> str:
    """Serialize findings to a compact text block for LLM consumption."""
    if not findings:
        return "No code vulnerabilities detected."
    lines = [f"CODE FINDINGS ({len(findings)} total):"]
    for f in findings:
        lines.append(
            f"  [{f.severity}] {f.vuln_name} | {f.file}:{f.line} | {f.description[:100]} | Fix: {f.fix[:80]}"
        )
    return "\n".join(lines)


def build_code_scanner(llm=None) -> Agent:
    """
    Create the Code Scanner CrewAI agent.

    The agent's role is analytical — it receives pre-processed scan
    results and enriches them with context using the LLM.
    """
    kwargs = {}
    if llm is not None:
        kwargs["llm"] = llm

    return Agent(
        role="Application Security Code Analyst",
        goal=(
            "Analyse static code scan results for a software project. "
            "Identify the most dangerous vulnerabilities, understand their context, "
            "and provide clear, actionable findings with severity ratings."
        ),
        backstory=(
            "You are a seasoned application security engineer with deep expertise in "
            "OWASP Top 10, secure coding practices, and vulnerability research. "
            "You have audited hundreds of codebases and know how to distinguish "
            "true positives from false positives in automated scans."
        ),
        verbose=True,
        allow_delegation=False,
        **kwargs,
    )


def build_scan_task(agent: Agent, scan_results_text: str) -> Task:
    """Create the CrewAI Task for the code scanner agent."""
    return Task(
        description=(
            f"You have received the following automated code scan results:\n\n"
            f"{scan_results_text}\n\n"
            f"Your job:\n"
            f"1. Review each finding and confirm whether it is a genuine vulnerability.\n"
            f"2. For any false positives (e.g., a URL in a comment), note them.\n"
            f"3. Group findings by severity: Critical, High, Medium, Low.\n"
            f"4. For each confirmed finding, provide:\n"
            f"   - What it is\n"
            f"   - Why it is dangerous\n"
            f"   - How to fix it\n"
            f"   - The file and line reference\n"
            f"Return your analysis as a well-structured markdown section titled "
            f"'## Code Analysis Findings'."
        ),
        expected_output=(
            "A markdown section '## Code Analysis Findings' with confirmed vulnerabilities "
            "grouped by severity (Critical → High → Medium → Low). Each finding must include "
            "file:line reference, description, danger explanation, and fix."
        ),
        agent=agent,
    )
