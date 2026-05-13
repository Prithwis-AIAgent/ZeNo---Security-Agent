"""
SecureAgent — Orchestrator

Coordinates all 3 agents in sequence:
  1. Code Scanner  — regex scan + LLM enrichment
  2. Dep Auditor   — OSV.dev CVE lookup + LLM enrichment
  3. Report Writer — unified markdown report

The orchestrator runs the pure-Python scans first (fast, free),
then optionally passes results through CrewAI for LLM enrichment.

Usage
-----
    from agents.orchestrator import run_audit, AuditResult
    from utils.github_fetcher import FileContent

    result = await run_audit(
        files=[FileContent(path="app.py", content="...")],
        dep_files={"requirements.txt": "requests==2.18.0"},
        target="https://github.com/owner/repo",
    )
    print(result.report)
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

from agents.code_scanner import (
    CodeFinding,
    build_code_scanner,
    build_scan_task,
    findings_to_text as code_findings_to_text,
    scan_files,
)
from agents.dep_auditor import (
    DepFinding,
    audit_dependencies,
    build_dep_auditor,
    build_dep_task,
    findings_to_text as dep_findings_to_text,
)
from agents.report_writer import (
    ReportMetadata,
    ReportSummary,
    build_report_task,
    build_report_writer,
    generate_report,
)
from mcp_server.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class AuditResult:
    """The complete result of a security audit."""
    report: str
    summary: ReportSummary
    code_findings: list[CodeFinding]
    dep_findings: list[DepFinding]
    error: Optional[str] = None


def _build_llm():
    """
    Build the LLM instance for CrewAI based on settings.
    Returns None if no API key is configured (disables LLM enrichment).
    """
    settings = get_settings()

    if not settings.active_llm_key:
        logger.warning(
            "No LLM API key configured — running in pattern-only mode (no LLM enrichment)."
        )
        return None

    try:
        if settings.llm_provider == "openai":
            from langchain_openai import ChatOpenAI
            os.environ["OPENAI_API_KEY"] = settings.openai_api_key
            return ChatOpenAI(model=settings.llm_model, temperature=0.1)
        elif settings.llm_provider == "gemini":
            from langchain_google_genai import ChatGoogleGenerativeAI
            os.environ["GOOGLE_API_KEY"] = settings.gemini_api_key
            return ChatGoogleGenerativeAI(model=settings.llm_model, temperature=0.1)
    except ImportError as exc:
        logger.warning("LLM import failed: %s — running in pattern-only mode.", exc)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM init failed: %s — running in pattern-only mode.", exc)
        return None


def _validate_code_findings(findings: list[CodeFinding]) -> list[CodeFinding]:
    """Validate and sanitise code findings before passing to next agent."""
    valid = []
    for f in findings:
        if not f.file or not f.vuln_name:
            logger.warning("Dropping malformed CodeFinding: %s", f)
            continue
        if f.severity not in ("Critical", "High", "Medium", "Low"):
            f.severity = "Low"
        valid.append(f)
    return valid


def _validate_dep_findings(findings: list[DepFinding]) -> list[DepFinding]:
    """Validate and sanitise dependency findings before passing to next agent."""
    valid = []
    for f in findings:
        if not f.package or not f.cve_id:
            logger.warning("Dropping malformed DepFinding: %s", f)
            continue
        valid.append(f)
    return valid


def run_audit(
    files: list,
    dep_files: dict[str, str],
    target: str,
    use_llm: bool = True,
) -> AuditResult:
    """
    Run the complete 3-agent security audit pipeline.

    Parameters
    ----------
    files:
        List of ``FileContent`` objects (source code files to scan).
    dep_files:
        Dict mapping filename → content for dependency manifests.
    target:
        Human-readable target identifier (URL or "inline code").
    use_llm:
        If True, pass findings through CrewAI LLM agents for enrichment.
        If False (or if no API key), run pattern-only mode.

    Returns
    -------
    AuditResult
        Contains the report markdown, summary counts, and raw findings.
    """
    metadata = ReportMetadata(
        target=target,
        scanned_files=len(files),
        scanned_packages=sum(
            1 for content in dep_files.values()
            for _ in [content]  # we count dep files, not packages
        ),
    )

    # ── Phase 1: Code Scanner ─────────────────────────────────────────
    logger.info("Phase 1: Running code scanner on %d files...", len(files))
    try:
        raw_code_findings = scan_files(files)
        code_findings = _validate_code_findings(raw_code_findings)
        logger.info("Code scan: %d valid finding(s)", len(code_findings))
    except Exception as exc:  # noqa: BLE001
        logger.error("Code scanner failed: %s", exc)
        code_findings = []

    # ── Phase 2: Dependency Auditor ───────────────────────────────────
    logger.info("Phase 2: Running dependency auditor on %d dep files...", len(dep_files))
    try:
        raw_dep_findings = audit_dependencies(dep_files)
        dep_findings = _validate_dep_findings(raw_dep_findings)
        logger.info("Dep audit: %d valid CVE(s)", len(dep_findings))
    except Exception as exc:  # noqa: BLE001
        logger.error("Dependency auditor failed: %s", exc)
        dep_findings = []

    # ── Phase 3: LLM enrichment (optional) ───────────────────────────
    llm_report: Optional[str] = None
    if use_llm:
        llm = _build_llm()
        if llm is not None:
            try:
                from crewai import Crew, Process

                code_agent = build_code_scanner(llm=llm)
                dep_agent = build_dep_auditor(llm=llm)
                report_agent = build_report_writer(llm=llm)

                code_text = code_findings_to_text(code_findings)
                dep_text = dep_findings_to_text(dep_findings)

                scan_task = build_scan_task(code_agent, code_text)
                dep_task = build_dep_task(dep_agent, dep_text)
                report_task = build_report_task(
                    report_agent,
                    code_analysis_text=f"{{scan_task}}",  # CrewAI context injection
                    dep_analysis_text=f"{{dep_task}}",
                    metadata=metadata,
                )
                # Wire task context
                report_task.context = [scan_task, dep_task]

                crew = Crew(
                    agents=[code_agent, dep_agent, report_agent],
                    tasks=[scan_task, dep_task, report_task],
                    process=Process.sequential,
                    verbose=True,
                )
                logger.info("Phase 3: Running CrewAI pipeline...")
                llm_report = str(crew.kickoff())
                logger.info("CrewAI pipeline complete.")
            except Exception as exc:  # noqa: BLE001
                logger.error("CrewAI pipeline failed: %s — falling back to template report.", exc)
                llm_report = None

    # ── Phase 4: Generate report ──────────────────────────────────────
    if llm_report:
        # LLM produced a report — compute summary from raw findings
        _, summary = generate_report(code_findings, dep_findings, metadata)
        report = llm_report
    else:
        # Fallback: use template-based report generator
        logger.info("Phase 3: Generating template-based report...")
        report, summary = generate_report(code_findings, dep_findings, metadata)

    return AuditResult(
        report=report,
        summary=summary,
        code_findings=code_findings,
        dep_findings=dep_findings,
    )
