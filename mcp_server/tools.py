"""
SecureAgent — MCP Tool schemas (Pydantic request/response models).
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


# ── Request models ────────────────────────────────────────────────────────────

class AuditRepoRequest(BaseModel):
    """Request body for the audit_repo tool."""
    github_url: str = Field(
        ...,
        description="Full GitHub repository URL (must be public).",
        examples=["https://github.com/owner/repo"],
    )
    use_llm: bool = Field(
        default=True,
        description="Enable LLM enrichment of scan results (requires API key in .env).",
    )
    min_severity: str = Field(
        default="low",
        description="Minimum severity to include (critical, high, medium, low, unknown).",
    )

    @field_validator("github_url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        v = v.strip()
        if "github.com" not in v:
            raise ValueError("URL must be a GitHub repository URL (github.com).")
        if not v.startswith("https://"):
            raise ValueError("URL must start with https://")
        return v


class AuditCodeRequest(BaseModel):
    """Request body for the audit_code tool."""
    code: str = Field(
        ...,
        description="Raw source code to audit.",
        min_length=1,
        max_length=500_000,
    )
    filename: str = Field(
        default="snippet.py",
        description="Filename with extension (used to select patterns). E.g. 'app.py', 'index.js'.",
    )
    use_llm: bool = Field(
        default=True,
        description="Enable LLM enrichment of scan results.",
    )
    min_severity: str = Field(
        default="low",
        description="Minimum severity to include (critical, high, medium, low, unknown).",
    )


# ── Response models ───────────────────────────────────────────────────────────

class SeveritySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0


class AuditResponse(BaseModel):
    """Successful audit response."""
    report: str = Field(..., description="Full markdown security report.")
    summary: SeveritySummary
    target: str = Field(..., description="Audit target (URL or filename).")


class ErrorResponse(BaseModel):
    """Error response returned when audit fails."""
    error: str = Field(..., description="Human-readable error message.")
    detail: Optional[str] = Field(default=None, description="Technical detail for debugging.")


# ── MCP Tool discovery schema ─────────────────────────────────────────────────

class MCPToolSchema(BaseModel):
    name: str
    description: str
    input_schema: dict


TOOL_REGISTRY: list[MCPToolSchema] = [
    MCPToolSchema(
        name="audit_repo",
        description=(
            "Audit a public GitHub repository for security vulnerabilities. "
            "Scans all Python, JavaScript, TypeScript, and .env files for "
            "hardcoded secrets, injection flaws, insecure code patterns, and "
            "known CVEs in dependencies."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "github_url": {
                    "type": "string",
                    "description": "Full public GitHub repository URL.",
                },
                "use_llm": {
                    "type": "boolean",
                    "description": "Enable LLM enrichment (default: true).",
                    "default": True,
                },
                "min_severity": {
                    "type": "string",
                    "description": "Minimum severity to include (critical, high, medium, low, unknown).",
                    "default": "low",
                },
            },
            "required": ["github_url"],
        },
    ),
    MCPToolSchema(
        name="audit_code",
        description=(
            "Audit a raw code snippet for security vulnerabilities. "
            "Runs the same pattern-based scanner as audit_repo but accepts "
            "pasted code directly."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Source code to audit.",
                },
                "filename": {
                    "type": "string",
                    "description": "Filename with extension (e.g. 'app.py').",
                    "default": "snippet.py",
                },
                "use_llm": {
                    "type": "boolean",
                    "description": "Enable LLM enrichment (default: true).",
                    "default": True,
                },
                "min_severity": {
                    "type": "string",
                    "description": "Minimum severity to include (critical, high, medium, low, unknown).",
                    "default": "low",
                },
            },
            "required": ["code"],
        },
    ),
]
