"""
SecureAgent — Regex patterns for vulnerability detection.

Each pattern is a dict with:
  name        : human-readable finding name
  pattern     : compiled regex
  severity    : Critical | High | Medium | Low
  description : why it is dangerous
  fix         : brief remediation advice
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Pattern


@dataclass
class VulnPattern:
    name: str
    pattern: Pattern[str]
    severity: str
    description: str
    fix: str
    category: str = "code"


VULN_PATTERNS: list[VulnPattern] = [
    # ── Hardcoded secrets ──────────────────────────────────────────────
    VulnPattern(
        name="Hardcoded API Key / Token",
        pattern=re.compile(
            r'(?i)((api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|api[_\-]?secret|token)\s*[:=]\s*["\'][^"\']{6,}["\']'
            r'|bearer\s+[A-Za-z0-9\-._~+/]{15,}=*'
            r'|(password|passwd)\s*[:=]\s*["\'][^"\']{6,}["\'])',
            re.IGNORECASE,
        ),
        severity="Critical",
        description=(
            "Hardcoded credentials in source code can be extracted by anyone "
            "with repository access and exploited to impersonate the service or owner."
        ),
        fix="Move secrets to environment variables and use a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault).",
        category="secrets",
    ),
    VulnPattern(
        name="AWS Access Key Exposed",
        pattern=re.compile(r'AKIA[0-9A-Z]{16}'),
        severity="Critical",
        description="AWS access keys grant programmatic access to AWS services. Exposure leads to full account compromise.",
        fix="Rotate the key immediately via AWS IAM console, then store it in environment variables or a secrets manager.",
        category="secrets",
    ),
    VulnPattern(
        name="Private Key Material",
        pattern=re.compile(r'-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        severity="Critical",
        description="Private key material embedded in code allows decryption of encrypted traffic and impersonation.",
        fix="Remove the key, revoke and reissue it, and store future keys outside the repository.",
        category="secrets",
    ),
    # ── SQL Injection ──────────────────────────────────────────────────
    VulnPattern(
        name="SQL Injection Risk (String Concatenation)",
        pattern=re.compile(
            r'(?i)(execute|cursor\.execute|query)\s*\(\s*["\']?\s*'
            r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*["\']?\s*\+',
        ),
        severity="Critical",
        description=(
            "Concatenating user input directly into SQL queries allows attackers to "
            "manipulate database queries, extract data, or destroy records."
        ),
        fix="Use parameterised queries or an ORM (e.g. SQLAlchemy) instead of string concatenation.",
        category="injection",
    ),
    VulnPattern(
        name="SQL Injection Risk (f-string / format)",
        pattern=re.compile(
            r'(?i)(execute|cursor\.execute)\s*\(\s*f["\'].*?(SELECT|INSERT|UPDATE|DELETE)',
        ),
        severity="Critical",
        description="f-string interpolation in SQL queries is equivalent to string concatenation — allows SQL injection.",
        fix="Use parameterised queries. Replace f-strings with `?` or `%s` placeholders and pass values as a tuple.",
        category="injection",
    ),
    # ── XSS ────────────────────────────────────────────────────────────
    VulnPattern(
        name="Cross-Site Scripting (XSS) — innerHTML",
        pattern=re.compile(r'\.innerHTML\s*=\s*(?![\'"]\s*[\'"])', re.IGNORECASE),
        severity="High",
        description=(
            "Setting innerHTML with untrusted data allows attackers to inject "
            "malicious scripts that execute in the victim's browser."
        ),
        fix="Use textContent instead of innerHTML, or sanitise input with DOMPurify before assignment.",
        category="xss",
    ),
    VulnPattern(
        name="Cross-Site Scripting (XSS) — document.write",
        pattern=re.compile(r'document\.write\s*\(', re.IGNORECASE),
        severity="High",
        description="document.write with user-controlled data can inject arbitrary HTML and scripts.",
        fix="Use DOM manipulation methods (createElement, appendChild) with properly escaped content.",
        category="xss",
    ),
    # ── Dangerous functions ────────────────────────────────────────────
    VulnPattern(
        name="Use of eval()",
        pattern=re.compile(r'\beval\s*\('),
        severity="High",
        description=(
            "eval() executes arbitrary code. If user input reaches eval(), "
            "an attacker can run any code in the application context."
        ),
        fix="Replace eval() with safer alternatives: JSON.parse() for data, or restructure the logic to avoid dynamic code execution.",
        category="dangerous_functions",
    ),
    VulnPattern(
        name="Use of exec() with Variable",
        pattern=re.compile(r'\bexec\s*\(\s*(?![\'"]{1}[^\'"]*[\'"]{1}\s*\))'),
        severity="High",
        description="exec() with dynamic input can execute arbitrary Python code, leading to full server compromise.",
        fix="Avoid exec() entirely. If dynamic execution is needed, use a restricted evaluator or redesign the logic.",
        category="dangerous_functions",
    ),
    VulnPattern(
        name="Shell Injection via subprocess (shell=True)",
        pattern=re.compile(r'subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True'),
        severity="Critical",
        description="shell=True with unsanitised input allows OS command injection, giving attackers full shell access.",
        fix="Set shell=False and pass arguments as a list. Validate and sanitise all inputs before use.",
        category="injection",
    ),
    VulnPattern(
        name="Use of os.system()",
        pattern=re.compile(r'\bos\.system\s*\('),
        severity="High",
        description="os.system() passes commands to the shell and is vulnerable to command injection.",
        fix="Use subprocess with shell=False and a list of arguments instead.",
        category="dangerous_functions",
    ),
    # ── Insecure network ───────────────────────────────────────────────
    VulnPattern(
        name="HTTP Instead of HTTPS",
        pattern=re.compile(r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)[\w\-./]+'),
        severity="Medium",
        description="Plain HTTP transmits data in cleartext, exposing it to man-in-the-middle attacks.",
        fix="Replace http:// with https:// and ensure TLS certificates are valid.",
        category="network",
    ),
    VulnPattern(
        name="SSL Verification Disabled",
        pattern=re.compile(r'verify\s*=\s*False', re.IGNORECASE),
        severity="High",
        description="Disabling SSL verification makes the application vulnerable to man-in-the-middle attacks.",
        fix="Remove verify=False. Fix any certificate issues properly rather than bypassing verification.",
        category="network",
    ),
    # ── Insecure deserialization ───────────────────────────────────────
    VulnPattern(
        name="Insecure Pickle Deserialization",
        pattern=re.compile(r'\bpickle\.loads?\s*\('),
        severity="High",
        description=(
            "Deserialising untrusted pickle data can execute arbitrary code. "
            "An attacker supplying a malicious pickle payload achieves RCE."
        ),
        fix="Never deserialise pickle data from untrusted sources. Use JSON or MessagePack for data interchange.",
        category="deserialization",
    ),
    VulnPattern(
        name="Insecure YAML Load",
        pattern=re.compile(r'\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)'),
        severity="High",
        description="yaml.load() without SafeLoader can deserialise arbitrary Python objects, enabling code execution.",
        fix="Use yaml.safe_load() instead of yaml.load(), or explicitly pass Loader=yaml.SafeLoader.",
        category="deserialization",
    ),
    # ── Debug / dev endpoints ──────────────────────────────────────────
    VulnPattern(
        name="Debug Mode Enabled",
        pattern=re.compile(r'(?i)(debug\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True)'),
        severity="Medium",
        description="Debug mode exposes stack traces, environment variables, and interactive consoles to end users.",
        fix="Set debug=False in production. Use environment-based configuration to control debug mode.",
        category="debug",
    ),
    VulnPattern(
        name="Hardcoded Debug / TODO Credential",
        pattern=re.compile(r'(?i)(password|passwd|pwd|secret)\s*=\s*["\']?(admin|password|123456|test|changeme|default)["\']?'),
        severity="Critical",
        description="Default or placeholder credentials are the first thing attackers try during brute-force attacks.",
        fix="Generate a strong, unique password and store it in an environment variable or secrets manager.",
        category="secrets",
    ),
    # ── JWT ────────────────────────────────────────────────────────────
    VulnPattern(
        name="JWT Algorithm None",
        pattern=re.compile(r'algorithm\s*=\s*["\']none["\']', re.IGNORECASE),
        severity="Critical",
        description='Using algorithm="none" disables JWT signature verification, allowing token forgery.',
        fix='Always specify a strong signing algorithm (e.g. HS256, RS256) and reject tokens with alg=none.',
        category="auth",
    ),
]
