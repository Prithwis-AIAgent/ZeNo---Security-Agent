# 🔐 SecureAgent

> **AI-Powered Security Audit Tool exposed as an MCP Server**

SecureAgent is a Python-based MCP (Model Context Protocol) server that accepts a GitHub repository URL or pasted code and runs a 3-agent security audit pipeline, returning a prioritized plain-English security report.

---

## ⚠️ Disclaimer

**This tool is for auditing YOUR OWN code only.**  
Do not use SecureAgent to audit third-party systems, repositories, or infrastructure without **explicit written permission** from the owner. Unauthorized security scanning may violate computer fraud laws.

---

## 🏗️ Architecture

```
GitHub URL / Raw Code
        │
        ▼
  ┌─────────────┐
  │  MCP Server │  (FastAPI — POST /tools/audit_repo, /tools/audit_code)
  └──────┬──────┘
         │
         ▼
  ┌─────────────────────────────────────────────────────┐
  │                   Orchestrator                       │
  │                                                     │
  │  Agent 1          Agent 2            Agent 3        │
  │  Code Scanner  →  Dep Auditor   →  Report Writer   │
  │  (regex + LLM)   (OSV.dev CVEs)   (Markdown report)│
  └─────────────────────────────────────────────────────┘
```

### Agent Responsibilities

| Agent | Responsibility |
|-------|---------------|
| **Code Scanner** | Scans `.py`, `.js`, `.ts`, `.env` files for hardcoded secrets, SQL injection, XSS, `eval()`, HTTP links, insecure deserialization, debug endpoints |
| **Dependency Auditor** | Parses `requirements.txt` / `package.json`, queries OSV.dev for CVEs and affected versions |
| **Report Writer** | Combines findings into a structured markdown report: Critical / High / Medium / Low |

---

## 🚀 Quick Start

### 1. Prerequisites

- Python 3.11+
- Git

### 2. Clone & set up

```bash
git clone https://github.com/yourname/secureagent.git
cd secureagent

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env and add your API key
```

**.env** (minimum required):
```env
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...your-key...
OPENAI_MODEL=gpt-4o-mini
```

> **Note:** The server works without an LLM key! In that case it runs regex-only scanning and a template-based report. An LLM key enables deeper contextual analysis.

### 4. Start the server

```bash
python -m mcp_server.main
```

Server starts at **http://localhost:8000**

- **API docs:** http://localhost:8000/docs  
- **MCP manifest:** http://localhost:8000/mcp  
- **Health check:** http://localhost:8000/health  

---

## 🔧 API Usage

### Audit a GitHub Repository

```bash
curl -X POST http://localhost:8000/tools/audit_repo \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/pallets/flask"}'
```

### Audit Pasted Code

```bash
curl -X POST http://localhost:8000/tools/audit_code \
  -H "Content-Type: application/json" \
  -d '{
    "code": "import os\npassword = \"admin123\"\nos.system(\"ls \" + user_input)",
    "filename": "app.py"
  }'
```

### Response Format

```json
{
  "report": "# 🔐 SecureAgent Security Audit Report\n...",
  "scan_summary": "Scanned 42 files. Found 7 issues: 2 Critical, 3 High, 2 Medium.",
  "dep_summary": "Checked 15 packages. Found 2 CVEs: 1 HIGH, 1 MEDIUM.",
  "total_findings": 9,
  "target": "https://github.com/owner/repo",
  "duration_seconds": 12.4,
  "errors": []
}
```

---

## 🛡️ Detected Vulnerability Categories

| Category | Examples |
|----------|---------|
| **Secrets** | AWS keys, API tokens, hardcoded passwords, private keys |
| **Injection** | SQL injection (string concat, f-strings), shell injection, `os.system()` |
| **XSS** | `innerHTML` assignment, `document.write()` |
| **Dangerous functions** | `eval()`, `exec()` with dynamic input |
| **Network** | HTTP instead of HTTPS, SSL verification disabled |
| **Deserialization** | `pickle.loads()`, `yaml.load()` without SafeLoader |
| **Debug** | Debug mode enabled, default credentials |
| **Auth** | JWT `alg=none` |
| **CVEs** | Known vulnerabilities in Python/Node.js packages via OSV.dev |

---

## 🧪 Testing the GitHub Fetcher

```bash
python -c "
from utils.github_fetcher import fetch_files_as_dict
result = fetch_files_as_dict('https://github.com/pallets/flask')
print(f'Fetched {result[\"files_fetched\"]} files from {result[\"owner\"]}/{result[\"repo\"]}')
print('Manifests found:', list(result['manifests'].keys()))
"
```

---

## 📁 Project Structure

```
secureagent/
├── mcp_server/
│   ├── main.py          # FastAPI app exposing MCP tools
│   ├── tools.py         # Pydantic models for tool I/O
│   └── config.py        # Settings loader (pydantic-settings)
├── agents/
│   ├── orchestrator.py  # Runs all 3 agents with validation
│   ├── code_scanner.py  # Agent 1 — regex + LLM code analysis
│   ├── dep_auditor.py   # Agent 2 — OSV.dev CVE lookups
│   └── report_writer.py # Agent 3 — markdown report generation
├── utils/
│   ├── github_fetcher.py  # Fetch repo files via GitHub API
│   ├── osv_client.py      # Query OSV.dev for CVEs
│   └── patterns.py        # 18+ regex vulnerability patterns
├── output/
│   └── report_template.md # Report structure reference
├── .env.example
├── requirements.txt
└── README.md
```

---

## 🔑 Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `LLM_PROVIDER` | No | `openai` or `gemini` (default: `openai`) |
| `OPENAI_API_KEY` | For LLM | Your OpenAI API key |
| `OPENAI_MODEL` | No | Model name (default: `gpt-4o-mini`) |
| `GEMINI_API_KEY` | For LLM | Your Google Gemini API key |
| `GEMINI_MODEL` | No | Model name (default: `gemini-1.5-flash`) |
| `GITHUB_TOKEN` | No | Raises rate limit from 60 → 5000 req/hr |
| `HOST` | No | Server host (default: `0.0.0.0`) |
| `PORT` | No | Server port (default: `8000`) |
| `MAX_FILES_PER_REPO` | No | Max files to scan per repo (default: `200`) |
| `MAX_FILE_SIZE_KB` | No | Max file size to scan in KB (default: `500`) |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Run tests: `pytest`
4. Submit a pull request

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with ❤️ using FastAPI, CrewAI, and OSV.dev*
