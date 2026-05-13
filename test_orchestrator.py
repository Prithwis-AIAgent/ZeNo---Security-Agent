from agents.orchestrator import run_audit
from utils.github_fetcher import fetch_repo_files

repo = fetch_repo_files('https://github.com/Prithwis-AIAgent/AI-Agents-for-Medical-Diagnostics')
res = run_audit(repo.source_files, repo.dep_files, 'target', use_llm=False, min_severity='low')
with open('audit_report_test.md', 'w', encoding='utf-8') as f:
    f.write(res.report)
