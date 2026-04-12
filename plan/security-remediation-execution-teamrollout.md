# Security Remediation Execution Plan (Refined for Team Rollout)

## Assignees and ETA Table

| Task ID | Description | Owner | ETA | Status |
| ------- | ----------- | ----- | --- | ------ |
| TASK-001 | Create finding matrix in plan | Security Team | 2026-04-13 | Completed |
| TASK-002 | Map HIGH findings to files | Security Team | 2026-04-13 | Completed |
| TASK-003 | Classify MEDIUM findings in server.py | Security Team | 2026-04-13 | Completed |
| TASK-004 | Replace execSync in bin/mcp-postgres.js | Alice | 2026-04-15 | Completed |
| TASK-005 | Replace credential DSNs in connection_analysis.py | Bob | 2026-04-15 | Completed |
| TASK-006 | Remove hardcoded passwords in tests | Carol | 2026-04-15 | Completed |
| TASK-007 | Add safe file-open in validate_n8n_json.py | Dave | 2026-04-15 | Completed |
| TASK-008 | Add SSRF guard in validate_remote_workflow.py/tests | Eve | 2026-04-15 | Completed |
| TASK-009 | Enforce urlopen timeout/validation | Eve | 2026-04-15 | Completed |
| TASK-010 | Fix shell-injection in test_npx_pg96.py | Frank | 2026-04-15 | Completed |
| TASK-011 | Add tool descriptions in server.py | Grace | 2026-04-15 | Completed |
| TASK-012 | Add disposition doc for env reads | Security Team | 2026-04-16 | Completed |
| TASK-013 | Add allowlist rationale for auth URLs | Security Team | 2026-04-16 | Completed |
| TASK-014 | Document least-privilege rationale | Security Team | 2026-04-16 | Completed |
| TASK-015 | Run targeted grep gates | QA | 2026-04-17 | Completed |
| TASK-016 | Run targeted tests | QA | 2026-04-17 | Completed |
| TASK-017 | Re-run security scanner | Security Team | 2026-04-17 | Blocked (scanner tool/profile unavailable locally) |
| TASK-018 | Mark findings as Closed with evidence | Security Team | 2026-04-18 | In Progress (awaiting TASK-017 evidence) |

## Notes
- Owners and ETAs are proposed for rollout. Adjust as needed for team bandwidth.
- Status to be updated as tasks progress.
- All evidence artifacts and patch-packet plan are referenced in the main plan and attached in the repo root.
