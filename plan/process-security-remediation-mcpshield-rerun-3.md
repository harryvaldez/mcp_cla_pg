---
goal: Resolve Reported MCP Security Findings and Execute Post-Push Full Assessment
version: 3.0
date_created: 2026-04-12
last_updated: 2026-04-12
owner: Security Team
status: 'In progress'
tags: [process, security, remediation, mcp-shield, credential-hygiene, ssrf, metadata]
---

# Introduction

![Status: In progress](https://img.shields.io/badge/status-In%20progress-yellow)

This plan defines deterministic remediation for the reported HIGH and MEDIUM findings, enforces the required commit-and-push sequence, and executes a full `mcp-shield` assessment only after GitHub sync.

## 1. Requirements & Constraints

- **REQ-001**: Remove or refactor all code patterns flagged as `secrets_hardcoded` and `credential_in_args` by eliminating inline URI credential formatting in source files.
- **REQ-002**: Validate and constrain outbound URL usage for all `urllib` calls flagged as `ssrf_dynamic_url`.
- **REQ-003**: Ensure all MCP tools flagged as `description_empty` have explicit non-empty descriptions.
- **REQ-004**: Preserve existing behavior of MCP tools and transports unless required for security remediation.
- **REQ-005**: Commit and push remediation artifacts to `origin/main` before running `mcp-shield scan https://github.com/harryvaldez/mcp_cla_pg --full`.
- **SEC-001**: No plaintext credentials or password placeholders may remain in repository-tracked source code.
- **SEC-002**: Unknown external URLs must be either validated/allowlisted or explicitly dispositioned with rationale.
- **CON-001**: Do not include oversized local artifact `baseline_grep_evidence.txt` in commits.
- **CON-002**: Use non-interactive git commands only.
- **GUD-001**: Every scanner finding class must map to a remediation task and a verification command.
- **PAT-001**: Execute in strict order: plan update -> code/doc fixes -> commit/push -> assessment rerun -> results capture.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Build a finding-to-file action map from the reported issues list.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Map `secrets_hardcoded` and `credential_in_args` findings to: `scripts/connection_analysis.py`, `scripts/invoke_analysis.py`, `tests/functional_test.py`, `tests/stress_test_mcp.py`, `tests/stress_test_performance.py`, and related DSN builder locations. | ✅ | 2026-04-12 |
| TASK-002 | Map `ssrf_dynamic_url` findings to URL construction/request callsites in `scripts/validate_remote_workflow.py` and test harness HTTP callers. | ✅ | 2026-04-12 |
| TASK-003 | Map `description_empty`, `unknown_external_url`, and `sensitive_file_access` findings to `server.py` and disposition docs. | ✅ | 2026-04-12 |

### Implementation Phase 2

- GOAL-002: Apply deterministic remediation edits and policy documentation updates.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-004 | Refactor credential handling to env-backed values only and remove hardcoded literal credentials from mapped files. | ✅ | 2026-04-12 |
| TASK-005 | Ensure URL validation/allowlist guard is applied before `urllib.request.Request(...)` and `urlopen(...)` in flagged paths. | ✅ | 2026-04-12 |
| TASK-006 | Ensure tool metadata descriptions are non-empty for flagged MCP tools in `server.py` and document dispositions for acceptable medium findings. | ✅ | 2026-04-12 |

### Implementation Phase 3

- GOAL-003: Verify remediations locally and record evidence.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-007 | Run grep gates for banned credential literals and risky shell patterns in `bin`, `scripts`, and `tests` (excluding cache outputs). | ✅ | 2026-04-12 |
| TASK-008 | Run targeted regression tests for remediated paths and capture pass/skip/failure evidence. | ✅ | 2026-04-12 |
| TASK-009 | Produce verification artifact file under `plan/` summarizing commands and outputs. | ✅ | 2026-04-12 |

### Implementation Phase 4

- GOAL-004: Commit and push remediation before rerunning security assessment tool.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-010 | Stage remediation files while excluding `baseline_grep_evidence.txt`; commit with security remediation message. | ✅ | 2026-04-12 |
| TASK-011 | Push commit to `origin/main` and record resulting commit hash. | ✅ | 2026-04-12 |
| TASK-012 | Execute `mcp-shield scan https://github.com/harryvaldez/mcp_cla_pg --full` and save terminal output artifact. |  |  |

### Implementation Phase 5

- GOAL-005: Close findings based on rerun results.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-013 | Compare rerun findings against baseline classes (`HIGH`, `MEDIUM`, `LOW`) and identify residual items. |  |  |
| TASK-014 | Update `plan/security-remediation-vulnerability-fixes-1.md` finding table statuses to `Closed` or `Dispositioned` with evidence pointers. |  |  |
| TASK-015 | If residual findings remain, create follow-up patch packet and assign owners/ETA in team rollout plan. |  |  |

## 3. Alternatives

- **ALT-001**: Run assessment tool before push. Rejected because requirement mandates commit/push first.
- **ALT-002**: Suppress medium findings globally. Rejected due to audit/compliance traceability loss.
- **ALT-003**: Commit oversized evidence files. Rejected because GitHub size constraints can block push.

## 4. Dependencies

- **DEP-001**: Git remote access to `https://github.com/harryvaldez/mcp_cla_pg.git`.
- **DEP-002**: Availability of local runtime for verification commands.
- **DEP-003**: `mcp-shield` CLI availability to execute the required full scan.
- **DEP-004**: Existing remediation artifacts in `plan/` and security disposition docs.

## 5. Files

- **FILE-001**: `plan/process-security-remediation-mcpshield-rerun-3.md`
- **FILE-002**: `plan/security-remediation-vulnerability-fixes-1.md`
- **FILE-003**: `plan/security-remediation-execution-teamrollout.md`
- **FILE-004**: `plan/phase4-verification-evidence-20260412.md`
- **FILE-005**: `SECURITY_FINDINGS_DISPOSITIONS.md`
- **FILE-006**: `scripts/connection_analysis.py`
- **FILE-007**: `scripts/invoke_analysis.py`
- **FILE-008**: `scripts/validate_remote_workflow.py`
- **FILE-009**: `tests/functional_test.py`
- **FILE-010**: `tests/stress_test_mcp.py`
- **FILE-011**: `tests/stress_test_performance.py`

## 6. Testing

- **TEST-001**: `Get-ChildItem -Path bin,scripts,tests -Recurse -File | Select-String -Pattern 'execSync\(|shell\s*=\s*True|password123|readonly123|R0_mcp' -AllMatches`
- **TEST-002**: `python -m pytest -q tests/test_docker_pg96.py tests/test_remote_workflow.py tests/test_npx_pg96.py tests/test_uv_pg96.py`
- **TEST-003**: `mcp-shield scan https://github.com/harryvaldez/mcp_cla_pg --full`
- **TEST-004**: Validate post-scan status updates in remediation and rollout plans.

## 7. Risks & Assumptions

- **RISK-001**: `mcp-shield` may not be installed locally; mitigation is explicit prerequisite check and blocker documentation.
- **RISK-002**: Scanner may report contextual false positives for environment lookups and controlled external URLs.
- **ASSUMPTION-001**: Current pushed branch `main` contains latest remediation commit.
- **ASSUMPTION-002**: GitHub repository URL is accessible from the scan runtime.

## 8. Related Specifications / Further Reading

[plan/security-remediation-vulnerability-fixes-1.md](plan/security-remediation-vulnerability-fixes-1.md)
[plan/security-remediation-execution-teamrollout.md](plan/security-remediation-execution-teamrollout.md)
[plan/security-scanner-rerun-handoff-20260412.md](plan/security-scanner-rerun-handoff-20260412.md)