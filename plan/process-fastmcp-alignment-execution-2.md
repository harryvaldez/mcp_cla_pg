---
goal: Execute Option 1 Patch-and-Validate Workflow with Deterministic Terminal Steps
version: 1.1
date_created: 2026-04-02
last_updated: 2026-04-02
owner: Harry Valdez
status: Planned
tags: [process, execution, terminal, validation, fastmcp]
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

This process artifact provides deterministic terminal steps for Option 1: apply the single patch payload and run scoped validation commands.

## 1. Requirements & Constraints

- REQ-001: Execute exactly one patch apply using Section 9 from plan/feature-fastmcp-server-docs-alignment-7.md.
- REQ-002: Execute three validation commands in sequence with stop-on-failure.
- REQ-003: Record each command outcome in Validation Snapshot.
- SEC-001: Do not run destructive git operations.
- CON-001: Run commands from repository root path c:/Users/HarryValdez/OneDrive/Documents/trae/mcp-postgres.
- CON-002: Use .venv Python interpreter context.
- OPS-001: If any command fails, stop and capture failure summary before retry planning.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Apply the prepared single-operation patch.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Open plan/feature-fastmcp-server-docs-alignment-7.md and copy Section 9 payload only. |  |  |
| TASK-002 | Execute one apply patch operation with copied payload. |  |  |
| TASK-003 | Verify changed files are only: server.py, README.md, DEPLOYMENT.md, tests/functional_test.py, tests/test_tools_pg96.py. |  |  |

### Implementation Phase 2

- GOAL-002: Validate startup gate and tool contract behavior.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-004 | Run CMD-001 and confirm success. |  |  |
| TASK-005 | Run CMD-002 and confirm success. |  |  |
| TASK-006 | Run CMD-003 and confirm success. |  |  |

## 3. Alternatives

- ALT-001: Skip targeted tests and run full suite only. Rejected due to longer feedback loop.
- ALT-002: Apply files manually. Rejected due to higher drift risk versus single patch payload.

## 4. Dependencies

- DEP-001: plan/feature-fastmcp-server-docs-alignment-7.md exists and includes Section 9 payload.
- DEP-002: pytest available in .venv.
- DEP-003: Docker dependencies available for functional tests if required by test selection.

## 5. Files

- FILE-001: plan/feature-fastmcp-server-docs-alignment-7.md
- FILE-002: plan/process-fastmcp-alignment-execution-2.md

## 6. Testing

- TEST-001: python -m pytest tests/functional_test.py -k "legacy_sse or startup" -q
- TEST-002: python -m pytest tests/test_tools_pg96.py -k "transport_gate_changes" -q
- TEST-003: python -m pytest tests/functional_test.py tests/test_tools_pg96.py -q

## 7. Risks & Assumptions

- RISK-001: Functional tests may fail if local Docker services are not ready.
- RISK-002: Environment variables from prior sessions may influence startup behavior.
- ASSUMPTION-001: User intends strict Option 1 execution path with no scope expansion.

## 8. Related Specifications / Further Reading

- plan/feature-fastmcp-server-docs-alignment-7.md
- plan/process-fastmcp-alignment-execution-1.md

## 9. Terminal Command Script

Run in this exact order:

1. Activate environment:

   .\\.venv\\Scripts\\Activate.ps1

2. Apply patch payload from plan/feature-fastmcp-server-docs-alignment-7.md Section 9.

3. Validate changed files:

   git diff --name-only

4. Run targeted startup tests:

   python -m pytest tests/functional_test.py -k "legacy_sse or startup" -q

5. Run contract guard:

   python -m pytest tests/test_tools_pg96.py -k "transport_gate_changes" -q

6. Run combined targeted suite:

   python -m pytest tests/functional_test.py tests/test_tools_pg96.py -q

## 10. Measurable Completion Criteria

- MCC-001: Patch from alignment-7 Section 9 applied once.
- MCC-002: git diff --name-only includes expected target files only.
- MCC-003: TEST-001, TEST-002, TEST-003 all pass.

## 11. Validation Snapshot

- VAL-001: Patch Apply -> Pending
- VAL-002: File Diff Check -> Pending
- VAL-003: TEST-001 -> Pending
- VAL-004: TEST-002 -> Pending
- VAL-005: TEST-003 -> Pending
