---
goal: Deterministic README and Deployment Documentation Consistency Remediation
version: 1.0
date_created: 2026-04-12
last_updated: 2026-04-12
owner: Harry Valdez
status: Planned
tags: [process, docs, consistency, readme, deployment]
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

This plan defines deterministic steps to align README and deployment documentation with current runtime behavior and published release metadata, with explicit validation and zero interpretation required.

## 1. Requirements & Constraints

- **REQ-001**: Normalize all documented transport defaults to `http` primary, `sse` legacy compatibility, `stdio` local mode.
- **REQ-002**: Normalize all documented default HTTP ports to `8085` unless a section explicitly documents container port mapping.
- **REQ-003**: Ensure Docker digest references in README are internally consistent with the current release snapshot section.
- **REQ-004**: Ensure environment-variable tables in README and DEPLOYMENT use the same wording for overlapping keys.
- **REQ-005**: Preserve all existing MCP tool names, examples, and signatures unless a mismatch with runtime defaults is proven.
- **SEC-001**: Do not introduce instructions that weaken authentication requirements for write mode.
- **DOC-001**: Keep existing section order and headings in README unless required to remove contradictions.
- **CON-001**: Modify only documentation files in this scope.
- **GUD-001**: Prefer smallest textual edits that resolve contradictions.
- **PAT-001**: Every changed statement must have one corresponding validation check in Section 6.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Produce a complete contradiction inventory across README and deployment docs.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Scan [README.md](README.md) for all occurrences of digest references (`sha256:`), transport defaults (`MCP_TRANSPORT`), and default ports (`MCP_PORT`, hard-coded URLs). |  |  |
| TASK-002 | Scan [DEPLOYMENT.md](DEPLOYMENT.md) for the same keys and capture exact conflicting strings in a comparison table. |  |  |
| TASK-003 | Create a deterministic contradiction ledger in [plan/process-readme-deployment-consistency-1.md](plan/process-readme-deployment-consistency-1.md) under an added subsection `Phase 1 Output` with one row per contradiction. |  |  |

### Implementation Phase 2

- GOAL-002: Apply minimal text edits to resolve all documented contradictions.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-004 | Update [README.md](README.md) Docker commands and pinned digest examples so all digest values match the latest release snapshot digest or explicitly label historical digests by date. |  |  |
| TASK-005 | Update [README.md](README.md) and [DEPLOYMENT.md](DEPLOYMENT.md) wording for `MCP_TRANSPORT` and `MCP_PORT` to identical normalized phrasing for overlapping sections. |  |  |
| TASK-006 | Fix any malformed list or table line breaks in [README.md](README.md) discovered during Phase 1 (including truncated bullet text artifacts). |  |  |

### Implementation Phase 3

- GOAL-003: Verify deterministic documentation correctness via automated and manual checks.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-007 | Run `rg "sha256:" README.md DEPLOYMENT.md` and verify digest values are either identical for current release references or explicitly contextualized as historical references. |  |  |
| TASK-008 | Run `rg "MCP_TRANSPORT|MCP_PORT|8085|8000|/sse|/mcp" README.md DEPLOYMENT.md` and confirm no unresolved contradictions remain. |  |  |
| TASK-009 | Execute markdown lint or structural validation command available in repository tooling and confirm no new markdown-format errors in edited files. |  |  |

## 3. Alternatives

- **ALT-001**: Rewrite README sections from scratch. Rejected because high churn increases review risk and may regress validated content.
- **ALT-002**: Keep mixed digest references without context. Rejected because this produces operational ambiguity for deployment pinning.
- **ALT-003**: Defer consistency checks to release day. Rejected because release-time doc drift creates avoidable deployment errors.

## 4. Dependencies

- **DEP-001**: Existing release metadata entries in [README.md](README.md).
- **DEP-002**: Current deployment guidance in [DEPLOYMENT.md](DEPLOYMENT.md).
- **DEP-003**: `rg` availability for deterministic string verification.

## 5. Files

- **FILE-001**: [README.md](README.md) - primary user-facing operational documentation.
- **FILE-002**: [DEPLOYMENT.md](DEPLOYMENT.md) - deployment configuration and defaults.
- **FILE-003**: [plan/process-readme-deployment-consistency-1.md](plan/process-readme-deployment-consistency-1.md) - execution tracker and contradiction ledger.

## 6. Testing

- **TEST-001**: Validate no contradictory default transport statements remain between [README.md](README.md) and [DEPLOYMENT.md](DEPLOYMENT.md).
- **TEST-002**: Validate no contradictory default port statements remain between [README.md](README.md) and [DEPLOYMENT.md](DEPLOYMENT.md).
- **TEST-003**: Validate current-release digest appears consistently in all non-historical pinned-image examples in [README.md](README.md).
- **TEST-004**: Validate markdown renders without malformed list/table artifacts in edited sections.

## 7. Risks & Assumptions

- **RISK-001**: Historical digest records may be intentionally retained and can be mistaken for contradictions without date labels.
- **RISK-002**: Examples for container networking may intentionally use different URLs than local runtime examples.
- **ASSUMPTION-001**: Release snapshot on 2026-04-12 is the authoritative source for current digest references.
- **ASSUMPTION-002**: Documentation-only edits are acceptable without runtime code changes.

## 8. Related Specifications / Further Reading

[README.md](README.md)
[DEPLOYMENT.md](DEPLOYMENT.md)
[plan/feature-fastmcp-server-docs-alignment-7.md](plan/feature-fastmcp-server-docs-alignment-7.md)