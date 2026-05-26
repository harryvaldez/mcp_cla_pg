# MCP Security Agent Workflow

Use this workflow to keep security checks and security fixes auditable, minimal, and repeatable.

## Purpose

This repository provides two complementary custom agents:

- `MCP Security Review`: identifies and prioritizes security findings
- `MCP Security Remediation`: applies minimal, test-backed fixes

Running them in sequence reduces noise, improves traceability, and keeps remediation scoped to validated findings.

## Recommended Sequence

1. Run `MCP Security Review` first.
2. Run `MCP Security Remediation` on accepted findings.
3. Re-run `MCP Security Review` for closure and residual risk.

## Suggested Prompts

Review phase:

- "MCP security review for this PR against read-only posture, input validation, authz/rate limiting, and audit logging."

Remediation phase:

- "Remediate the confirmed High/Medium findings with minimal patches and show test evidence."

Closure phase:

- "Re-review after remediation and report remaining risks or approve."

## Expected Outputs

### MCP Security Review

- Findings sorted by severity (`Critical`, `High`, `Medium`, `Low`)
- Location and concise evidence
- Risk statement and minimal fix recommendation
- Open questions/assumptions
- Decision: `Approve`, `Approve with follow-ups`, or `Block`

### MCP Security Remediation

- Applied fixes with rationale
- Finding-to-fix mapping
- Test evidence (commands and outcomes)
- Residual risks/follow-ups
- Status: `Resolved`, `Partially Resolved`, or `Blocked`

## Guardrails

- Keep read-only defaults and write guard expectations intact.
- Preserve centralized input validation and parameterized SQL patterns.
- Do not weaken authz/rate limiting/audit behavior to satisfy tests.
- Prefer smallest safe patch set that closes accepted findings.
