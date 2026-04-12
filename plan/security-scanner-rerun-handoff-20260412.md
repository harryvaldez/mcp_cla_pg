# Security Scanner Rerun Handoff (TASK-017)

## Why this handoff exists
Local remediation and verification are complete, but the baseline scanner profile/toolchain is not installed in this environment. TASK-017 must run in the original scanning environment to preserve comparability.

## Inputs to use
- Updated remediation plan: plan/security-remediation-vulnerability-fixes-1.md
- Dispositions: SECURITY_FINDINGS_DISPOSITIONS.md
- Local verification evidence: plan/phase4-verification-evidence-20260412.md
- Patch packet: patch_packet_plan.md

## Required output
- Scanner report artifact (same scanner/profile as baseline)
- Summary showing HIGH = 0
- MEDIUM findings list with each item mapped to either:
  - fixed code location, or
  - approved disposition in SECURITY_FINDINGS_DISPOSITIONS.md

## Completion criteria for TASK-017
- Scanner rerun executed using baseline-compatible settings.
- Report artifact linked back into remediation plan.

## Completion criteria for TASK-018
- Update each row in Phase 1 Output to `Closed`.
- Add evidence pointer per row (scanner report id/path, command output, commit hash).

## Suggested plan update after scanner rerun
- Set TASK-017 to Completed with execution date.
- Set TASK-018 to Completed with execution date.
- Update top-level plan status from Planned/In Progress to Completed.
