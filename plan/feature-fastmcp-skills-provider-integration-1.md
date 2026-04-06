---
goal: Integrate FastMCP Skills Provider and incorporate Smithery postgresql skill into runtime resources
version: 1.0
date_created: 2026-04-04
last_updated: 2026-04-05
owner: Harry Valdez
status: Complete
tags: [feature, fastmcp, skills, integration, smithery]
---

# Introduction

![Status: Complete](https://img.shields.io/badge/status-Complete-brightgreen)

This plan introduces native FastMCP Skills Provider support based on https://gofastmcp.com/servers/providers/skills and incorporates the Smithery skill from npx @smithery/cli@latest skill add sickn33/postgresql into this server's discoverable resources.

## 1. Requirements & Constraints

- REQ-001: Use FastMCP provider classes from fastmcp.server.providers.skills instead of only custom local skills resources.
- REQ-002: Make the Smithery skill installed via npx @smithery/cli@latest skill add sickn33/postgresql discoverable through MCP resources at runtime.
- REQ-003: Keep existing server behavior for db_pg96 tools unchanged.
- REQ-004: Keep existing custom resources skills://index and skills://{skill_id} operational during migration window.
- REQ-005: Add deterministic environment variable controls for provider enablement and reload behavior.
- SEC-001: Do not expose files outside configured skill roots.
- SEC-002: Reject non-directory or missing roots silently and log warnings without crashing startup.
- CON-001: Current dependency range must remain fastmcp[auth,tasks]>=3.0.0,<4.
- CON-002: Existing code location for skills registration is in server.py function _register_skills_resources and call site near mcp initialization.
- GUD-001: Follow FastMCP Skills Provider URI conventions skill://<skill>/SKILL.md and skill://<skill>/_manifest.
- GUD-002: Prefer vendor default roots for Copilot skills while allowing explicit overrides via env vars.
- PAT-001: Preserve backward compatibility first, then deprecate old behavior with explicit docs.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Add provider-based runtime plumbing and configuration for Skills Provider in server startup.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Update server imports in server.py to include SkillsDirectoryProvider and CopilotSkillsProvider from fastmcp.server.providers.skills. | ✅ | 2026-04-05 |
| TASK-002 | Add function _env_optional_string(name: str) returning Optional[str] in server.py to centralize nullable env parsing for provider options. | ✅ | 2026-04-05 |
| TASK-003 | Add function _resolve_provider_skills_roots() in server.py with ordered root resolution: 1) MCP_SKILLS_DIRS or FASTMCP_SKILLS_DIRS when set, 2) workspace .trae/skills, 3) ~/.copilot/skills. | ✅ | 2026-04-05 |
| TASK-004 | Add function _register_fastmcp_skills_provider() in server.py that reads MCP_SKILLS_PROVIDER_ENABLED (default true), MCP_SKILLS_PROVIDER_RELOAD (default false), and MCP_SKILLS_SUPPORTING_FILES_MODE (template or resources, default template). | ✅ | 2026-04-05 |
| TASK-005 | In _register_fastmcp_skills_provider(), instantiate SkillsDirectoryProvider with resolved roots and supporting_files mode, then call mcp.add_provider(provider). | ✅ | 2026-04-05 |
| TASK-006 | Keep existing _register_skills_resources() call in place and add warning log if both provider and legacy resources are enabled to indicate temporary compatibility mode. | ✅ | 2026-04-05 |

### Implementation Phase 2

- GOAL-002: Incorporate Smithery postgresql skill and ensure deterministic discovery from runtime.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-007 | Add scripts/install_smithery_skill.ps1 that runs npx @smithery/cli@latest skill add sickn33/postgresql and exits non-zero on failure. | ✅ | 2026-04-05 |
| TASK-008 | Add scripts/verify_skill_install.ps1 to verify at least one SKILL.md exists for the installed skill under configured roots and print resolved skill id(s). | ✅ | 2026-04-05 |
| TASK-009 | Add README.md section Skills Provider Integration with exact install command, expected install root, and expected resources skill://<id>/SKILL.md and skill://<id>/_manifest. | ✅ | 2026-04-05 |
| TASK-010 | Add README.md environment table rows for MCP_SKILLS_PROVIDER_ENABLED, MCP_SKILLS_PROVIDER_RELOAD, and MCP_SKILLS_SUPPORTING_FILES_MODE with defaults and accepted values. | ✅ | 2026-04-05 |
| TASK-011 | Add DEPLOYMENT.md operational note for production: set MCP_SKILLS_PROVIDER_RELOAD=false and restrict MCP_SKILLS_DIRS to trusted directories only. | ✅ | 2026-04-05 |
| TASK-012 | Add compatibility note in README.md that existing skills://index resources remain available during migration and are planned for future deprecation. | ✅ | 2026-04-05 |

### Implementation Phase 3

- GOAL-003: Add automated tests and validation for provider and Smithery skill incorporation.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-013 | Add tests in tests/functional_test.py: test_skills_provider_registers_when_enabled by monkeypatching mcp.add_provider and env flags. | ✅ | 2026-04-05 |
| TASK-014 | Add tests in tests/functional_test.py: test_skills_provider_disabled_when_flag_false. | ✅ | 2026-04-05 |
| TASK-015 | Add tests in tests/functional_test.py: test_skills_provider_root_precedence_env_over_workspace_over_copilot using temporary directories. | ✅ | 2026-04-05 |
| TASK-016 | Add tests in tests/test_tools_pg96.py: test_legacy_skills_resources_still_register to protect backward compatibility. | ✅ | 2026-04-05 |
| TASK-017 | Add tests in tests/functional_test.py: test_supporting_files_mode_validation_rejects_invalid_values with ValueError message containing accepted values template/resources. | ✅ | 2026-04-05 |
| TASK-018 | Execute pytest target set: tests/functional_test.py and tests/test_tools_pg96.py; store results in test_results.json update section for skills-provider coverage. | ✅ | 2026-04-05 |

## 3. Alternatives

- ALT-001: Replace legacy skills:// resources immediately and use only FastMCP provider. Rejected to avoid breaking existing clients depending on current resource URIs.
- ALT-002: Use CopilotSkillsProvider only without custom roots. Rejected because workspace-scoped .trae/skills content must remain discoverable.
- ALT-003: Add skill content directly to repository under .trae/skills/postgresql. Rejected because user requirement explicitly references Smithery-installed skill incorporation path.

## 4. Dependencies

- DEP-001: fastmcp[auth,tasks]>=3.0.0,<4 already present in pyproject.toml and requirements.txt.
- DEP-002: Node.js and npx availability required to execute npx @smithery/cli@latest skill add sickn33/postgresql.
- DEP-003: Network access to Smithery registry during skill installation.
- DEP-004: File system access to user skills root (expected default ~/.copilot/skills).

## 5. Files

- FILE-001: server.py - Add provider imports, env parsing, root resolution, and provider registration call.
- FILE-002: README.md - Add Skills Provider setup, Smithery command, env variables, and migration notes.
- FILE-003: DEPLOYMENT.md - Add production guidance for skills provider operation.
- FILE-004: tests/functional_test.py - Add provider registration and root precedence tests.
- FILE-005: tests/test_tools_pg96.py - Add legacy resources compatibility test.
- FILE-006: scripts/install_smithery_skill.ps1 - Deterministic install script for requested skill.
- FILE-007: scripts/verify_skill_install.ps1 - Deterministic verification script for incorporated skill.

## 6. Testing

- TEST-001: Unit test for _resolve_provider_skills_roots precedence and path normalization.
- TEST-002: Unit test for _register_fastmcp_skills_provider enable/disable toggle behavior.
- TEST-003: Unit test for supporting_files mode validation and defaults.
- TEST-004: Integration test confirming legacy skills://index still resolves while provider is enabled.
- TEST-005: Integration test confirming provider-exposed resources include skill://.../SKILL.md after Smithery install.
- TEST-006: Script-level validation that scripts/verify_skill_install.ps1 exits 0 only when target skill files are present.

## 7. Risks & Assumptions

- RISK-001: Smithery CLI may install skill into a root not included in default provider roots.
- RISK-002: Provider reload mode can increase per-request overhead if left enabled in production.
- RISK-003: Skill naming collisions across roots may change visible skill ids.
- ASSUMPTION-001: fastmcp version in current environment supports SkillsDirectoryProvider and vendor providers.
- ASSUMPTION-002: Existing clients can tolerate parallel availability of skills:// and skill:// URIs during migration.
- ASSUMPTION-003: User intends to keep Smithery-managed skill updates external to repository version control.

## 8. Related Specifications / Further Reading

- https://gofastmcp.com/servers/providers/skills
- https://raw.githubusercontent.com/modelcontextprotocol/python-sdk/main/README.md
- plan/feature-fastmcp-server-alignment-1.md
- plan/feature-fastmcp-server-docs-alignment-7.md