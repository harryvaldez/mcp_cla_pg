---
goal: Add Optional Okta OAuth Authentication via FastMCP JWTVerifier
version: 1.0
date_created: 2026-06-29
last_updated: 2026-07-01
owner: harryvaldez
status: Implemented
tags: [feature, okta, oauth, auth, jwt, optional, security]
---

# Introduction

![Status: Implemented](https://img.shields.io/badge/status-implemented-green)

Add optional Okta OAuth 2.0 / OIDC authentication to the MCP server. When enabled, every tool call must include a valid Okta-issued JWT bearer token. The Okta sub claim becomes the actor for rate limiting and audit logging. Auth is **disabled by default** and activated via auth_mode: okta in configuration.

Uses FastMCP v3 built-in JWTVerifier from fastmcp.server.auth.providers.jwt - no custom token validation code. The verifier handles JWKS key fetching, signature validation, expiry, issuer, and audience checks natively.

## 1. Requirements

- REQ-001: Okta auth is optional � default auth_mode: disabled preserves existing behavior
- REQ-002: When auth_mode: okta, every tool call requires a valid Okta JWT bearer token
- REQ-003: Actor identity = Okta sub claim (unique per-user, drives rate limiting + audit)
- REQ-004: Privilege level derived from Okta groups and scopes: mcp:write -> write, mcp:read -> read. JWTVerifier validates the token, while the server applies tool-level authorization.
- REQ-005: Uses FastMCP v3 JWTVerifier � no custom crypto, no PyJWT manual calls
- REQ-006: Config via env vars + runtime-policy.yaml
- SEC-001: Custom routes (/health, /readiness, /metrics, /security) remain unauthenticated
- SEC-002: Never log Okta tokens, client secrets, or JWKS responses
- CON-001: No new Python dependencies � FastMCP already bundles pyjwt[crypto]

## 2. Implementation Steps

### Phase 1 � Config & Models

| Task | Description | Completed | Date |
|------|------------|-----------|------|
| TASK-001 | Add Okta fields to AuthConfig in src/models.py | ✅ | 2026-06-29 |
| TASK-002 | Add okta section to config/runtime-policy.yaml | ✅ | 2026-06-29 |
| TASK-003 | Add Okta env vars to .env (commented out, disabled by default) | ✅ | 2026-06-29 |

### Phase 2 � Server Wiring

| Task | Description | Completed | Date |
|------|------------|-----------|------|
| TASK-004 | In src/server.py build_app(): if auth_mode == okta, construct JWTVerifier with jwks_uri, issuer, audience; pass auth=verifier to FastMCP() | ✅ | 2026-06-29 |
| TASK-005 | Store Okta config on AppState for diagnostics (exclude secrets) | ✅ | 2026-06-29 |

### Phase 3 � Actor Resolution

| Task | Description | Completed | Date |
|------|------------|-----------|------|
| TASK-006 | Update _resolve_actor_and_authorize() in pg_tools.py for Okta claims | ✅ | 2026-06-29 |
| TASK-007 | Update _auth_enforced() to recognize auth_mode == okta | ✅ | 2026-06-29 |

### Phase 4 � Tests & Deploy

| Task | Description | Completed | Date |
|------|------------|-----------|------|
| TASK-008 | Add tests/test_okta_auth.py | ✅ | 2026-06-29 |
| TASK-009 | Run ruff check . + pytest -q | ✅ | 2026-06-30 |
| TASK-010 | Rebuild Docker, push, redeploy | ✅ | 2026-06-29 |

## 3. Architecture

Sequence: Client -> MCP (FastMCP) -> JWTVerifier -> Okta JWKS endpoint
JWTVerifier validates sig, exp, iss, aud. FastMCP extracts sub claim as actor and applies privilege checks from groups/scopes.

## 4. Configuration

.env (when enabled):
  OKTA_DOMAIN=your-org.okta.com
  OKTA_CLIENT_ID=0oabc123...
  OKTA_AUTH_SERVER_ID=default

runtime-policy.yaml (new section):
  okta_required_scopes: [mcp:read]
  okta_read_scopes: [mcp:read]
  okta_write_scopes: [mcp:write]

Note: `okta_required_scopes` is retained in the policy model for configuration compatibility, but the current server implementation does not pass it into `JWTVerifier`.

## 5. Files

- FILE-001: src/models.py � Add Okta fields to AuthConfig
- FILE-002: src/server.py � Conditional JWTVerifier + FastMCP auth
- FILE-003: src/tools/pg_tools.py � _resolve_actor_and_authorize + _auth_enforced
- FILE-004: config/runtime-policy.yaml � okta_* sections
- FILE-005: .env � Okta env vars (commented out)
- FILE-006: tests/test_okta_auth.py � NEW

## 6. Testing

- TEST-001: auth_mode disabled -> pass-through (existing behavior)
- TEST-002: auth_mode okta -> JWTVerifier created correctly
- TEST-003: Actor resolution extracts sub from claims
- TEST-004: Scope-based privilege derivation
- TEST-005: All 145 existing tests still pass

## 7. Risks

- RISK-001: JWKS endpoint must be reachable from container
- RISK-002: Key rotation handled by JWTVerifier built-in JWKS client cache
- ASSUMPTION-001: Okta uses RS256 signing (standard)
- ASSUMPTION-002: Scopes in scp claim (Okta default)

