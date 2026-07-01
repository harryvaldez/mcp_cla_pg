# Okta Authentication and Group Setup for This MCP Server

This guide explains how to enable optional Okta OAuth authentication for this FastMCP server, including Okta group mapping for read/write privilege classification.

## Scope and Current Behavior

This document is based on the current implementation in this repository.

- Authentication is optional and disabled by default.
- Okta mode is enabled by setting `auth.auth_mode: okta` in `config/runtime-policy.yaml`.
- When Okta mode is enabled, FastMCP validates bearer tokens using `JWTVerifier` (JWKS, signature, issuer, audience, expiration).
- `JWTVerifier` does not enforce `okta_required_scopes`; scopes and groups are used by the server to derive privilege and apply tool-level authorization.
- Actor identity is taken from the JWT `sub` claim.
- Scopes and groups are parsed to derive a privilege level (`read`, `write`, `none`) for audit context.
- Group precedence is `write group > read group > write scope > read scope`.

Important: Group-based and scope-based privilege enforcement is fully implemented. See the [Read-Group Tool Restrictions](#read-group-tool-restrictions) section below for which tools are restricted for read-level callers.

## Prerequisites

### Okta Prerequisites

- An Okta org (for example `your-org.okta.com`)
- API Access Management enabled (required for custom authorization servers/scopes)
- Admin access to create:
  - OAuth scopes (`mcp:read`, `mcp:write`)
  - Groups (`mcp-readers`, `mcp-writers`)
  - Access token claim for `groups`
  - OIDC app integration

### MCP Server Prerequisites

- This repository configured and running locally or in Docker
- Python 3.11+ or Docker runtime
- Existing DB credentials set in `.env`
- Network egress from server container/host to Okta JWKS endpoint:
  - `https://<OKTA_DOMAIN>/oauth2/<AUTH_SERVER_ID>/v1/keys`

## Step 1: Create Okta Groups

In Okta Admin:

1. Go to Directory > Groups.
2. Create group `mcp-readers`.
3. Create group `mcp-writers`.
4. Assign users (or service principals, depending on your identity model):
   - Read-only users to `mcp-readers`
   - Elevated users to `mcp-writers`

Recommendation:

- Keep `mcp-writers` tightly controlled.
- Use group membership as the primary access signal, with scopes as fallback.

## Step 2: Create/Confirm Authorization Server and Scopes

In Okta Admin:

1. Go to Security > API.
2. Select your Authorization Server (commonly `default`) or create one.
3. Under Scopes, create:
   - `mcp:read`
   - `mcp:write`
4. Ensure policies/rules issue those scopes to the intended clients/users.

## Step 3: Add Groups Claim to Access Tokens

In the same Authorization Server:

1. Open Claims.
2. Add a claim named `groups`.
3. Include in: Access Token.
4. Value type: Groups.
5. Filter to include at least `mcp-readers` and `mcp-writers`.

Expected result:

- Access token contains `scp` (scope list) and `groups` (group list) claims.

## Step 4: Create OIDC App Integration

In Okta Admin:

1. Create an OIDC app integration for your MCP client type.
2. Capture the Client ID.
3. Assign users/groups that should access MCP.
4. Ensure the app can request the scopes you plan to use for privilege classification (`mcp:read` and/or `mcp:write`).

You need these values for server configuration:

- `OKTA_DOMAIN` (for example `your-org.okta.com`)
- `OKTA_CLIENT_ID`
- `OKTA_AUTH_SERVER_ID` (for example `default`)

## Step 5: Configure MCP Server Runtime Policy

Edit `config/runtime-policy.yaml` and add/update the `auth` section:

```yaml
auth:
  auth_mode: okta
  okta_domain: your-org.okta.com
  okta_client_id: 0oa123example
  okta_auth_server_id: default
  okta_required_scopes:
    - mcp:read
  okta_read_scopes:
    - mcp:read
  okta_write_scopes:
    - mcp:write
  okta_read_groups:
    - mcp-readers
  okta_write_groups:
    - mcp-writers
  # Restricted tool suffixes for read-group callers (defaults shown below)
  okta_read_restricted_tool_suffixes:
    - _pg96_hypopg_create_virtual_indexes
    - _pg96_hypopg_explain_with_virtual
    - _pg96_hypopg_find_optimal_indexes
  okta_cross_session_tool_suffixes:
    - _pg96_blocking_sessions
```

Notes:

- `auth` must be nested under `config/runtime-policy.yaml` root.
- The loader reads auth settings from this `auth` block.
- Top-level `okta_*` keys outside `auth` are not used by the current config loader.

## Step 6: Configure Environment Variables

In `.env`, set or uncomment:

```env
OKTA_DOMAIN=your-org.okta.com
OKTA_CLIENT_ID=0oa123example
OKTA_AUTH_SERVER_ID=default
```

Behavior detail:

- Runtime env values override YAML for `domain`, `client_id`, and `auth_server_id` in server startup.

## Step 7: Start or Restart the Server

Python:

```powershell
python -m src.server
```

Docker runtime:

```powershell
docker compose -f docker/docker-compose.runtime.yml --profile local-redis up -d
```

## Step 8: Verify Authentication is Active

### Startup Verification

Check logs for:

- `Okta OAuth enabled (issuer=...)`

If `OKTA_DOMAIN` or `OKTA_CLIENT_ID` is missing while `auth_mode: okta`, startup fails with:

- `RuntimeError: auth_mode=okta requires OKTA_DOMAIN and OKTA_CLIENT_ID`

### Endpoint Behavior Verification

1. Call MCP tool endpoint without bearer token.
2. Expect authentication failure from FastMCP auth layer.
3. Call again with a valid Okta access token containing expected audience/issuer.
4. Expect successful auth path and normal tool execution.

Diagnostics endpoint note:

- `/health`, `/readiness`, `/metrics`, and `/security` remain unauthenticated by design.

### Group and Scope Verification

Validate these token cases:

1. Token has `groups: [mcp-writers]` and only read scope.
Expected derived privilege: `write` (group priority).
2. Token has `groups: [mcp-readers]` and no scopes.
Expected derived privilege: `read`.
3. Token has no matching groups but has `scp: [mcp:write]`.
Expected derived privilege: `write` (scope fallback).
4. Token has neither matching groups nor scopes.
Expected derived privilege: `none`.

Current-state behavior:

- Derived privilege is tracked in auth/audit context.
- Per-tool authorization is enforced in handlers: read-group callers are denied access to HypoPG tools (`_pg96_hypopg_*`) and cross-session inspection tools (`_pg96_blocking_sessions`). Write-group callers have unrestricted access to all tools.
- The restricted tool suffix lists are configurable via `okta_read_restricted_tool_suffixes` and `okta_cross_session_tool_suffixes` in the `auth` section of `config/runtime-policy.yaml`.

## Read-Group Tool Restrictions

When `auth_mode: okta` is enabled, callers authenticated with read-level privileges (via `okta_read_groups` group membership or `mcp:read` scope fallback) are **denied access** to certain tools that pose security or data-exposure risks.

### Restricted Tool Categories

| Category | Tool Suffix Pattern | Reason |
|---|---|---|
| **HypoPG virtual indexes** | `_pg96_hypopg_create_virtual_indexes` | Creates/modifies session-level virtual indexes — modifies internal session state |
| | `_pg96_hypopg_explain_with_virtual` | Requires HypoPG session state — excluded as a group for consistency |
| | `_pg96_hypopg_find_optimal_indexes` | Creates/drops virtual indexes during testing — modifies session state |
| **Cross-session inspection** | `_pg96_blocking_sessions` | Exposes other users' session activity, locks, and queries |

### Behavior Summary

| Caller Type | HypoPG Tools | Blocking Sessions | All Other Tools |
|---|---|---|---|
| Write-group member | ✅ Allowed | ✅ Allowed | ✅ Allowed |
| Read-group member | ❌ Denied (`AUTHZ_DENIED`) | ❌ Denied (`AUTHZ_DENIED`) | ✅ Allowed |
| Scope-only (write) | ✅ Allowed | ✅ Allowed | ✅ Allowed |
| Scope-only (read) | ❌ Denied | ❌ Denied | ✅ Allowed |
| No groups/scopes | ❌ Denied | ❌ Denied | ❌ Denied |

### Configuring Restricted Suffixes

The restricted suffix lists are configurable in `config/runtime-policy.yaml` under the `auth` section:

```yaml
auth:
  okta_read_restricted_tool_suffixes:
    - _pg96_hypopg_create_virtual_indexes
    - _pg96_hypopg_explain_with_virtual
    - _pg96_hypopg_find_optimal_indexes
  okta_cross_session_tool_suffixes:
    - _pg96_blocking_sessions
```

To add or remove restrictions, modify these lists. For example, to allow read-group callers to use `blocking_sessions`, remove `_pg96_blocking_sessions` from `okta_cross_session_tool_suffixes`. To restrict additional tools, add their suffixes to either list.

## Security and Operations Checklist

- Do not log bearer tokens, secrets, or JWKS responses.
- Restrict membership of `mcp-writers`.
- Keep the read/write scope lists minimal and aligned with your app registration.
- Ensure container/host can resolve and reach Okta JWKS endpoint.
- Rotate app credentials and review group assignments regularly.

## Troubleshooting

### Invalid Audience

Symptom:

- Token rejected even though signature is valid.

Action:

- Confirm token `aud` equals configured `OKTA_CLIENT_ID`.

### Invalid Issuer

Symptom:

- Authentication failure with issuer mismatch.

Action:

- Confirm issuer exactly matches:
  - `https://<OKTA_DOMAIN>/oauth2/<OKTA_AUTH_SERVER_ID>`

### No Groups in Token

Symptom:

- Derived privilege falls back to scopes or `none`.

Action:

- Verify `groups` claim is configured in Authorization Server claims.
- Verify assigned users are in `mcp-readers` or `mcp-writers`.

### Startup Fails in Okta Mode

Symptom:

- Runtime error on server boot.

Action:

- Confirm `auth.auth_mode: okta` plus both `OKTA_DOMAIN` and `OKTA_CLIENT_ID`.

## Implementation Verification and Review

This document was reviewed against current source and tests in this repository:

- Auth model fields: `src/models.py`
- Config loading of `auth` section: `src/config_loader.py`
- Okta verifier wiring and startup requirements: `src/server.py`
- Actor resolution and group/scope precedence: `src/tools/pg_tools.py`
- Runtime policy source file: `config/runtime-policy.yaml`
- Behavior tests for scope/group precedence: `tests/test_okta_auth.py`

Review date: 2026-06-30

## References

Internal references:

- `src/models.py`
- `src/config_loader.py`
- `src/server.py`
- `src/tools/pg_tools.py`
- `config/runtime-policy.yaml`
- `tests/test_okta_auth.py`

External references:

- FastMCP documentation: https://gofastmcp.com/
- FastMCP authentication and JWT verifier docs:
  - https://gofastmcp.com/servers/auth/
  - https://gofastmcp.com/servers/auth/jwt/
- Okta OAuth 2.0 and OIDC concepts:
  - https://developer.okta.com/docs/concepts/oauth-openid/
- Okta custom authorization servers and scopes:
  - https://developer.okta.com/docs/guides/customize-authz-server/
- Okta token claims and groups claims:
  - https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/