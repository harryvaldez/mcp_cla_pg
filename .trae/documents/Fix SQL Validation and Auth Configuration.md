# Plan to Fix SQL Validation and Authentication Configuration

## 1. Resolve `SET` Keyword Conflict in `_is_sql_readonly`
The `SET` keyword is currently present in both `_READONLY_START` and `_WRITE_KEYWORDS`, causing `_is_sql_readonly` to accept queries starting with `SET` initially but then reject them during token scanning. 
- **Intended Behavior**: I will allow `SET` commands in read-only mode to support session-level configurations (e.g., `SET search_path`, `SET timezone`), which are common in database exploration tools.
- **Action**: Remove `"set"` from the `_WRITE_KEYWORDS` set in `server.py`. This ensures that if a query starts with `SET` (allowed by `_READONLY_START`), it will not be blocked by the subsequent token check.

## 2. Validate `FASTMCP_AUTH_TYPE` Environment Variable
The `_get_auth` function currently returns unrecognized `FASTMCP_AUTH_TYPE` values directly, which can lead to misconfiguration.
- **Intended Behavior**: Validate the `auth_type` against the supported authentication providers and raise a clear error if an invalid value is provided.
- **Action**: 
    - Define the allowed authentication types: `oidc`, `jwt`, `azure-ad`, and `none`.
    - Modify `_get_auth()` in `server.py` to check the provided `FASTMCP_AUTH_TYPE` against this set.
    - If the value is invalid, raise a `ValueError` that includes the provided value and the list of accepted values.
    - If the value is `"none"`, explicitly return `None`.

## 3. Technical Implementation Details
### `server.py` Changes:
- Update `_WRITE_KEYWORDS` set.
- Update `_get_auth()` function to include validation logic and return `None` for `"none"`.

## 4. Verification
- Verify that `_is_sql_readonly("SET search_path = 'public'")` returns `True`.
- Verify that `_is_sql_readonly("SELECT * FROM users")` still returns `True`.
- Verify that `_is_sql_readonly("INSERT INTO users ...")` still returns `False`.
- Verify that `_get_auth()` raises a `ValueError` when `FASTMCP_AUTH_TYPE` is set to an unsupported value like `"invalid-auth"`.
- Verify that `_get_auth()` returns `None` when `FASTMCP_AUTH_TYPE` is set to `"none"`.

Are you okay with this plan?
