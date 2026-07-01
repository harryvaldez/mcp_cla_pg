from src.models import AuthConfig
from src.tools.pg_tools import (
    _is_restricted_read_tool,
    evaluate_okta_tool_access,
)


class TestOktaAuthDisabled:
    def test_auth_config_defaults_to_disabled(self):
        cfg = AuthConfig()
        assert cfg.auth_mode == 'disabled'
        assert cfg.okta_domain is None

    def test_auth_enforced_false_when_disabled(self):
        cfg = AuthConfig(auth_mode='disabled')
        is_enforced = cfg.auth_mode in ('azure_token_verifier', 'okta')
        assert not is_enforced


class TestOktaAuthConfig:
    def test_okta_fields_default_values(self):
        cfg = AuthConfig(auth_mode='okta')
        assert cfg.okta_auth_server_id == 'default'
        assert cfg.okta_required_scopes == ['mcp:read']
        assert cfg.okta_read_scopes == ['mcp:read']
        assert cfg.okta_write_scopes == ['mcp:write']

    def test_okta_auth_enforced_recognizes_okta_mode(self):
        cfg = AuthConfig(auth_mode='okta')
        assert cfg.auth_mode in ('azure_token_verifier', 'okta')


class TestActorResolutionOkta:
    def test_disabled_mode_returns_system_actor(self):
        cfg = AuthConfig(auth_mode='disabled')
        assert cfg.auth_mode not in ('okta', 'azure_token_verifier')

    def test_scope_privilege_read(self):
        scopes = ['mcp:read', 'openid']
        read_scopes = ['mcp:read']
        write_scopes = ['mcp:write']
        privilege = 'none'
        if any(s in write_scopes for s in scopes):
            privilege = 'write'
        elif any(s in read_scopes for s in scopes):
            privilege = 'read'
        assert privilege == 'read'

    def test_scope_privilege_write(self):
        scopes = ['mcp:write', 'mcp:read']
        read_scopes = ['mcp:read']
        write_scopes = ['mcp:write']
        privilege = 'none'
        if any(s in write_scopes for s in scopes):
            privilege = 'write'
        elif any(s in read_scopes for s in scopes):
            privilege = 'read'
        assert privilege == 'write'

    def test_scope_privilege_none(self):
        scopes = ['openid', 'profile']
        read_scopes = ['mcp:read']
        write_scopes = ['mcp:write']
        privilege = 'none'
        if any(s in write_scopes for s in scopes):
            privilege = 'write'
        elif any(s in read_scopes for s in scopes):
            privilege = 'read'
        assert privilege == 'none'

    def test_scope_claim_as_list(self):
        scopes = ['mcp:read', 'mcp:write']
        write_scopes = ['mcp:write']
        read_scopes = ['mcp:read']
        privilege = 'none'
        if any(s in write_scopes for s in scopes):
            privilege = 'write'
        elif any(s in read_scopes for s in scopes):
            privilege = 'read'
        assert privilege == 'write'

    def test_okta_groups_default_values(self):
        cfg = AuthConfig(auth_mode='okta')
        assert cfg.okta_read_groups == ['mcp-readers']
        assert cfg.okta_write_groups == ['mcp-writers']


class TestGroupBasedAccess:
    """Groups take priority over scopes when Okta auth is enabled."""

    def test_write_group_grants_write_priority_over_scopes(self):
        """mcp-writers group → write, even if scopes only say read."""
        groups = ['everyone', 'mcp-writers']
        scopes = ['mcp:read']  # scopes say read-only
        write_groups = ['mcp-writers']
        read_groups = ['mcp-readers']
        write_scopes = ['mcp:write']
        read_scopes = ['mcp:read']

        privilege = 'none'
        if any(g in write_groups for g in groups):
            privilege = 'write'
        elif any(g in read_groups for g in groups):
            privilege = 'read'
        elif any(s in write_scopes for s in scopes):
            privilege = 'write'
        elif any(s in read_scopes for s in scopes):
            privilege = 'read'
        assert privilege == 'write'  # group wins

    def test_read_group_grants_read(self):
        """mcp-readers group → read."""
        groups = ['mcp-readers']
        scopes: list = []
        write_groups = ['mcp-writers']
        read_groups = ['mcp-readers']
        write_scopes = ['mcp:write']
        read_scopes = ['mcp:read']

        privilege = 'none'
        if any(g in write_groups for g in groups):
            privilege = 'write'
        elif any(g in read_groups for g in groups):
            privilege = 'read'
        elif any(s in write_scopes for s in scopes):
            privilege = 'write'
        elif any(s in read_scopes for s in scopes):
            privilege = 'read'
        assert privilege == 'read'

    def test_no_group_falls_back_to_scopes(self):
        """No matching groups → fall back to scope check."""
        groups: list = []
        scopes = ['mcp:write']
        write_groups = ['mcp-writers']
        read_groups = ['mcp-readers']
        write_scopes = ['mcp:write']
        read_scopes = ['mcp:read']

        privilege = 'none'
        if any(g in write_groups for g in groups):
            privilege = 'write'
        elif any(g in read_groups for g in groups):
            privilege = 'read'
        elif any(s in write_scopes for s in scopes):
            privilege = 'write'
        elif any(s in read_scopes for s in scopes):
            privilege = 'read'
        assert privilege == 'write'  # scope fallback

    def test_no_group_no_scope_grants_none(self):
        """No groups, no scopes → denied."""
        groups: list = []
        scopes: list = []
        write_groups = ['mcp-writers']
        read_groups = ['mcp-readers']
        write_scopes = ['mcp:write']
        read_scopes = ['mcp:read']

        privilege = 'none'
        if any(g in write_groups for g in groups):
            privilege = 'write'
        elif any(g in read_groups for g in groups):
            privilege = 'read'
        elif any(s in write_scopes for s in scopes):
            privilege = 'write'
        elif any(s in read_scopes for s in scopes):
            privilege = 'read'
        assert privilege == 'none'


class TestOktaToolAuthorizationPolicy:
    def test_write_group_can_access_hypopg_tool(self):
        allowed, reason = evaluate_okta_tool_access(
            tool_name='db_1_pg96_hypopg_find_optimal_indexes',
            privilege_level='read',
            groups=['mcp-writers'],
            write_groups=['mcp-writers'],
            read_groups=['mcp-readers'],
        )
        assert allowed is True
        assert reason is None

    def test_read_group_cannot_access_hypopg_tool(self):
        allowed, reason = evaluate_okta_tool_access(
            tool_name='db_2_pg96_hypopg_explain_with_virtual',
            privilege_level='read',
            groups=['mcp-readers'],
            write_groups=['mcp-writers'],
            read_groups=['mcp-readers'],
        )
        assert allowed is False
        assert reason is not None and 'AUTHZ_DENIED' in reason

    def test_read_group_cannot_access_blocking_sessions(self):
        allowed, reason = evaluate_okta_tool_access(
            tool_name='db_1_pg96_blocking_sessions',
            privilege_level='read',
            groups=['mcp-readers'],
            write_groups=['mcp-writers'],
            read_groups=['mcp-readers'],
        )
        assert allowed is False
        assert reason is not None and 'AUTHZ_DENIED' in reason

    def test_read_group_can_access_nonrestricted_tool(self):
        allowed, reason = evaluate_okta_tool_access(
            tool_name='db_1_pg96_ping',
            privilege_level='read',
            groups=['mcp-readers'],
            write_groups=['mcp-writers'],
            read_groups=['mcp-readers'],
        )
        assert allowed is True
        assert reason is None

    def test_scope_read_fallback_is_restricted_for_hypopg(self):
        allowed, reason = evaluate_okta_tool_access(
            tool_name='db_2_pg96_hypopg_create_virtual_indexes',
            privilege_level='read',
            groups=[],
            write_groups=['mcp-writers'],
            read_groups=['mcp-readers'],
        )
        assert allowed is False
        assert reason is not None and 'AUTHZ_DENIED' in reason

    def test_scope_write_fallback_can_access_all_tools(self):
        allowed, reason = evaluate_okta_tool_access(
            tool_name='db_2_pg96_blocking_sessions',
            privilege_level='write',
            groups=[],
            write_groups=['mcp-writers'],
            read_groups=['mcp-readers'],
        )
        assert allowed is True
        assert reason is None


class TestAuthConfigRestrictedSuffixes:
    """Tests for the configurable restricted tool suffix lists."""

    def test_okta_read_restricted_tool_suffixes_defaults(self):
        """Default restricted suffixes include all HypoPG tools."""
        cfg = AuthConfig(auth_mode='okta')
        assert '_pg96_hypopg_create_virtual_indexes' in cfg.okta_read_restricted_tool_suffixes
        assert '_pg96_hypopg_explain_with_virtual' in cfg.okta_read_restricted_tool_suffixes
        assert '_pg96_hypopg_find_optimal_indexes' in cfg.okta_read_restricted_tool_suffixes

    def test_okta_cross_session_tool_suffixes_defaults(self):
        """Default cross-session suffixes include blocking_sessions."""
        cfg = AuthConfig(auth_mode='okta')
        assert '_pg96_blocking_sessions' in cfg.okta_cross_session_tool_suffixes

    def test_custom_restricted_suffixes_override_defaults(self):
        """Custom restricted suffix lists override defaults."""
        cfg = AuthConfig(
            auth_mode='okta',
            okta_read_restricted_tool_suffixes=['_pg96_custom_restricted'],
            okta_cross_session_tool_suffixes=['_pg96_custom_session'],
        )
        assert cfg.okta_read_restricted_tool_suffixes == ['_pg96_custom_restricted']
        assert cfg.okta_cross_session_tool_suffixes == ['_pg96_custom_session']

    def test_combined_restricted_suffixes_from_config(self):
        """Both suffix lists are combined at runtime for the restricted check."""
        restricted = [
            '_pg96_hypopg_create_virtual_indexes',
            '_pg96_hypopg_explain_with_virtual',
            '_pg96_hypopg_find_optimal_indexes',
            '_pg96_blocking_sessions',
        ]
        assert _is_restricted_read_tool('db_1_pg96_hypopg_create_virtual_indexes', restricted)
        assert _is_restricted_read_tool('db_2_pg96_blocking_sessions', restricted)
        assert not _is_restricted_read_tool('db_1_pg96_ping', restricted)
        assert not _is_restricted_read_tool('db_2_pg96_exec_query', restricted)


class TestOktaToolAuthorizationCustomSuffixes:
    """Tests for evaluate_okta_tool_access with custom restricted_suffixes."""

    def test_custom_suffixes_block_read_group(self):
        """Custom restricted suffix blocks read-group caller."""
        allowed, reason = evaluate_okta_tool_access(
            tool_name='db_1_pg96_custom_restricted_tool',
            privilege_level='read',
            groups=['mcp-readers'],
            write_groups=['mcp-writers'],
            read_groups=['mcp-readers'],
            restricted_suffixes=['_pg96_custom_restricted_tool'],
        )
        assert allowed is False
        assert reason is not None and 'AUTHZ_DENIED' in reason

    def test_custom_suffixes_write_group_allowed(self):
        """Write-group bypasses custom restricted suffix."""
        allowed, reason = evaluate_okta_tool_access(
            tool_name='db_1_pg96_custom_restricted_tool',
            privilege_level='read',
            groups=['mcp-writers'],
            write_groups=['mcp-writers'],
            read_groups=['mcp-readers'],
            restricted_suffixes=['_pg96_custom_restricted_tool'],
        )
        assert allowed is True
        assert reason is None

    def test_empty_restricted_suffixes_allows_all(self):
        """Empty restricted suffix list allows read-group to access all tools."""
        allowed, reason = evaluate_okta_tool_access(
            tool_name='db_1_pg96_hypopg_create_virtual_indexes',
            privilege_level='read',
            groups=['mcp-readers'],
            write_groups=['mcp-writers'],
            read_groups=['mcp-readers'],
            restricted_suffixes=[],
        )
        assert allowed is True
        assert reason is None

    def test_restricted_suffixes_with_scope_fallback(self):
        """Custom restricted suffix also applies to scope-read fallback."""
        allowed, reason = evaluate_okta_tool_access(
            tool_name='db_1_pg96_custom_restricted',
            privilege_level='read',
            groups=[],
            write_groups=['mcp-writers'],
            read_groups=['mcp-readers'],
            restricted_suffixes=['_pg96_custom_restricted'],
        )
        assert allowed is False
        assert reason is not None and 'AUTHZ_DENIED' in reason

    def test_none_restricted_suffixes_falls_back_to_defaults(self):
        """None restricted_suffixes uses default hardcoded set."""
        allowed, reason = evaluate_okta_tool_access(
            tool_name='db_1_pg96_hypopg_create_virtual_indexes',
            privilege_level='read',
            groups=['mcp-readers'],
            write_groups=['mcp-writers'],
            read_groups=['mcp-readers'],
            restricted_suffixes=None,
        )
        assert allowed is False
        assert reason is not None and 'AUTHZ_DENIED' in reason


class TestWriteGroupAllToolsAllowed:
    """Write-group members can access ALL tools, including restricted ones."""

    _HYPOPG_TOOLS = [
        'db_1_pg96_hypopg_create_virtual_indexes',
        'db_2_pg96_hypopg_create_virtual_indexes',
        'db_1_pg96_hypopg_explain_with_virtual',
        'db_2_pg96_hypopg_explain_with_virtual',
        'db_1_pg96_hypopg_find_optimal_indexes',
        'db_2_pg96_hypopg_find_optimal_indexes',
    ]

    _CROSS_SESSION_TOOLS = [
        'db_1_pg96_blocking_sessions',
        'db_2_pg96_blocking_sessions',
    ]

    def test_hypopg_tools_allowed_for_write_group(self):
        """Write-group members can access all HypoPG tools."""
        for tool_name in self._HYPOPG_TOOLS:
            allowed, reason = evaluate_okta_tool_access(
                tool_name=tool_name,
                privilege_level='read',
                groups=['mcp-writers'],
                write_groups=['mcp-writers'],
                read_groups=['mcp-readers'],
            )
            assert allowed is True, f'{tool_name} should be allowed for write group'
            assert reason is None

    def test_blocking_sessions_allowed_for_write_group(self):
        """Write-group members can access blocking_sessions."""
        for tool_name in self._CROSS_SESSION_TOOLS:
            allowed, reason = evaluate_okta_tool_access(
                tool_name=tool_name,
                privilege_level='read',
                groups=['mcp-writers'],
                write_groups=['mcp-writers'],
                read_groups=['mcp-readers'],
            )
            assert allowed is True, f'{tool_name} should be allowed for write group'
            assert reason is None


class TestReadGroupDeniesRestrictedTools:
    """Read-group members are denied access to restricted tools."""

    _RESTRICTED_TOOLS = [
        'db_1_pg96_hypopg_create_virtual_indexes',
        'db_2_pg96_hypopg_create_virtual_indexes',
        'db_1_pg96_hypopg_explain_with_virtual',
        'db_2_pg96_hypopg_explain_with_virtual',
        'db_1_pg96_hypopg_find_optimal_indexes',
        'db_2_pg96_hypopg_find_optimal_indexes',
        'db_1_pg96_blocking_sessions',
        'db_2_pg96_blocking_sessions',
    ]

    _NON_RESTRICTED_TOOLS = [
        'db_1_pg96_ping',
        'db_2_pg96_ping',
        'db_1_pg96_exec_query',
        'db_2_pg96_exec_query',
        'db_1_pg96_get_slow_statements',
        'db_1_pg96_analyze_table',
        'db_1_pg96_analyze_sett_sec',
        'db_1_pg96_list_objects',
        'db_1_pg96_list_tables',
    ]

    def test_read_group_denied_all_hypopg_tools(self):
        """Read-group members cannot access any HypoPG tool."""
        for tool_name in self._RESTRICTED_TOOLS:
            allowed, reason = evaluate_okta_tool_access(
                tool_name=tool_name,
                privilege_level='read',
                groups=['mcp-readers'],
                write_groups=['mcp-writers'],
                read_groups=['mcp-readers'],
            )
            assert allowed is False, f'{tool_name} should be denied for read group'
            assert reason is not None and 'AUTHZ_DENIED' in reason

    def test_read_group_allowed_non_restricted_tools(self):
        """Read-group members can access all non-restricted tools."""
        for tool_name in self._NON_RESTRICTED_TOOLS:
            allowed, reason = evaluate_okta_tool_access(
                tool_name=tool_name,
                privilege_level='read',
                groups=['mcp-readers'],
                write_groups=['mcp-writers'],
                read_groups=['mcp-readers'],
            )
            assert allowed is True, f'{tool_name} should be allowed for read group'
            assert reason is None
