import asyncio
import importlib
import json
import hashlib
import logging
import os
import re
import sys
import time
import uuid
import threading
import atexit
import signal
import decimal
from datetime import datetime, date, timedelta, timezone
from urllib.parse import quote, urlparse, urlunparse, urlsplit, urlunsplit
from typing import Any, Optional, cast

from sshtunnel import SSHTunnelForwarder
from fastmcp import FastMCP
from psycopg import Error as PsycopgError
from psycopg import sql
from psycopg.errors import UndefinedTable
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row
from starlette.requests import Request
from starlette.responses import PlainTextResponse, JSONResponse, HTMLResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware import Middleware
from starlette.applications import Starlette
from starlette.routing import Route
import uvicorn

# Startup Confirmation Dialog
# As requested: "once this MCP is loaded, it will load a dialog box asking the user's confirmation"
if sys.platform == 'win32':
    try:
        import ctypes
        def show_startup_confirmation():
            # MessageBox constants
            MB_YESNO = 0x04
            MB_ICONQUESTION = 0x20
            MB_TOPMOST = 0x40000
            MB_SETFOREGROUND = 0x10000
            IDYES = 6

            result = ctypes.windll.user32.MessageBoxW(
                0, 
                "This MCP server is in Beta version. Review all commands before running.  Do you want to proceed?", 
                "MCP Server Confirmation", 
                MB_YESNO | MB_ICONQUESTION | MB_TOPMOST | MB_SETFOREGROUND
            )
            
            if result != IDYES:
                sys.exit(0)

        if os.environ.get("MCP_SKIP_CONFIRMATION", "").lower() != "true":
            show_startup_confirmation()
    except Exception as e:
        # If dialog fails, log it but proceed (or exit? safe to proceed if UI fails, but maybe log to stderr)
        sys.stderr.write(f"Warning: Could not show startup confirmation dialog: {e}\n")

# Configure structured logging
log_level_str = os.environ.get("MCP_LOG_LEVEL", "INFO").upper()
log_level = getattr(logging, log_level_str, logging.INFO)
log_file = os.environ.get("MCP_LOG_FILE")

_logging_kwargs: dict[str, Any] = {
    "level": log_level,
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "filename": log_file,
}
if log_file:
    _logging_kwargs["filemode"] = "a"

logging.basicConfig(**_logging_kwargs)
logger = logging.getLogger("mcp-postgres")


def _import_symbol(module_path: str, symbol_name: str) -> Any:
    module = importlib.import_module(module_path)
    try:
        return getattr(module, symbol_name)
    except AttributeError as exc:
        raise RuntimeError(f"Missing symbol '{symbol_name}' in module '{module_path}'") from exc


def _env_optional_int(name: str) -> int | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return None
    return int(value)


def _build_auth_client_storage() -> Any:
    """Build optional FastMCP OAuth/OIDC client storage from environment variables."""
    backend = (os.environ.get("FASTMCP_CLIENT_STORAGE_BACKEND") or "").strip().lower()
    if not backend:
        return None

    default_collection = os.environ.get("FASTMCP_CLIENT_STORAGE_COLLECTION")

    if backend == "memory":
        MemoryStore = _import_symbol("key_value.aio.stores.memory", "MemoryStore")
        store = MemoryStore(default_collection=default_collection)
    elif backend in {"disk", "file"}:
        DiskStore = _import_symbol("key_value.aio.stores.disk", "DiskStore")
        store = DiskStore(
            directory=os.environ.get("FASTMCP_CLIENT_STORAGE_PATH", ".fastmcp-client-storage"),
            max_size=_env_optional_int("FASTMCP_CLIENT_STORAGE_MAX_SIZE"),
            default_collection=default_collection,
        )
    elif backend == "redis":
        RedisStore = _import_symbol("key_value.aio.stores.redis", "RedisStore")
        redis_url = os.environ.get("FASTMCP_CLIENT_STORAGE_REDIS_URL")
        if redis_url:
            store = RedisStore(url=redis_url, default_collection=default_collection)
        else:
            store = RedisStore(
                host=os.environ.get("FASTMCP_CLIENT_STORAGE_REDIS_HOST", "localhost"),
                port=int(os.environ.get("FASTMCP_CLIENT_STORAGE_REDIS_PORT", "6379")),
                db=int(os.environ.get("FASTMCP_CLIENT_STORAGE_REDIS_DB", "0")),
                password=os.environ.get("FASTMCP_CLIENT_STORAGE_REDIS_PASSWORD"),
                default_collection=default_collection,
            )
    else:
        raise ValueError(
            "Invalid FASTMCP_CLIENT_STORAGE_BACKEND. Accepted values are: memory, disk, redis"
        )

    encryption_key = os.environ.get("FASTMCP_CLIENT_STORAGE_ENCRYPTION_KEY")
    if encryption_key:
        FernetEncryptionWrapper = _import_symbol(
            "key_value.aio.wrappers.encryption", "FernetEncryptionWrapper"
        )
        Fernet = _import_symbol("cryptography.fernet", "Fernet")
        try:
            fernet = Fernet(encryption_key.encode("ascii"))
        except ValueError as exc:
            logger.error(
                "Invalid FASTMCP_CLIENT_STORAGE_ENCRYPTION_KEY. "
                "Expected a URL-safe base64-encoded Fernet key."
            )
            raise RuntimeError(
                "Invalid FASTMCP_CLIENT_STORAGE_ENCRYPTION_KEY format."
            ) from exc
        store = FernetEncryptionWrapper(
            key_value=store,
            fernet=fernet,
        )

    return store

# Patch for Windows asyncio ProactorEventLoop "ConnectionResetError" noise on shutdown
# References:
# - https://bugs.python.org/issue39232 (bpo-39232)
# - https://github.com/python/cpython/issues/83413
# Rationale:
# On Windows, when the ProactorEventLoop is closing, if a connection is forcibly closed
# by the remote (or the process is terminating), _call_connection_lost can raise
# ConnectionResetError (WinError 10054). This is harmless but noisy in logs.
if sys.platform == 'win32':
    # This issue primarily affects Python 3.8+, where Proactor is the default.
    if sys.version_info >= (3, 8):
        try:
            from asyncio.proactor_events import _ProactorBasePipeTransport

            original_call_connection_lost = getattr(_ProactorBasePipeTransport, "_call_connection_lost", None)

            if callable(original_call_connection_lost):
                original_call_connection_lost_fn = cast(Any, original_call_connection_lost)
                def _silenced_call_connection_lost(self, exc):
                    try:
                        original_call_connection_lost_fn(self, exc)
                    except ConnectionResetError:
                        pass  # Benign: connection forcibly closed by remote host during shutdown

                setattr(_ProactorBasePipeTransport, "_call_connection_lost", _silenced_call_connection_lost)
                logger.debug("Applied workaround for asyncio ProactorEventLoop ConnectionResetError")
            else:
                logger.debug("Skipping asyncio workaround: _call_connection_lost not found")
        except ImportError:
            logger.info("Could not import asyncio.proactor_events._ProactorBasePipeTransport; skipping workaround")
    else:
        logger.debug("Skipping asyncio ProactorEventLoop workaround (Python version < 3.8)")

def _get_auth() -> Any:
    auth_type = os.environ.get("FASTMCP_AUTH_TYPE")
    if not auth_type:
        return None

    auth_type_lower = auth_type.lower()
    allowed_auth_types = {"oidc", "jwt", "azure-ad", "github", "google", "oauth2", "none"}
    
    if auth_type_lower not in allowed_auth_types:
        raise ValueError(
            f"Invalid FASTMCP_AUTH_TYPE: '{auth_type}'. "
            f"Accepted values are: {', '.join(sorted(allowed_auth_types))}"
        )

    if auth_type_lower == "none":
        return None

    client_storage = _build_auth_client_storage()

    # Full OIDC Proxy (handles login flow)
    if auth_type_lower == "oidc":
        OIDCProxy = _import_symbol("fastmcp.server.auth.oidc_proxy", "OIDCProxy")

        config_url = os.environ.get("FASTMCP_OIDC_CONFIG_URL")
        client_id = os.environ.get("FASTMCP_OIDC_CLIENT_ID")
        client_secret = os.environ.get("FASTMCP_OIDC_CLIENT_SECRET")
        base_url = os.environ.get("FASTMCP_OIDC_BASE_URL")

        if not all([config_url, client_id, client_secret, base_url]):
            raise RuntimeError(
                "OIDC authentication requires FASTMCP_OIDC_CONFIG_URL, FASTMCP_OIDC_CLIENT_ID, "
                "FASTMCP_OIDC_CLIENT_SECRET, and FASTMCP_OIDC_BASE_URL"
            )

        return OIDCProxy(
            config_url=config_url,
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            audience=os.environ.get("FASTMCP_OIDC_AUDIENCE"),
            client_storage=client_storage,
        )

    # Pure JWT Verification (resource server mode)
    if auth_type_lower == "jwt":
        JWTVerifier = _import_symbol("fastmcp.server.auth.providers.jwt", "JWTVerifier")

        jwks_uri = os.environ.get("FASTMCP_JWT_JWKS_URI")
        issuer = os.environ.get("FASTMCP_JWT_ISSUER")

        if not all([jwks_uri, issuer]):
            raise RuntimeError(
                "JWT verification requires FASTMCP_JWT_JWKS_URI and FASTMCP_JWT_ISSUER"
            )

        return JWTVerifier(
            jwks_uri=jwks_uri,
            issuer=issuer,
            audience=os.environ.get("FASTMCP_JWT_AUDIENCE"),
        )

    # Azure AD (Microsoft Entra ID) simplified configuration
    if auth_type_lower == "azure-ad":
        tenant_id = os.environ.get("FASTMCP_AZURE_AD_TENANT_ID")
        client_id = os.environ.get("FASTMCP_AZURE_AD_CLIENT_ID")
        
        if not all([tenant_id, client_id]):
            raise RuntimeError(
                "Azure AD authentication requires FASTMCP_AZURE_AD_TENANT_ID and FASTMCP_AZURE_AD_CLIENT_ID"
            )
            
        # Determine if we should use full OIDC flow or just JWT verification
        # If client_secret and base_url are provided, we use OIDC Proxy
        client_secret = os.environ.get("FASTMCP_AZURE_AD_CLIENT_SECRET")
        base_url = os.environ.get("FASTMCP_AZURE_AD_BASE_URL")
        
        config_url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
        
        if client_secret and base_url:
            OIDCProxy = _import_symbol("fastmcp.server.auth.oidc_proxy", "OIDCProxy")
            return OIDCProxy(
                config_url=config_url,
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
                audience=os.environ.get("FASTMCP_AZURE_AD_AUDIENCE", client_id),
                client_storage=client_storage,
            )
        else:
            JWTVerifier = _import_symbol("fastmcp.server.auth.providers.jwt", "JWTVerifier")
            jwks_uri = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
            issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
            return JWTVerifier(
                jwks_uri=jwks_uri,
                issuer=issuer,
                audience=os.environ.get("FASTMCP_AZURE_AD_AUDIENCE", client_id),
            )
            
    # GitHub OAuth2
    if auth_type_lower == "github":
        GitHubProvider = _import_symbol("fastmcp.server.auth.providers.github", "GitHubProvider")
        
        client_id = os.environ.get("FASTMCP_GITHUB_CLIENT_ID")
        client_secret = os.environ.get("FASTMCP_GITHUB_CLIENT_SECRET")
        if not all([client_id, client_secret]):
            raise RuntimeError(
                "GitHub authentication requires FASTMCP_GITHUB_CLIENT_ID and FASTMCP_GITHUB_CLIENT_SECRET"
            )

        # Default to public GitHub URL if the env var is not set
        base_url = os.environ.get("FASTMCP_GITHUB_BASE_URL", "https://github.com")

        return GitHubProvider(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            client_storage=client_storage,
        )

    # Google OAuth2
    if auth_type_lower == "google":
        GoogleProvider = _import_symbol("fastmcp.server.auth.providers.google", "GoogleProvider")
        
        client_id = os.environ.get("FASTMCP_GOOGLE_CLIENT_ID")
        client_secret = os.environ.get("FASTMCP_GOOGLE_CLIENT_SECRET")
        base_url = os.environ.get("FASTMCP_GOOGLE_BASE_URL")
        
        if not all([client_id, client_secret, base_url]):
            raise RuntimeError(
                "Google authentication requires FASTMCP_GOOGLE_CLIENT_ID, "
                "FASTMCP_GOOGLE_CLIENT_SECRET, and FASTMCP_GOOGLE_BASE_URL"
            )
            
        return GoogleProvider(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            client_storage=client_storage,
        )

    # Generic OAuth2 Proxy
    if auth_type_lower == "oauth2":
        OAuthProxy = _import_symbol("fastmcp.server.auth.oauth_proxy", "OAuthProxy")
        JWTVerifier = _import_symbol("fastmcp.server.auth.providers.jwt", "JWTVerifier")
        
        auth_url = os.environ.get("FASTMCP_OAUTH_AUTHORIZE_URL")
        token_url = os.environ.get("FASTMCP_OAUTH_TOKEN_URL")
        client_id = os.environ.get("FASTMCP_OAUTH_CLIENT_ID")
        client_secret = os.environ.get("FASTMCP_OAUTH_CLIENT_SECRET")
        base_url = os.environ.get("FASTMCP_OAUTH_BASE_URL")
        
        # Token verifier details
        jwks_uri = os.environ.get("FASTMCP_OAUTH_JWKS_URI")
        issuer = os.environ.get("FASTMCP_OAUTH_ISSUER")
        
        if not all([auth_url, token_url, client_id, client_secret, base_url, jwks_uri, issuer]):
            raise RuntimeError(
                "Generic OAuth2 requires FASTMCP_OAUTH_AUTHORIZE_URL, FASTMCP_OAUTH_TOKEN_URL, "
                "FASTMCP_OAUTH_CLIENT_ID, FASTMCP_OAUTH_CLIENT_SECRET, FASTMCP_OAUTH_BASE_URL, "
                "FASTMCP_OAUTH_JWKS_URI, and FASTMCP_OAUTH_ISSUER"
            )
            
        token_verifier = JWTVerifier(
            jwks_uri=jwks_uri,
            issuer=issuer,
            audience=os.environ.get("FASTMCP_OAUTH_AUDIENCE")
        )
        
        return OAuthProxy(
            upstream_authorization_endpoint=auth_url,
            upstream_token_endpoint=token_url,
            upstream_client_id=client_id,
            upstream_client_secret=client_secret,
            token_verifier=token_verifier,
            base_url=base_url,
            client_storage=client_storage,
        )
            
def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return int(value)


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_optional_bool(name: str) -> bool | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return None
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_optional_tag_set(name: str) -> set[str] | None:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return None
    parts = [segment.strip() for segment in re.split(r"[;,]", value) if segment.strip()]
    if not parts:
        return None
    return set(parts)


def _resolve_skills_roots() -> list[str]:
    raw = os.environ.get("MCP_SKILLS_DIRS") or os.environ.get("FASTMCP_SKILLS_DIRS")
    if raw:
        candidates = [segment.strip() for segment in re.split(r"[;,]", raw) if segment.strip()]
    else:
        candidates = [os.path.join(os.getcwd(), ".trae", "skills")]

    resolved: list[str] = []
    for candidate in candidates:
        full = os.path.abspath(os.path.expanduser(candidate))
        if os.path.isdir(full) and full not in resolved:
            resolved.append(full)
    return resolved


def _build_skill_index() -> dict[str, str]:
    roots = _resolve_skills_roots()
    if not roots:
        return {}

    grouped: dict[str, list[tuple[str, str]]] = {}
    for root in roots:
        root_alias = os.path.basename(root.rstrip("/\\")) or "skills"
        try:
            entries = sorted(os.scandir(root), key=lambda entry: entry.name.lower())
        except OSError:
            continue

        for entry in entries:
            if not entry.is_dir():
                continue
            skill_md = os.path.join(entry.path, "SKILL.md")
            if not os.path.isfile(skill_md):
                continue
            grouped.setdefault(entry.name, []).append((root_alias, skill_md))

    index: dict[str, str] = {}
    for name, locations in grouped.items():
        if len(locations) == 1:
            index[name] = locations[0][1]
            continue
        for alias, skill_md in locations:
            index[f"{alias}/{name}"] = skill_md
    return index


def _register_skills_resources() -> None:
    enabled = _env_bool("MCP_SKILLS_RESOURCES_ENABLED", False)
    if not enabled:
        return

    @mcp.resource(
        "skills://index",
        name="skills_index",
        description="List available local SKILL.md resources exposed by this server.",
        mime_type="text/markdown",
    )
    def skills_index_resource() -> str:
        skill_map = _build_skill_index()
        roots = _resolve_skills_roots()

        lines = ["# Skills Index", ""]
        if roots:
            lines.append("Configured roots:")
            for root in roots:
                lines.append(f"- `{root}`")
            lines.append("")

        if not skill_map:
            lines.append("No `SKILL.md` files found in configured roots.")
            return "\n".join(lines)

        lines.append("Available skill resources:")
        for skill_id in sorted(skill_map.keys()):
            lines.append(f"- `skills://{skill_id}`")
        return "\n".join(lines)

    @mcp.resource(
        "skills://{skill_id}",
        name="skill_resource",
        description="Read a local skill document (SKILL.md) by id from the skills index.",
        mime_type="text/markdown",
    )
    def skill_resource(skill_id: str) -> str:
        skill_map = _build_skill_index()
        skill_path = skill_map.get(skill_id)
        if not skill_path:
            available = ", ".join(sorted(skill_map.keys())[:20])
            if len(skill_map) > 20:
                available = f"{available}, ..."
            raise ValueError(
                f"Unknown skill id '{skill_id}'. Read 'skills://index' for available ids. "
                f"Visible ids: {available or '(none)'}"
            )

        try:
            with open(skill_path, "r", encoding="utf-8") as handle:
                return handle.read()
        except OSError as exc:
            raise RuntimeError(f"Failed to read skill file '{skill_path}': {exc}") from exc


# Initialize FastMCP
auth_type = os.environ.get("FASTMCP_AUTH_TYPE", "").lower()
tasks_enabled = _env_optional_bool("FASTMCP_TASKS_ENABLED")
if tasks_enabled is None:
    tasks_enabled = _env_optional_bool("MCP_TASKS_ENABLED")
include_tags = _env_optional_tag_set("FASTMCP_INCLUDE_TAGS")
if include_tags is None:
    include_tags = _env_optional_tag_set("MCP_INCLUDE_TAGS")
exclude_tags = _env_optional_tag_set("FASTMCP_EXCLUDE_TAGS")
if exclude_tags is None:
    exclude_tags = _env_optional_tag_set("MCP_EXCLUDE_TAGS")
include_fastmcp_meta = _env_optional_bool("FASTMCP_INCLUDE_META")
if include_fastmcp_meta is None:
    include_fastmcp_meta = _env_optional_bool("MCP_INCLUDE_META")
mcp = FastMCP(
    name=os.environ.get("MCP_SERVER_NAME", "PostgreSQL MCP Server"),
    auth=_get_auth() if auth_type != "apikey" else None,
    tasks=tasks_enabled,
)

if include_tags:
    mcp.enable(tags=include_tags, only=True)
if exclude_tags:
    mcp.disable(tags=exclude_tags)
if include_fastmcp_meta is not None:
    logger.warning(
        "FASTMCP_INCLUDE_META/MCP_INCLUDE_META is not supported by this FastMCP version and will be ignored."
    )

_register_skills_resources()

# Backward-compatibility alias for tests/clients expecting `server` as the FastMCP app object.
server = mcp

# API Key Middleware for simple static token auth
class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        # DEBUG LOG
        # logger.info(f"APIKeyMiddleware checking path: {path}")

        # 1. Compatibility Redirect: Redirect /mcp to /sse
        # Many users might try /mcp based on old docs or assumptions
        # Only redirect GET requests; POST requests might be for stateless JSON-RPC
        if path == "/mcp" and request.method == "GET":
            return RedirectResponse(url="/sse")

        # 2. Enforce API Key on SSE and Message endpoints
        # FastMCP mounts SSE at /sse and messages at /messages
        # We must protect both to prevent unauthorized access
        if path.startswith("/sse") or path.startswith("/messages"):
            auth_type = os.environ.get("FASTMCP_AUTH_TYPE", "").lower()
            logger.info(f"APIKeyMiddleware match. Auth type: {auth_type}")
            if auth_type == "apikey":
                auth_header = request.headers.get("Authorization")
                expected_key = os.environ.get("FASTMCP_API_KEY")
                
                if not expected_key:
                    logger.error("FASTMCP_API_KEY not configured but auth type is apikey")
                    return JSONResponse({"detail": "Server configuration error"}, status_code=500)
                
                # Check query param for SSE as fallback (standard for EventSource in some clients)
                token = None
                if auth_header and auth_header.startswith("Bearer "):
                    token = auth_header.split(" ")[1]
                elif "token" in request.query_params:
                    token = request.query_params["token"]
                elif "api_key" in request.query_params:
                    token = request.query_params["api_key"]
                
                if not token:
                    return JSONResponse({"detail": "Missing Authorization header or token"}, status_code=401)
                
                if token != expected_key:
                    return JSONResponse({"detail": "Invalid API Key"}, status_code=403)
        
        return await call_next(request)

# Browser-friendly middleware to handle direct visits to the SSE endpoint
class BrowserFriendlyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # If visiting the MCP endpoint with a browser (Accept: text/html)
        # and NOT providing the required text/event-stream header
        if request.url.path == "/mcp":
            accept = request.headers.get("accept", "")
            if "text/html" in accept and "text/event-stream" not in accept:
                logger.info(f"Interposing browser-friendly response for {request.url.path}")
                return HTMLResponse(f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>PostgreSQL MCP Server</title>
                        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
                        <style>
                            .bg-gradient {{ background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); }}
                        </style>
                    </head>
                    <body class="bg-gray-50 min-h-screen flex items-center justify-center p-4">
                        <div class="bg-white rounded-2xl shadow-2xl max-w-2xl w-full overflow-hidden">
                            <div class="bg-gradient p-8 text-white">
                                <h1 class="text-4xl font-extrabold mb-2">PostgreSQL MCP Server</h1>
                                <p class="text-blue-100 text-lg opacity-90">Protocol Endpoint Detected</p>
                            </div>
                            
                            <div class="p-8">
                                <div class="flex items-start mb-6 bg-blue-50 p-4 rounded-xl border border-blue-100">
                                    <div class="bg-blue-500 text-white rounded-full p-2 mr-4 mt-1">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="id-circle" />
                                            <circle cx="12" cy="12" r="9" />
                                            <line x1="12" y1="8" x2="12" y2="12" />
                                            <line x1="12" y1="16" x2="12.01" y2="16" />
                                        </svg>
                                    </div>
                                    <div>
                                        <h3 class="text-blue-800 font-bold text-lg mb-1">MCP Protocol Active</h3>
                                        <p class="text-blue-700">
                                            This endpoint (<code class="bg-blue-100 px-1 rounded">/mcp</code>) is reserved for <strong>Model Context Protocol</strong> clients.
                                        </p>
                                    </div>
                                </div>

                                <p class="text-gray-600 mb-8 leading-relaxed">
                                    You are seeing this page because your browser cannot speak the <code>text/event-stream</code> protocol required for MCP. 
                                    To use this server, add this URL to your MCP client configuration (e.g., Claude Desktop).
                                </p>

                                <div class="space-y-4">
                                    <h4 class="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-2">Available Dashboards</h4>
                                    
                                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <a href="/data-model-analysis" class="group flex flex-col p-5 border border-gray-100 rounded-xl hover:border-blue-300 hover:shadow-md transition-all bg-white">
                                            <span class="text-blue-600 font-bold mb-1 group-hover:text-blue-700">Data Model Analysis</span>
                                            <span class="text-sm text-gray-500">View interactive ERD and schema health score.</span>
                                        </a>
                                        
                                        <a href="/sessions-monitor" class="group flex flex-col p-5 border border-gray-100 rounded-xl hover:border-blue-300 hover:shadow-md transition-all bg-white">
                                            <span class="text-blue-600 font-bold mb-1 group-hover:text-blue-700">Sessions Monitor</span>
                                            <span class="text-sm text-gray-500">Track real-time database connections and queries.</span>
                                        </a>
                                    </div>
                                </div>

                                <div class="mt-10 pt-6 border-t border-gray-100 flex justify-between items-center">
                                    <a href="/health" class="text-sm text-gray-400 hover:text-gray-600 transition-colors italic">Server Status: Healthy</a>
                                    <a href="/" class="bg-gray-900 text-white px-6 py-2 rounded-lg font-medium hover:bg-black transition-colors shadow-sm">
                                        View Server Info
                                    </a>
                                </div>
                            </div>
                        </div>
                    </body>
                    </html>
                """)
        return await call_next(request)

# Add the middleware to the FastMCP app
# MOVED to main() to ensure transport-specific app is configured correctly
# mcp.http_app().add_middleware(APIKeyMiddleware)
# mcp.http_app().add_middleware(BrowserFriendlyMiddleware)


def _build_database_url_from_pg_env() -> str | None:
    host = os.environ.get("PGHOST")
    port = os.environ.get("PGPORT", "5432")
    user = os.environ.get("PGUSER")
    password = os.environ.get("PGPASSWORD")
    database = os.environ.get("PGDATABASE")
    if not host or not user or not database:
        return None
    
    # URL-encode user and password to handle special characters
    user_encoded = quote(user)
    password_part = f":{quote(password)}" if password else ""
    
    return f"postgresql://{user_encoded}{password_part}@{host}:{port}/{database}"


DATABASE_URL = os.environ.get("DATABASE_URL") or _build_database_url_from_pg_env()
if not DATABASE_URL:
    raise RuntimeError(
        "Missing DATABASE_URL or PGHOST/PGUSER/PGDATABASE environment variables"
    )

# Capture original connection details before any SSH tunneling modification
# This ensures we report the correct target server info to the user
try:
    _parsed_initial = urlparse(DATABASE_URL)
    ORIGINAL_DB_HOST = _parsed_initial.hostname
    ORIGINAL_DB_PORT = _parsed_initial.port or 5432
    ORIGINAL_DB_NAME = _parsed_initial.path.lstrip('/')
except Exception:
    ORIGINAL_DB_HOST = None
    ORIGINAL_DB_PORT = None
    ORIGINAL_DB_NAME = None

if os.environ.get("MCP_ALLOW_WRITE") is None:
    raise RuntimeError("MCP_ALLOW_WRITE environment variable is required (e.g. 'true' or 'false')")

ALLOW_WRITE = _env_bool("MCP_ALLOW_WRITE", False)
CONFIRM_WRITE = _env_bool("MCP_CONFIRM_WRITE", False)
TRANSPORT = os.environ.get("MCP_TRANSPORT", "http").lower()
AUTH_TYPE = os.environ.get("FASTMCP_AUTH_TYPE")

# Security Mechanisms for Write Mode
if ALLOW_WRITE:
    # Mechanism 1: Explicit Confirmation Latch (Prevents accidental enablement)
    if not CONFIRM_WRITE:
        raise RuntimeError(
            "Security Check Failed: Write mode enabled (MCP_ALLOW_WRITE=true) "
            "but missing confirmation. You must also set MCP_CONFIRM_WRITE=true."
        )

    # Mechanism 2: Transport Security / Auth Enforcement (Prevents insecure exposure)
    # If running over HTTP, we MUST have some form of authentication configured.
    if TRANSPORT == "http" and not AUTH_TYPE:
        raise RuntimeError(
            "Security Check Failed: Write mode enabled over HTTP without authentication. "
            "You must configure FASTMCP_AUTH_TYPE (e.g., 'azure-ad', 'oidc', 'jwt') "
            "or use stdio transport for local access."
        )

# Block 'enterprisedb' user as requested
# Parse the DATABASE_URL to check the username
try:
    _parsed_url = urlparse(DATABASE_URL)
    if _parsed_url.username == 'enterprisedb':
        raise RuntimeError(
            "Security Violation: The 'enterprisedb' user is explicitly disallowed from running this MCP server."
        )
except Exception as e:
    # If parsing fails, we assume it's safe or handle it elsewhere, but for this specific check:
    if "enterprisedb" in DATABASE_URL:
         raise RuntimeError(
            "Security Violation: The 'enterprisedb' user is explicitly disallowed from running this MCP server."
        )

DEFAULT_MAX_ROWS = _env_int("MCP_MAX_ROWS", 500)
POOL_MIN_SIZE = _env_int("MCP_POOL_MIN_SIZE", 1)
POOL_MAX_SIZE = _env_int("MCP_POOL_MAX_SIZE", 20)
POOL_TIMEOUT = float(os.environ.get("MCP_POOL_TIMEOUT", "60.0"))
POOL_MAX_WAITING = _env_int("MCP_POOL_MAX_WAITING", 20)
STATEMENT_TIMEOUT_MS = _env_int("MCP_STATEMENT_TIMEOUT_MS", 120000) # 120s default
RATE_LIMIT_ENABLED = _env_bool("MCP_RATE_LIMIT_ENABLED", True)
RATE_LIMIT_PER_MINUTE = _env_int("MCP_RATE_LIMIT_PER_MINUTE", 600)
BREAKER_TRIP_REJECTIONS = _env_int("MCP_BREAKER_TRIP_REJECTIONS", 20)
BREAKER_OPEN_SECONDS = float(os.environ.get("MCP_BREAKER_OPEN_SECONDS", "30"))

ENFORCE_TABLE_SCOPE = _env_bool("MCP_ENFORCE_TABLE_SCOPE", False)
ALLOWED_TABLES_RAW = os.environ.get("MCP_ALLOWED_TABLES", "")

AUDIT_LOG_FILE = os.environ.get("MCP_AUDIT_LOG_FILE", "mcp_audit.log")
AUDIT_LOG_SQL_TEXT = _env_bool("MCP_AUDIT_LOG_SQL_TEXT", False)
AUDIT_REQUIRE_PROMPT = _env_bool("MCP_AUDIT_REQUIRE_PROMPT", False)
AUDIT_LOG_REQUIRED = _env_bool("MCP_AUDIT_LOG_REQUIRED", False)


# SSH Tunnel Configuration
SSH_HOST = os.environ.get("SSH_HOST")
SSH_USER = os.environ.get("SSH_USER")
SSH_PASSWORD = os.environ.get("SSH_PASSWORD")
SSH_PKEY = os.environ.get("SSH_PKEY")
SSH_PORT = _env_int("SSH_PORT", 22)

# Global reference to keep tunnel alive
_ssh_tunnel = None

if SSH_HOST and SSH_USER:
    logger.info(f"Configuring SSH tunnel to {SSH_USER}@{SSH_HOST}:{SSH_PORT}...")
    
    # Parse destination from DATABASE_URL
    # DATABASE_URL is guaranteed to be set by previous checks
    try:
        parsed_db_url = urlparse(DATABASE_URL)
        
        remote_bind_host = parsed_db_url.hostname
        remote_bind_port = parsed_db_url.port or 5432
        
        if not remote_bind_host:
            raise RuntimeError(
                "SSH requested but DATABASE_URL lacks a host. Provide a URL like postgresql://user:pass@host:5432/db"
            )
    
        # Read allow_agent configuration from environment variable
        allow_ssh_agent = os.environ.get("ALLOW_SSH_AGENT", "false").lower() in ("true", "1", "yes", "on")
        
        ssh_args = {
            "ssh_address_or_host": (SSH_HOST, SSH_PORT),
            "ssh_username": SSH_USER,
            "remote_bind_address": (remote_bind_host, remote_bind_port),
            "allow_agent": allow_ssh_agent, # Configurable via ALLOW_SSH_AGENT environment variable
        }
        
        if SSH_PASSWORD:
            ssh_args["ssh_password"] = SSH_PASSWORD
        if SSH_PKEY:
            ssh_args["ssh_pkey"] = SSH_PKEY
            
        logger.info(f"Starting SSH tunnel to remote bind: {remote_bind_host}:{remote_bind_port}")
        _ssh_tunnel = SSHTunnelForwarder(**ssh_args)
        _ssh_tunnel.start()
        
        logger.info(f"SSH tunnel established. Local bind port: {_ssh_tunnel.local_bind_port}")
        
        # Reconstruct DATABASE_URL with local port using robust split/unsplit to preserve components
        parts = urlsplit(DATABASE_URL)
        userinfo = ''
        if parts.username:
            userinfo = parts.username
            if parts.password:
                userinfo += f":{quote(parts.password)}"
            userinfo += '@'
        new_netloc = f"{userinfo}127.0.0.1:{_ssh_tunnel.local_bind_port}"
        DATABASE_URL = urlunsplit((parts.scheme, new_netloc, parts.path, parts.query, parts.fragment))
        
        logger.info("Updated DATABASE_URL to use SSH tunnel.")
        
    except Exception as e:
        logger.error(f"Failed to establish SSH tunnel: {e}")
        # We raise here because if the user asked for SSH and it fails, we shouldn't proceed
        # attempting to connect directly (which would likely timeout or fail anyway)
        raise RuntimeError(f"SSH Tunnel setup failed: {e}") from e


def _cleanup_ssh_tunnel():
    """Cleanup function to stop SSH tunnel on process exit."""
    global _ssh_tunnel
    if _ssh_tunnel is not None:
        try:
            logger.info("Closing SSH tunnel...")
            _ssh_tunnel.stop()
            _ssh_tunnel = None
            logger.info("SSH tunnel closed.")
        except Exception as e:
            logger.error(f"Error closing SSH tunnel: {e}")


# Register cleanup handlers
atexit.register(_cleanup_ssh_tunnel)

# Register signal handlers for graceful shutdown
def _signal_handler(signum, frame):
    logger.info(f"Received signal {signum}, cleaning up...")
    _cleanup_ssh_tunnel()
    sys.exit(0)

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


pool = ConnectionPool(
    conninfo=DATABASE_URL,
    min_size=POOL_MIN_SIZE,
    max_size=POOL_MAX_SIZE,
    timeout=POOL_TIMEOUT,
    max_waiting=POOL_MAX_WAITING,
    open=True,
    kwargs={"row_factory": dict_row, "options": "-c DateStyle=ISO,MDY"},
)


def _parse_allowed_tables(raw_value: str) -> set[str]:
    items = [item.strip().lower() for item in raw_value.split(",") if item.strip()]
    malformed = [item for item in items if "." not in item]
    if malformed:
        raise RuntimeError(
            "Invalid MCP_ALLOWED_TABLES entries (must be schema.table): "
            + ", ".join(malformed[:10])
        )
    return set(items)


def _validate_table_scope() -> None:
    if not ENFORCE_TABLE_SCOPE:
        logger.warning(
            "Least-privilege table scope enforcement is DISABLED "
            "(MCP_ENFORCE_TABLE_SCOPE=false)."
        )
        return

    allowed_tables = _parse_allowed_tables(ALLOWED_TABLES_RAW)
    logger.info(
        "Least-privilege table scope enforcement is ENABLED "
        f"(allowed_tables_configured={len(allowed_tables)})."
    )
    if not allowed_tables:
        raise RuntimeError(
            "MCP_ENFORCE_TABLE_SCOPE=true requires MCP_ALLOWED_TABLES (comma-separated schema.table list)."
        )

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                  n.nspname as schema_name,
                  c.relname as table_name,
                  has_table_privilege(current_user, c.oid, 'SELECT') as can_select,
                  has_table_privilege(current_user, c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') as can_write
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where c.relkind in ('r', 'p', 'v', 'm', 'f')
                  and n.nspname not in ('pg_catalog', 'information_schema')
                order by n.nspname, c.relname
                """
            )
            rows = cur.fetchall()

    selectable = {
        f"{row['schema_name']}.{row['table_name']}".lower()
        for row in rows
        if row.get("can_select")
    }
    writable = {
        f"{row['schema_name']}.{row['table_name']}".lower()
        for row in rows
        if row.get("can_write")
    }

    unauthorized_select = sorted(selectable - allowed_tables)
    missing_select = sorted(allowed_tables - selectable)

    if unauthorized_select:
        raise RuntimeError(
            "Credential scope violation: DB user can SELECT outside MCP_ALLOWED_TABLES. "
            f"Examples: {', '.join(unauthorized_select[:10])}"
        )

    if missing_select:
        raise RuntimeError(
            "Credential scope violation: DB user is missing SELECT on allowed tables. "
            f"Examples: {', '.join(missing_select[:10])}"
        )

    if not ALLOW_WRITE and writable:
        raise RuntimeError(
            "Credential scope violation: read-only MCP has write-capable DB credentials. "
            f"Examples: {', '.join(sorted(writable)[:10])}"
        )

    logger.info(
        f"Credential scope verified. allowed_tables={len(allowed_tables)} selectable={len(selectable)}"
    )


_validate_table_scope()


class _QueryRateCircuitBreaker:
    def __init__(self, rate_per_minute: int, trip_rejections: int, open_seconds: float):
        self.rate_per_minute = max(1, rate_per_minute)
        self.trip_rejections = max(1, trip_rejections)
        self.open_seconds = max(1.0, open_seconds)
        self.capacity = float(self.rate_per_minute)
        self.tokens = float(self.rate_per_minute)
        self.refill_per_second = self.rate_per_minute / 60.0
        self.last_refill = time.monotonic()
        self.open_until = 0.0
        self.rejections = 0
        self.lock = threading.Lock()

    def acquire(self) -> None:
        now = time.monotonic()
        with self.lock:
            if now < self.open_until:
                remaining = max(1, int(self.open_until - now))
                raise RuntimeError(
                    f"Circuit breaker open due to excessive query volume. Retry in ~{remaining}s."
                )

            elapsed = max(0.0, now - self.last_refill)
            self.last_refill = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)

            if self.tokens >= 1.0:
                self.tokens -= 1.0
                self.rejections = 0
                return

            self.rejections += 1
            if self.rejections >= self.trip_rejections:
                self.open_until = now + self.open_seconds
                self.rejections = 0
                logger.error(
                    "Opening query circuit breaker: query rate exceeded threshold. "
                    f"open_seconds={self.open_seconds} rate_per_minute={self.rate_per_minute}"
                )
                raise RuntimeError(
                    f"Rate limit exceeded. Circuit breaker opened for {int(self.open_seconds)} seconds."
                )

            raise RuntimeError(
                f"Rate limit exceeded ({self.rate_per_minute}/minute). Throttling query execution."
            )


_query_circuit_breaker = (
    _QueryRateCircuitBreaker(RATE_LIMIT_PER_MINUTE, BREAKER_TRIP_REJECTIONS, BREAKER_OPEN_SECONDS)
    if RATE_LIMIT_ENABLED
    else None
)


def _enforce_query_rate_limit() -> None:
    if _query_circuit_breaker is None:
        return
    _query_circuit_breaker.acquire()


_audit_log_lock = threading.Lock()


def _write_audit_event(
    *,
    tool_name: str,
    sql_text: str,
    source_prompt: str | None,
    params_json: str | None = None,
) -> None:
    if AUDIT_REQUIRE_PROMPT and not source_prompt:
        raise ValueError(
            "Audit policy requires source_prompt for query tools. Provide source_prompt or set MCP_AUDIT_REQUIRE_PROMPT=false."
        )

    event: dict[str, Any] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event_type": "query_audit",
        "tool": tool_name,
        "sql_len": len(sql_text),
        "sql_sha256": hashlib.sha256(sql_text.encode("utf-8")).hexdigest(),
        "source_prompt": source_prompt,
        "source_prompt_sha256": hashlib.sha256(source_prompt.encode("utf-8")).hexdigest() if source_prompt else None,
        "params_sha256": hashlib.sha256(params_json.encode("utf-8")).hexdigest() if params_json else None,
    }
    if AUDIT_LOG_SQL_TEXT:
        event["sql"] = sql_text

    with _audit_log_lock:
        try:
            with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except OSError as exc:
            if AUDIT_LOG_REQUIRED:
                logger.error(
                    f"Fatal audit log write failure for '{AUDIT_LOG_FILE}': {exc}"
                )
                raise RuntimeError(
                    f"Audit log write failed for '{AUDIT_LOG_FILE}': {exc}"
                ) from exc
            logger.warning(
                f"Non-fatal audit log write failure for '{AUDIT_LOG_FILE}': {exc}"
            )
            return
        except Exception as exc:
            if AUDIT_LOG_REQUIRED:
                logger.error(
                    f"Fatal unexpected audit log write failure for '{AUDIT_LOG_FILE}': {exc}"
                )
                raise RuntimeError(
                    f"Unexpected audit log write failure for '{AUDIT_LOG_FILE}': {exc}"
                ) from exc
            logger.warning(
                f"Non-fatal unexpected audit log write failure for '{AUDIT_LOG_FILE}': {exc}"
            )
            return


_SINGLE_QUOTED = re.compile(r"'(?:''|[^'])*'")
_DOUBLE_QUOTED = re.compile(r'"(?:[^"]|"")*"')
_LINE_COMMENT = re.compile(r"--[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*[\s\S]*?\*/")
_DOLLAR_QUOTED = re.compile(r"\$[A-Za-z0-9_]*\$[\s\S]*?\$[A-Za-z0-9_]*\$")


def _strip_sql_noise(sql: str) -> str:
    s = _BLOCK_COMMENT.sub(" ", sql)
    s = _LINE_COMMENT.sub(" ", s)
    s = _DOLLAR_QUOTED.sub(" ", s)
    s = _SINGLE_QUOTED.sub(" ", s)
    s = _DOUBLE_QUOTED.sub(" ", s)
    return s


_WRITE_KEYWORDS = {
    "insert",
    "update",
    "delete",
    "merge",
    "create",
    "alter",
    "drop",
    "truncate",
    "grant",
    "revoke",
    "comment",
    "vacuum",
    "analyze",
    "reindex",
    "cluster",
    "refresh",
    "copy",
    "call",
    "do",
    "execute",
    "reset",
    "lock",
    "commit",
    "rollback",
    "begin",
    "savepoint",
    "release",
}

_READONLY_START = {"select", "with", "show", "explain", "set"}


def _is_sql_readonly(sql: str) -> bool:
    cleaned = _strip_sql_noise(sql).strip().lower()
    if not cleaned:
        return False
    # Check if first word is a known read-only starting keyword
    first = cleaned.split(None, 1)[0]
    if first not in _READONLY_START:
        return False
    # Ensure no write keywords exist anywhere in the tokens
    tokens = re.findall(r"[a-zA-Z_]+", cleaned)
    return not any(t in _WRITE_KEYWORDS for t in tokens)


def _require_readonly(sql: str) -> None:
    if ALLOW_WRITE:
        return
    if not _is_sql_readonly(sql):
        logger.warning(f"BLOCKED write attempt in read-only mode: {sql[:200]}...")
        raise ValueError(
            "Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable."
        )


def _fetch_limited(cur, max_rows: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    remaining = max_rows
    while remaining > 0:
        batch = cur.fetchmany(min(remaining, 200))
        if not batch:
            break
        rows.extend(batch)
        remaining -= len(batch)
    return rows


def _trim_list(items: list[Any], max_items: int | None) -> tuple[list[Any], bool]:
    if max_items is None or max_items < 0 or len(items) <= max_items:
        return items, False
    return items[:max_items], True


def _build_response_envelope(
    *,
    tool: str,
    payload: Any,
    summary: dict[str, Any] | None = None,
    truncated: bool = False,
    hints_for_next_call: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "tool": tool,
        "summary": summary or {},
        "truncated": truncated,
        "hints_for_next_call": hints_for_next_call or [],
        "data": payload,
    }


def _rollback_cursor_connection(cur) -> None:
    conn = getattr(cur, "connection", None)
    if conn is None:
        return
    try:
        conn.rollback()
    except Exception as rollback_error:
        logger.debug(f"Rollback after query error failed: {rollback_error}")


def _execute_safe(cur, sql: Any, params: Any = None) -> None:
    """Executes a query with session-level timeouts and sanitized error handling."""
    try:
        _enforce_query_rate_limit()
        if logger.isEnabledFor(logging.DEBUG):
            # Log query (truncated if too long for sanity)
            query_str = str(sql)
            if len(query_str) > 1000:
                query_str = query_str[:1000] + "..."
            logger.debug(f"Executing SQL: {query_str} | Params: {params}")

        # Set session-level timeout for this specific query execution
        cur.execute(f"SET statement_timeout = {STATEMENT_TIMEOUT_MS}")
        cur.execute(sql, params)
    except PsycopgError as e:
        _rollback_cursor_connection(cur)
        logger.error(f"Database error: {str(e)}")
        # Sanitize error message to prevent leaking schema details
        # We only return the main error message if it's safe or a generic one
        if "timeout" in str(e).lower():
            raise RuntimeError("Query execution timed out.") from e
        raise RuntimeError(f"Database operation failed: {e.diag.message_primary if hasattr(e, 'diag') and e.diag else 'Internal error'}") from e
    except Exception as e:
        _rollback_cursor_connection(cur)
        logger.exception("Unexpected error during query execution")
        raise RuntimeError("An unexpected error occurred while processing the query.") from e


def _execute_safe_with_fallback(
    cur,
    primary_sql: Any,
    fallback_sql: Any,
    primary_params: Any = None,
    fallback_params: Any = None,
) -> bool:
    """
    Execute a primary query and fallback query when the primary fails.

    Returns:
        True when the primary query succeeded, False when fallback was used.
    """
    try:
        _execute_safe(cur, primary_sql, primary_params)
        return True
    except RuntimeError as primary_error:
        logger.warning(f"Primary query failed, attempting fallback query: {primary_error}")
        _rollback_cursor_connection(cur)
        _execute_safe(cur, fallback_sql, fallback_params)
        return False


@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


@mcp.custom_route("/", methods=["GET"])
async def root(_request: Request) -> HTMLResponse:
    return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>PostgreSQL MCP Server</title>
            <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
            <style>
                .bg-gradient {{ background: linear-gradient(135deg, #111827 0%, #1f2937 100%); }}
            </style>
        </head>
        <body class="bg-gray-50 min-h-screen font-sans">
            <nav class="bg-gradient text-white p-6 shadow-lg">
                <div class="max-w-5xl mx-auto flex justify-between items-center">
                    <h1 class="text-2xl font-bold tracking-tight">PostgreSQL MCP Server</h1>
                    <span class="bg-green-500 text-white text-xs font-bold px-3 py-1 rounded-full uppercase tracking-widest">Online</span>
                </div>
            </nav>

            <main class="max-w-5xl mx-auto p-8">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
                    <div class="md:col-span-2">
                        <h2 class="text-3xl font-extrabold text-gray-900 mb-4">Server Status & Info</h2>
                        <p class="text-lg text-gray-600 mb-6">
                            This server provides a high-performance <strong>Model Context Protocol (MCP)</strong> interface to your PostgreSQL database.
                        </p>
                        
                        <div class="bg-white p-6 rounded-2xl border border-gray-100 shadow-sm mb-8">
                            <h3 class="text-sm font-bold text-gray-400 uppercase tracking-widest mb-4">Connection Details</h3>
                            <dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-6">
                                <div>
                                    <dt class="text-sm text-gray-500">MCP Protocol Endpoint</dt>
                                    <dd class="text-gray-900 font-mono text-sm bg-gray-50 p-2 rounded mt-1 border border-gray-100">/mcp</dd>
                                </div>
                                <div>
                                    <dt class="text-sm text-gray-500">Health Check</dt>
                                    <dd class="text-gray-900 font-mono text-sm bg-gray-50 p-2 rounded mt-1 border border-gray-100">/health</dd>
                                </div>
                                <div>
                                    <dt class="text-sm text-gray-500">Database Host</dt>
                                    <dd class="text-gray-900 font-medium mt-1">{ORIGINAL_DB_HOST or "N/A"}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm text-gray-500">Database Name</dt>
                                    <dd class="text-gray-900 font-medium mt-1">{ORIGINAL_DB_NAME or "N/A"}</dd>
                                </div>
                            </dl>
                        </div>
                    </div>

                    <div class="space-y-6">
                        <div class="bg-blue-600 p-6 rounded-2xl text-white shadow-xl">
                            <h3 class="font-bold text-xl mb-3 text-white">Interactive Tools</h3>
                            <p class="text-blue-100 text-sm mb-6 opacity-90">Access your database insights through these specialized dashboards.</p>
                            
                            <div class="space-y-3">
                                <a href="/data-model-analysis" class="block w-full text-center bg-white text-blue-700 font-bold py-3 rounded-xl hover:bg-blue-50 transition-colors">
                                    Data Model Analysis
                                </a>
                                <a href="/sessions-monitor" class="block w-full text-center bg-blue-500 text-white border border-blue-400 font-bold py-3 rounded-xl hover:bg-blue-400 transition-colors">
                                    Sessions Monitor
                                </a>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="bg-yellow-50 border-l-4 border-yellow-400 p-6 rounded-r-2xl mb-12">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <svg class="h-6 w-6 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                            </svg>
                        </div>
                        <div class="ml-3">
                            <h3 class="text-sm font-bold text-yellow-800 uppercase tracking-wider">How to connect</h3>
                            <div class="mt-2 text-sm text-yellow-700">
                                <p>To use this server with Claude Desktop, add the following to your configuration:</p>
                                <pre class="mt-2 p-3 bg-white bg-opacity-50 rounded font-mono text-xs overflow-x-auto">"mcpServers": {{
    "postgres": {{
        "command": "docker",
        "args": ["run", "-i", "--rm", "-e", "DATABASE_URL=...", "harryvaldez/mcp-postgres:latest"]
    }}
}}</pre>
                            </div>
                        </div>
                    </div>
                </div>
            </main>

            <footer class="max-w-5xl mx-auto p-8 border-t border-gray-100 text-center text-gray-400 text-sm">
                &copy; {datetime.now().year} MCP PostgreSQL Server &bull; Running on FastMCP
            </footer>
        </body>
        </html>
    """)


@mcp.tool(tags={"public"})
def db_pg96_create_db_user(
    username: str,
    password: str,
    privileges: str = "read",
    database: str | None = None
) -> str:
    """
    Creates a new database user and assigns privileges.

    Args:
        username: The name of the user to create.
        password: The password for the new user.
        privileges: 'read' for SELECT only, 'read-write' for full DML access.
        database: The database to grant access to (default: current database).

    Note:
        ALTER DEFAULT PRIVILEGES commands executed by this function only apply to objects created by the
        role running the MCP server. Objects created by other roles will not automatically grant privileges
        to the new user unless explicitly configured otherwise.
    """
    if not ALLOW_WRITE:
        raise ValueError("Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable user creation.")

    if privileges not in ["read", "read-write"]:
        raise ValueError("privileges must be either 'read' or 'read-write'")

    # Basic input validation for username to prevent SQL injection in identifiers
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", username):
        raise ValueError("Invalid username format. Use only alphanumeric characters and underscores, starting with a letter.")

    # We use a separate connection if the target database is different from the current one
    # to ensure GRANT commands on tables work correctly (they are database-local).
    # However, for simplicity and protocol consistency, we use the existing pool
    # and warn if the grants might be schema-specific to the current DB.
    with pool.connection() as conn:
        with conn.cursor() as cur:
            # Resolve database if not provided
            cur.execute("SELECT current_database()")
            current_db_row = cur.fetchone() or {"current_database": None}
            current_db = current_db_row["current_database"]
            if current_db is None:
                raise RuntimeError("Unable to resolve current_database() before creating user")
            
            target_db = database if database is not None else current_db
            is_same_db = target_db == current_db

            # 1. Create the user (Global operation)
            logger.info(f"Creating database user: {username}")
            _execute_safe(
                cur,
                sql.SQL("CREATE ROLE {} WITH LOGIN PASSWORD {}").format(
                    sql.Identifier(username),
                    sql.Literal(password),
                ),
            )

            # 2. Grant connection to database
            _execute_safe(
                cur,
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(target_db),
                    sql.Identifier(username),
                ),
            )

            # 3. Grant schema/table permissions (Only if connected to the target DB)
            if is_same_db:
                # Note: These typically apply to the database the session is currently connected to.
                if privileges == "read":
                    _execute_safe(
                        cur,
                        sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(username)),
                    )
                    _execute_safe(
                        cur,
                        sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA public TO {}").format(sql.Identifier(username)),
                    )
                    # Optionally grant ro_role if it exists
                    cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'ro_role'")
                    if cur.fetchone():
                        _execute_safe(
                            cur,
                            sql.SQL("GRANT ro_role to {}").format(sql.Identifier(username)),
                        )
                    # Note: This ALTER DEFAULT PRIVILEGES only applies to objects created by the current role.
                    # To apply to other creators, one must execute ALTER DEFAULT PRIVILEGES FOR ROLE <creator> ...
                    _execute_safe(
                        cur,
                        sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {}").format(
                            sql.Identifier(username)
                        ),
                    )
                else:
                    _execute_safe(
                        cur,
                        sql.SQL("GRANT ALL PRIVILEGES ON DATABASE {} TO {}").format(
                            sql.Identifier(target_db),
                            sql.Identifier(username),
                        ),
                    )
                    _execute_safe(
                        cur,
                        sql.SQL("GRANT ALL PRIVILEGES ON SCHEMA public TO {}").format(sql.Identifier(username)),
                    )
                    _execute_safe(
                        cur,
                        sql.SQL("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO {}").format(sql.Identifier(username)),
                    )
                    # Note: This ALTER DEFAULT PRIVILEGES only applies to objects created by the current role.
                    # To apply to other creators, one must execute ALTER DEFAULT PRIVILEGES FOR ROLE <creator> ...
                    _execute_safe(
                        cur,
                        sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO {}").format(
                            sql.Identifier(username)
                        ),
                    )
                
                return f"User '{username}' created successfully with {privileges} privileges on database '{target_db}'."
            else:
                return (
                    f"User '{username}' created and granted CONNECT on database '{target_db}'. "
                    f"WARNING: Schema/Table privileges were NOT applied because the server is connected to '{current_db}'. "
                    f"To apply table privileges, please connect to '{target_db}'."
                )


@mcp.tool(tags={"public"})
def db_pg96_drop_db_user(username: str) -> str:
    """
    Drops a database user (role).

    Args:
        username: The name of the user to drop.

    Returns:
        A message indicating success.
    """
    if not ALLOW_WRITE:
        raise ValueError("Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable user deletion.")

    # Basic input validation for username
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", username):
        raise ValueError("Invalid username format.")

    with pool.connection() as conn:
        with conn.cursor() as cur:
            logger.info(f"Dropping database user: {username}")
            _execute_safe(
                cur,
                sql.SQL("DROP OWNED BY {}").format(sql.Identifier(username)),
            )
            _execute_safe(
                cur,
                sql.SQL("DROP ROLE {}").format(sql.Identifier(username)),
            )
            return f"User '{username}' dropped successfully."


@mcp.tool(tags={"public"})
def db_pg96_alter_object(
    object_type: str,
    object_name: str,
    operation: str,
    schema: str | None = None,
    owner: str | None = None,
    parameters: dict[str, Any] | None = None
) -> str:
    """
    Executes ALTER DDL statements for database objects.
    
    Args:
        object_type: One of: database, schema, table, view, index, function, procedure, trigger, server.
        object_name: Name of the object.
        operation: One of: rename, owner_to, set_schema, add_column, rename_column, alter_column, drop_column, rename_constraint, attach_partition, detach_partition.
        schema: Schema name (required for schema-scoped objects).
        owner: New owner name (for 'owner_to' operation).
        parameters: Additional parameters for specific operations:
            - new_name: for 'rename' (target name)
            - new_schema: for 'set_schema'
            - column_name: for column operations
            - new_column_name: for 'rename_column'
            - data_type: for 'add_column', 'alter_column'
            - constraint_name: for 'rename_constraint'
            - new_constraint_name: for 'rename_constraint'
            - partition_name: for partition operations
            - bounds: for 'attach_partition' (e.g., "FOR VALUES IN (1)")
            - table_name: for 'trigger' operations (the table the trigger is on)
            - function_args: for 'function'/'procedure' (e.g., "integer, text") to identify specific overload
            - not_null: bool, for 'alter_column'
            - default: any, for 'alter_column' (SET DEFAULT)
            - drop_default: bool, for 'alter_column'
            - constraints: str, for 'add_column' (e.g. "NOT NULL DEFAULT 0")
    """
    if not ALLOW_WRITE:
        raise ValueError("Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable.")

    params = parameters or {}
    op = operation.lower()
    obj_type = object_type.lower()
    
    # Normalize object types
    if obj_type == 'procedure':
        obj_type = 'function' # PG 9.6 treats procedures as functions
    
    object_tokens = {
        "database": sql.SQL("DATABASE"),
        "schema": sql.SQL("SCHEMA"),
        "table": sql.SQL("TABLE"),
        "view": sql.SQL("VIEW"),
        "index": sql.SQL("INDEX"),
        "function": sql.SQL("FUNCTION"),
        "trigger": sql.SQL("TRIGGER"),
        "server": sql.SQL("SERVER"),
    }

    with pool.connection() as conn:
        with conn.cursor() as cur:
            query = None
            object_token = object_tokens.get(obj_type)
            
            # Base object identifier construction
            if schema and obj_type not in ('database', 'server', 'schema'):
                # For functions, we might need args signature
                if obj_type == 'function' and params.get('function_args'):
                     # Format: "schema"."name"(args) - args are raw SQL
                     obj_id = sql.SQL("{}.{}({})").format(
                         sql.Identifier(schema),
                         sql.Identifier(object_name),
                         sql.SQL(params['function_args'])
                     )
                else:
                    obj_id = sql.Identifier(schema, object_name)
            else:
                if obj_type == 'function' and params.get('function_args'):
                     obj_id = sql.SQL("{}({})").format(
                         sql.Identifier(object_name),
                         sql.SQL(params['function_args'])
                     )
                else:
                    obj_id = sql.Identifier(object_name)

            # --- Universal Operations ---
            
            if op == 'rename':
                new_name = params.get('new_name')
                if not new_name:
                    raise ValueError("Parameter 'new_name' required for rename.")
                
                # Triggers are special: ALTER TRIGGER name ON table RENAME TO new_name
                if obj_type == 'trigger':
                    table_name = params.get('table_name')
                    if not table_name:
                        raise ValueError("Parameter 'table_name' required for altering triggers.")
                    query = sql.SQL("ALTER TRIGGER {} ON {} RENAME TO {}").format(
                        sql.Identifier(object_name),
                        sql.Identifier(schema, table_name) if schema else sql.Identifier(table_name),
                        sql.Identifier(new_name)
                    )
                else:
                    if object_token is None:
                        raise ValueError(f"Unsupported object_type for rename: {obj_type}")
                    query = sql.SQL("ALTER {} {} RENAME TO {}").format(
                        object_token,
                        obj_id,
                        sql.Identifier(new_name)
                    )

            elif op == 'owner_to':
                if not owner:
                    raise ValueError("Parameter 'owner' required for owner_to operation.")
                
                if obj_type == 'trigger':
                    raise ValueError("Triggers do not have owners (tables do).")
                if object_token is None:
                    raise ValueError(f"Unsupported object_type for owner_to: {obj_type}")
                
                query = sql.SQL("ALTER {} {} OWNER TO {}").format(
                    object_token,
                    obj_id,
                    sql.Identifier(owner)
                )

            elif op == 'set_schema':
                new_schema = params.get('new_schema')
                if not new_schema:
                    raise ValueError("Parameter 'new_schema' required for set_schema.")
                
                if obj_type in ('database', 'server', 'schema'):
                    raise ValueError(f"Cannot set schema for {obj_type}.")
                if object_token is None:
                    raise ValueError(f"Unsupported object_type for set_schema: {obj_type}")
                
                query = sql.SQL("ALTER {} {} SET SCHEMA {}").format(
                    object_token,
                    obj_id,
                    sql.Identifier(new_schema)
                )

            # --- Table Specific Operations ---
            
            elif obj_type == 'table':
                if op == 'add_column':
                    col_name = params.get('column_name')
                    dtype = params.get('data_type')
                    if not col_name or not dtype:
                        raise ValueError("Parameters 'column_name' and 'data_type' required.")
                    
                    constraints = params.get('constraints', '')
                    
                    query = sql.SQL("ALTER TABLE {} ADD COLUMN {} {} {}").format(
                        obj_id,
                        sql.Identifier(col_name),
                        sql.SQL(dtype),
                        sql.SQL(constraints)
                    )
                    
                elif op == 'rename_column':
                    col_name = params.get('column_name')
                    new_col_name = params.get('new_column_name')
                    if not col_name or not new_col_name:
                        raise ValueError("Parameters 'column_name' and 'new_column_name' required.")
                        
                    query = sql.SQL("ALTER TABLE {} RENAME COLUMN {} TO {}").format(
                        obj_id,
                        sql.Identifier(col_name),
                        sql.Identifier(new_col_name)
                    )
                    
                elif op == 'drop_column':
                    col_name = params.get('column_name')
                    if not col_name:
                        raise ValueError("Parameter 'column_name' required.")
                        
                    query = sql.SQL("ALTER TABLE {} DROP COLUMN {}").format(
                        obj_id,
                        sql.Identifier(col_name)
                    )

                elif op == 'alter_column':
                    col_name = params.get('column_name')
                    if not col_name:
                        raise ValueError("Parameter 'column_name' required.")
                    
                    sub_ops = []
                    if params.get('data_type'):
                        sub_ops.append(sql.SQL("TYPE {}").format(sql.SQL(params['data_type'])))
                    
                    if params.get('not_null') is True:
                        sub_ops.append(sql.SQL("SET NOT NULL"))
                    elif params.get('not_null') is False:
                        sub_ops.append(sql.SQL("DROP NOT NULL"))
                        
                    if params.get('default'):
                        sub_ops.append(sql.SQL("SET DEFAULT {}").format(sql.Literal(params['default'])))
                    elif params.get('drop_default'):
                        sub_ops.append(sql.SQL("DROP DEFAULT"))

                    if not sub_ops:
                         raise ValueError("No alteration specified for column (data_type, not_null, default).")
                    
                    actions = []
                    for action in sub_ops:
                        actions.append(sql.SQL("ALTER COLUMN {} {}").format(sql.Identifier(col_name), action))
                    
                    query = sql.SQL("ALTER TABLE {} {}").format(
                        obj_id,
                        sql.SQL(", ").join(actions)
                    )

                elif op == 'rename_constraint':
                    con_name = params.get('constraint_name')
                    new_con_name = params.get('new_constraint_name')
                    if not con_name or not new_con_name:
                        raise ValueError("Parameters 'constraint_name' and 'new_constraint_name' required.")
                        
                    query = sql.SQL("ALTER TABLE {} RENAME CONSTRAINT {} TO {}").format(
                        obj_id,
                        sql.Identifier(con_name),
                        sql.Identifier(new_con_name)
                    )
                    
                elif op == 'attach_partition':
                    part_name = params.get('partition_name')
                    bounds = params.get('bounds')
                    if not part_name or not bounds:
                         raise ValueError("Parameters 'partition_name' and 'bounds' required.")
                    
                    if '.' in part_name:
                        s, n = part_name.split('.', 1)
                        part_id = sql.Identifier(s, n)
                    else:
                        part_id = sql.Identifier(part_name)

                    query = sql.SQL("ALTER TABLE {} ATTACH PARTITION {} {}").format(
                        obj_id,
                        part_id,
                        sql.SQL(bounds)
                    )

                elif op == 'detach_partition':
                    part_name = params.get('partition_name')
                    if not part_name:
                         raise ValueError("Parameter 'partition_name' required.")
                    
                    if '.' in part_name:
                        s, n = part_name.split('.', 1)
                        part_id = sql.Identifier(s, n)
                    else:
                        part_id = sql.Identifier(part_name)
                        
                    query = sql.SQL("ALTER TABLE {} DETACH PARTITION {}").format(
                        obj_id,
                        part_id
                    )

            if not query:
                raise ValueError(f"Operation '{op}' not supported for object type '{obj_type}' or parameters missing.")

            logger.info(f"Executing ALTER: {query.as_string(conn)}")
            _execute_safe(cur, query)
            
            return f"Operation '{op}' on {obj_type} '{object_name}' completed successfully."


@mcp.tool(tags={"public"})
def db_pg96_create_object(
    object_type: str,
    object_name: str,
    schema: str | None = None,
    owner: str | None = None,
    parameters: dict[str, Any] | None = None
) -> str:
    """
    Executes CREATE DDL statements for database objects.
    
    Args:
        object_type: One of: database, schema, table, view, index, function, procedure, trigger, server.
        object_name: Name of the object.
        schema: Schema name (required for schema-scoped objects like table, view, index, function, trigger).
        owner: Optional owner of the object (AUTHORIZATION clause).
        parameters: Additional parameters for specific objects:
            - columns: list of dicts for 'table' (e.g. [{'name': 'id', 'type': 'serial', 'constraints': 'PRIMARY KEY'}])
            - query: str for 'view' (AS query)
            - table_name: str for 'index' or 'trigger'
            - index_columns: list of str for 'index' (column names or expressions)
            - unique: bool for 'index'
            - method: str for 'index' (e.g. 'btree', 'gin')
            - function_args: str for 'function'/'procedure' (e.g. "a integer, b text")
            - return_type: str for 'function' (e.g. "integer")
            - language: str for 'function' (e.g. "plpgsql")
            - body: str for 'function' body
            - replace: bool (CREATE OR REPLACE)
            - fdw_name: str for 'server'
            - options: str/dict for 'server' options
            - event: str for 'trigger' (e.g. "BEFORE INSERT")
            - function_name: str for 'trigger' execution
    """
    if not ALLOW_WRITE:
        raise ValueError("Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable.")

    params = parameters or {}
    obj_type = object_type.lower()
    
    # Normalize object types
    if obj_type == 'procedure':
        obj_type = 'function' # PG 9.6
        
    with pool.connection() as conn:
        with conn.cursor() as cur:
            query = None
            
            # --- Database ---
            if obj_type == 'database':
                # CREATE DATABASE name [OWNER user]
                parts = [sql.SQL("CREATE DATABASE"), sql.Identifier(object_name)]
                if owner:
                    parts.append(sql.SQL("OWNER"))
                    parts.append(sql.Identifier(owner))
                query = sql.SQL(" ").join(parts)
            
            # --- Schema ---
            elif obj_type == 'schema':
                # CREATE SCHEMA name [AUTHORIZATION user]
                parts = [sql.SQL("CREATE SCHEMA"), sql.Identifier(object_name)]
                if owner:
                    parts.append(sql.SQL("AUTHORIZATION"))
                    parts.append(sql.Identifier(owner))
                query = sql.SQL(" ").join(parts)

            # --- Table ---
            elif obj_type == 'table':
                if not schema:
                    raise ValueError("Parameter 'schema' required for creating table.")
                
                cols = params.get('columns', [])
                if not cols:
                    raise ValueError("Parameter 'columns' (list) required for creating table.")
                
                col_defs = []
                for col in cols:
                    c_name = col.get('name')
                    c_type = col.get('type')
                    if not c_name or not c_type:
                        raise ValueError("Column definition requires 'name' and 'type'.")
                    
                    c_parts = [sql.Identifier(c_name), sql.SQL(c_type)]
                    if col.get('constraints'):
                        c_parts.append(sql.SQL(col['constraints']))
                    col_defs.append(sql.SQL(" ").join(c_parts))
                
                query = sql.SQL("CREATE TABLE {}.{} ({})").format(
                    sql.Identifier(schema),
                    sql.Identifier(object_name),
                    sql.SQL(", ").join(col_defs)
                )
                
                if owner:
                     # Owner is usually set via ALTER after CREATE for tables, or part of CREATE TABLE logic?
                     # PG CREATE TABLE doesn't have OWNER clause directly, it defaults to current user.
                     # We can run ALTER afterwards if needed, but let's stick to CREATE.
                     pass

            # --- View ---
            elif obj_type == 'view':
                if not schema:
                    raise ValueError("Parameter 'schema' required for creating view.")
                
                view_query = params.get('query')
                if not view_query:
                    raise ValueError("Parameter 'query' required for creating view.")
                
                replace = "OR REPLACE" if params.get('replace') else ""
                
                query = sql.SQL("CREATE {} VIEW {}.{} AS {}").format(
                    sql.SQL(replace),
                    sql.Identifier(schema),
                    sql.Identifier(object_name),
                    sql.SQL(view_query)
                )

            # --- Index ---
            elif obj_type == 'index':
                if not schema:
                    raise ValueError("Parameter 'schema' required for creating index.")
                
                table_name = params.get('table_name')
                if not table_name:
                    raise ValueError("Parameter 'table_name' required for creating index.")
                
                idx_cols = params.get('index_columns', [])
                if not idx_cols:
                    raise ValueError("Parameter 'index_columns' required for creating index.")
                
                unique = "UNIQUE" if params.get('unique') else ""
                method = params.get('method', 'btree') # default btree
                
                # Columns can be expressions, so we trust input string for columns but wrap in parens if not present?
                # Usually list of column names.
                col_parts = []
                for c in idx_cols:
                     # If it looks like an identifier, use Identifier, else SQL (expression)
                     # Simple heuristic: if no spaces/parens, Identifier.
                     if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", c):
                         col_parts.append(sql.Identifier(c))
                     else:
                         col_parts.append(sql.SQL(c))

                query = sql.SQL("CREATE {} INDEX {} ON {}.{} USING {} ({})").format(
                    sql.SQL(unique),
                    sql.Identifier(object_name),
                    sql.Identifier(schema),
                    sql.Identifier(table_name),
                    sql.Identifier(method), # method is an identifier like btree
                    sql.SQL(", ").join(col_parts)
                )

            # --- Function ---
            elif obj_type == 'function':
                if not schema:
                    raise ValueError("Parameter 'schema' required for creating function.")
                
                args = params.get('function_args', '')
                ret_type = params.get('return_type', 'void')
                lang = params.get('language', 'plpgsql')
                body = params.get('body')
                if not body:
                     raise ValueError("Parameter 'body' required for creating function.")
                
                replace = "OR REPLACE" if params.get('replace') else ""
                
                query = sql.SQL("CREATE {} FUNCTION {}.{}({}) RETURNS {} AS {} LANGUAGE {}").format(
                    sql.SQL(replace),
                    sql.Identifier(schema),
                    sql.Identifier(object_name),
                    sql.SQL(args),
                    sql.SQL(ret_type),
                    sql.Literal(body), # Body as string literal
                    sql.Identifier(lang)
                )

            # --- Trigger ---
            elif obj_type == 'trigger':
                if not schema:
                    raise ValueError("Parameter 'schema' required for creating trigger.")
                
                table_name = params.get('table_name')
                event = params.get('event') # e.g. "BEFORE INSERT"
                func_name = params.get('function_name')
                if not table_name or not event or not func_name:
                    raise ValueError("Parameters 'table_name', 'event', 'function_name' required.")
                
                # TRIGGER is on TABLE. 
                query = sql.SQL("CREATE TRIGGER {} {} ON {}.{} FOR EACH ROW EXECUTE PROCEDURE {}").format(
                    sql.Identifier(object_name),
                    sql.SQL(event),
                    sql.Identifier(schema),
                    sql.Identifier(table_name),
                    sql.SQL(func_name) # function name might be schema qualified in string
                )

            # --- Server ---
            elif obj_type == 'server':
                fdw = params.get('fdw_name')
                if not fdw:
                     raise ValueError("Parameter 'fdw_name' required for creating server.")
                
                opts = params.get('options')
                opt_sql = sql.SQL("")
                if opts:
                    # options typically: OPTIONS (host 'foo', port '5432')
                    # If dict provided:
                    if isinstance(opts, dict):
                        opt_list = []
                        for k, v in opts.items():
                            opt_list.append(sql.SQL("{} {}").format(sql.Identifier(k), sql.Literal(v)))
                        opt_sql = sql.SQL("OPTIONS ({})").format(sql.SQL(", ").join(opt_list))
                    else:
                        opt_sql = sql.SQL(opts) # raw string

                query = sql.SQL("CREATE SERVER {} FOREIGN DATA WRAPPER {} {}").format(
                    sql.Identifier(object_name),
                    sql.Identifier(fdw),
                    opt_sql
                )

            else:
                raise ValueError(f"Creation of object type '{obj_type}' not supported.")

            logger.info(f"Executing CREATE: {query.as_string(conn)}")
            _execute_safe(cur, query)
            
            # Post-creation steps (like owner)
            if owner and obj_type in ('table', 'view', 'function', 'sequence'):
                 # Apply ownership if provided and not handled in create
                 object_token = {
                     'table': sql.SQL("TABLE"),
                     'view': sql.SQL("VIEW"),
                     'function': sql.SQL("FUNCTION"),
                     'sequence': sql.SQL("SEQUENCE"),
                 }[obj_type]
                 qualified_name = sql.Identifier(schema, object_name) if schema else sql.Identifier(object_name)
                 owner_query = sql.SQL("ALTER {} {} OWNER TO {}").format(
                     object_token,
                     qualified_name,
                     sql.Identifier(owner)
                 )
                 _execute_safe(cur, owner_query)

            return f"{obj_type.capitalize()} '{object_name}' created successfully."


@mcp.tool(tags={"public"})
def db_pg96_drop_object(
    object_type: str,
    object_name: str,
    schema: str | None = None,
    parameters: dict[str, Any] | None = None
) -> str:
    """
    Executes DROP DDL statements for database objects.
    
    Args:
        object_type: One of: database, schema, table, view, index, function, procedure, trigger, server.
        object_name: Name of the object.
        schema: Schema name (required for schema-scoped objects).
        parameters: Additional parameters:
            - cascade: bool (DROP ... CASCADE)
            - if_exists: bool (DROP ... IF EXISTS)
            - table_name: str (required for 'trigger')
            - function_args: str (signature for 'function'/'procedure', e.g. "int, text")
    """
    if not ALLOW_WRITE:
        raise ValueError("Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable.")

    params = parameters or {}
    obj_type = object_type.lower()
    
    # Normalize object types
    if obj_type == 'procedure':
        obj_type = 'function' # PG 9.6

    with pool.connection() as conn:
        with conn.cursor() as cur:
            
            # Common clauses
            if_exists = sql.SQL("IF EXISTS") if params.get('if_exists') else sql.SQL("")
            cascade = sql.SQL("CASCADE") if params.get('cascade') else sql.SQL("")
            
            query = None
            
            # --- Database ---
            if obj_type == 'database':
                # DROP DATABASE [IF EXISTS] name
                # Note: Cannot drop the currently open database.
                query = sql.SQL("DROP DATABASE {} {}").format(
                    if_exists,
                    sql.Identifier(object_name)
                )

            # --- Server ---
            elif obj_type == 'server':
                query = sql.SQL("DROP SERVER {} {} {}").format(
                    if_exists,
                    sql.Identifier(object_name),
                    cascade
                )
            
            # --- Schema ---
            elif obj_type == 'schema':
                query = sql.SQL("DROP SCHEMA {} {} {}").format(
                    if_exists,
                    sql.Identifier(object_name),
                    cascade
                )

            # --- Trigger ---
            elif obj_type == 'trigger':
                if not schema:
                     raise ValueError("Parameter 'schema' required for dropping trigger.")
                
                table_name = params.get('table_name')
                if not table_name:
                    raise ValueError("Parameter 'table_name' required for dropping trigger.")
                
                query = sql.SQL("DROP TRIGGER {} {} ON {}.{} {}").format(
                    if_exists,
                    sql.Identifier(object_name),
                    sql.Identifier(schema),
                    sql.Identifier(table_name),
                    cascade
                )

            # --- Function / Procedure ---
            elif obj_type == 'function':
                if not schema:
                     raise ValueError("Parameter 'schema' required for dropping function.")
                
                # If args provided, include them in signature
                args = params.get('function_args')
                if args:
                    obj_id = sql.SQL("{}.{}({})").format(
                        sql.Identifier(schema),
                        sql.Identifier(object_name),
                        sql.SQL(args)
                    )
                else:
                    obj_id = sql.Identifier(schema, object_name)
                
                query = sql.SQL("DROP FUNCTION {} {} {}").format(
                    if_exists,
                    obj_id,
                    cascade
                )

            # --- Table, View, Index ---
            elif obj_type in ('table', 'view', 'index'):
                if not schema:
                     raise ValueError(f"Parameter 'schema' required for dropping {obj_type}.")
                
                query = sql.SQL("DROP {} {} {}.{} {}").format(
                    sql.SQL(obj_type.upper()),
                    if_exists,
                    sql.Identifier(schema),
                    sql.Identifier(object_name),
                    cascade
                )

            else:
                raise ValueError(f"Dropping object type '{obj_type}' not supported.")

            logger.info(f"Executing DROP: {query.as_string(conn)}")
            _execute_safe(cur, query)
            
            return f"{obj_type.capitalize()} '{object_name}' dropped successfully."


@mcp.tool(tags={"public"})
def db_pg96_check_bloat(limit: int = 50) -> list[dict[str, Any]]:
    """
    Identifies the top bloated tables and indexes and provides maintenance commands.

    Args:
        limit: Maximum number of objects to return (default: 50).

    Returns:
        List of objects with bloat statistics and suggested maintenance commands.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            # Combined query for Table and Index bloat estimation
            # Using a simplified version of the PostgreSQL Experts/Check_postgres bloat query
            _execute_safe(
                cur,
                """
                with bloat as (
                  -- Table Bloat
                  select
                    'table' as type,
                    schemaname,
                    tblname as object_name,
                    bs::bigint * tblpages::bigint as real_size,
                    (tblpages::bigint - est_tblpages::bigint) * bs::bigint as extra_size,
                    case when tblpages > 0 then (tblpages - est_tblpages)::float / tblpages else 0 end as bloat_ratio,
                    case
                      when (tblpages - est_tblpages) > 0
                      then 'VACUUM FULL ' || quote_ident(schemaname) || '.' || quote_ident(tblname)
                      else 'VACUUM ' || quote_ident(schemaname) || '.' || quote_ident(tblname)
                    end as maintenance_cmd
                  from (
                    select
                      (ceil( reltuples / ( (bs-page_hdr)/fillfactor ) ) + ceil( toasttuples / 4 ))::bigint as est_tblpages,
                      tblpages, fillfactor, bs, tblname, schemaname, page_hdr
                    from (
                      select
                        (select current_setting('block_size')::int) as bs,
                        24 as page_hdr,
                        schemaname, tblname, reltuples, tblpages, toasttuples,
                        coalesce(substring(
                          array_to_string(reloptions, ' ') from 'fillfactor=([0-9]+)'
                        )::int, 100) as fillfactor
                      from (
                        select
                          n.nspname as schemaname,
                          c.relname as tblname,
                          c.reltuples,
                          c.relpages as tblpages,
                          c.reloptions,
                          coalesce( (select sum(t.reltuples) from pg_class t where t.oid = c.reltoastrelid), 0) as toasttuples
                        from pg_class c
                        join pg_namespace n on n.oid = c.relnamespace
                        where c.relkind = 'r'
                          and n.nspname not in ('pg_catalog', 'information_schema')
                          and c.relpages > 128
                      ) as foo
                    ) as first_el_idx
                  ) as second_el_idx

                  union all

                  -- Index Bloat (B-tree only)
                  select
                    'index' as type,
                    schemaname,
                    idxname as object_name,
                    bs::bigint * relpages::bigint as real_size,
                    (relpages::bigint - est_pages::bigint) * bs::bigint as extra_size,
                    case when relpages > 0 then (relpages - est_pages)::float / relpages else 0 end as bloat_ratio,
                    'REINDEX INDEX ' || quote_ident(schemaname) || '.' || quote_ident(idxname) as maintenance_cmd
                  from (
                    select
                      bs, schemaname, idxname, relpages,
                      ceil(reltuples * (avgwidth + 12.0) / (bs - 20.0) / 0.9)::bigint as est_pages
                    from (
                      select
                        (select current_setting('block_size')::int) as bs,
                        n.nspname as schemaname,
                        c.relname as idxname,
                        c.reltuples,
                        c.relpages,
                        (select avg(avg_width) from pg_stats where schemaname = n.nspname and tablename = t.relname) as avgwidth
                      from pg_class c
                      join pg_namespace n on n.oid = c.relnamespace
                      join pg_index i on i.indexrelid = c.oid
                      join pg_class t on t.oid = i.indrelid
                      where c.relkind = 'i'
                        and i.indisprimary = false
                        and n.nspname not in ('pg_catalog', 'information_schema')
                        and c.relpages > 128
                    ) as foo
                  ) as third_el_idx
                )
                select
                  type,
                  schemaname as schema,
                  object_name,
                  real_size as size_bytes,
                  extra_size as bloat_bytes,
                  round(bloat_ratio::numeric * 100, 2) as bloat_percentage,
                  maintenance_cmd
                from bloat
                where extra_size > 0
                order by extra_size desc
                limit %(limit)s
                """,
                {"limit": limit}
            )
            return cur.fetchall()


@mcp.tool(tags={"public"})
def db_pg96_db_stats(database: str | None = None, include_performance: bool = False) -> list[dict[str, Any]] | dict[str, Any]:
    """
    Get database-level statistics including commits, rollbacks, temp files, and deadlocks.
    
    Args:
        database: Optional database name to filter results. If None, returns all databases.
        include_performance: If True, includes additional performance metrics like cache hit ratio.
    
    Returns:
        List of database statistics or single database stats if database specified.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(cur, "select current_setting('server_version_num')::int as server_version_num")
            version_row = cur.fetchone()
            server_version_num = int(version_row["server_version_num"]) if version_row else 0
            checksum_expr = "checksum_failures" if server_version_num >= 120000 else "null::bigint as checksum_failures"

            if database:
                _execute_safe(
                    cur,
                    f"""
                    select
                      datname as database,
                      numbackends as active_connections,
                      xact_commit as commits,
                      xact_rollback as rollbacks,
                      blks_read as blocks_read,
                      blks_hit as blocks_hit,
                      tup_returned as tuples_returned,
                      tup_fetched as tuples_fetched,
                      tup_inserted as tuples_inserted,
                      tup_updated as tuples_updated,
                      tup_deleted as tuples_deleted,
                      conflicts,
                      temp_files,
                      temp_bytes,
                      deadlocks,
                      {checksum_expr}
                    from pg_stat_database
                    where datname = %(database)s
                    """,
                    {"database": database}
                )
                result = cur.fetchone()
                if not result:
                    return {"error": f"Database '{database}' not found"}
                
                if include_performance:
                    # Add cache hit ratio calculation
                    total_blocks = result["blocks_read"] + result["blocks_hit"]
                    result["cache_hit_ratio"] = round((result["blocks_hit"] / total_blocks * 100), 2) if total_blocks > 0 else 0
                    
                    # Add transaction success rate
                    total_xacts = result["commits"] + result["rollbacks"]
                    result["transaction_success_rate"] = round((result["commits"] / total_xacts * 100), 2) if total_xacts > 0 else 0
                
                return result
            else:
                _execute_safe(
                    cur,
                    f"""
                    select
                      datname as database,
                      numbackends as active_connections,
                      xact_commit as commits,
                      xact_rollback as rollbacks,
                      blks_read as blocks_read,
                      blks_hit as blocks_hit,
                      tup_returned as tuples_returned,
                      tup_fetched as tuples_fetched,
                      tup_inserted as tuples_inserted,
                      tup_updated as tuples_updated,
                      tup_deleted as tuples_deleted,
                      conflicts,
                      temp_files,
                      temp_bytes,
                      deadlocks,
                      {checksum_expr},
                      blk_read_time as block_read_time_ms,
                      blk_write_time as block_write_time_ms,
                      stats_reset
                    from pg_stat_database
                    where datname not like 'template%%'
                    order by datname
                    """
                )
                results = cur.fetchall()
                
                if include_performance:
                    # Enhance each result with performance metrics
                    for result in results:
                        total_blocks = result["blocks_read"] + result["blocks_hit"]
                        result["cache_hit_ratio"] = round((result["blocks_hit"] / total_blocks * 100), 2) if total_blocks > 0 else 0
                        
                        total_xacts = result["commits"] + result["rollbacks"]
                        result["transaction_success_rate"] = round((result["commits"] / total_xacts * 100), 2) if total_xacts > 0 else 0
                
                return results


@mcp.tool(tags={"public"})
def db_pg96_analyze_table_health(
    schema: str | None = None,
    min_size_mb: int = 50,
    include_bloat: bool = True,
    include_maintenance: bool = True,
    include_autovacuum: bool = True,
    limit: int = 30,
    profile: str = "oltp",
    detail_level: str = "full",
    max_tables: int | None = None,
    response_format: str = "legacy",
) -> dict[str, Any]:
    """
    Comprehensive table health analysis combining bloat detection, maintenance needs, and autovacuum recommendations.
    
    Args:
        schema: Optional schema name to filter analysis.
        min_size_mb: Minimum table size in MB to consider.
        include_bloat: Include bloat analysis (default: True).
        include_maintenance: Include maintenance statistics (default: True).
        include_autovacuum: Include autovacuum recommendations (default: True).
        limit: Maximum number of tables to analyze (default: 30).
        profile: Workload profile to tune thresholds, e.g. "oltp" or "olap".
    
    Returns:
        Dictionary containing table health summary, detailed analysis, and recommendations.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            results = {
                "summary": {
                    "total_tables_analyzed": 0,
                    "tables_with_issues": 0,
                    "critical_issues": 0,
                    "materialized_view_candidates": 0,
                    "recommendations": []
                },
                "tables": [],
                "overall_health_score": 100
            }

            profile_value = (profile or "oltp").lower()
            if profile_value == "olap":
                autovac_high_mod_threshold = 5000
                autovac_low_mod_threshold = 500
                mv_min_size_mb = max(min_size_mb, 50)
                mv_max_mods_per_day = 1000
                mv_min_reads = 100
                mv_min_ratio = 3.0
            else:
                autovac_high_mod_threshold = 1000
                autovac_low_mod_threshold = 100
                mv_min_size_mb = max(min_size_mb, 100)
                mv_max_mods_per_day = 100
                mv_min_reads = 1000
                mv_min_ratio = 10.0

            # Get candidate tables
            _execute_safe(
                cur,
                """
                select
                  c.oid
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where c.relkind = 'r'
                  and n.nspname not in ('pg_catalog', 'information_schema')
                  and (%(schema)s::text is null or n.nspname = %(schema)s::text)
                  and pg_relation_size(c.oid) > %(min_size)s::bigint * 1024 * 1024
                order by pg_relation_size(c.oid) desc
                limit %(limit)s
                """,
                {"schema": schema, "min_size": min_size_mb, "limit": limit}
            )
            candidate_oids = [row['oid'] for row in cur.fetchall()]
            
            candidate_tables = []
            if candidate_oids:
                _execute_safe(
                    cur,
                    """
                    select
                      n.nspname as schema,
                      c.relname as table,
                      pg_total_relation_size(c.oid) as size_bytes,
                      c.reltuples::bigint as approx_rows,
                      s.n_live_tup as live_tuples,
                      s.n_dead_tup as dead_tuples,
                      s.n_tup_ins as inserts,
                      s.n_tup_upd as updates,
                      s.n_tup_del as deletes,
                      s.seq_scan,
                      s.idx_scan,
                      s.last_vacuum,
                      s.last_autovacuum,
                      s.last_analyze,
                      s.last_autoanalyze,
                      case
                        when coalesce(s.last_autovacuum, s.last_vacuum) is null then null
                        else extract(epoch from (now() - coalesce(s.last_autovacuum, s.last_vacuum)))
                      end as seconds_since_vacuum,
                      case
                        when coalesce(s.last_autoanalyze, s.last_analyze) is null then null
                        else extract(epoch from (now() - coalesce(s.last_autoanalyze, s.last_analyze)))
                      end as seconds_since_analyze,
                      age(c.relfrozenxid) as frozenxid_age
                    from pg_class c
                    join pg_namespace n on n.oid = c.relnamespace
                    left join pg_stat_user_tables s on s.relid = c.oid
                    where c.oid = any(%(oids)s)
                    """,
                    {"oids": candidate_oids}
                )
                candidate_tables = cur.fetchall()
            
            results["summary"]["total_tables_analyzed"] = len(candidate_tables)

            for table in candidate_tables:
                table_analysis = {
                    "schema": table["schema"],
                    "table": table["table"],
                    "size_mb": round(table["size_bytes"] / (1024 * 1024), 1),
                    "approx_rows": table["approx_rows"],
                    "health_score": 100,
                    "issues": [],
                    "recommendations": []
                }

                # Calculate modification rate
                total_mods = (table["inserts"] or 0) + (table["updates"] or 0) + (table["deletes"] or 0)
                age_seconds_candidates = [table.get("seconds_since_vacuum"), table.get("seconds_since_analyze")]
                age_seconds = min([s for s in age_seconds_candidates if s is not None], default=86400)
                age_days = max(float(age_seconds) / 86400.0, 1.0)
                mod_rate_per_day = total_mods / age_days

                # 1. Bloat Analysis
                if include_bloat:
                    _execute_safe(
                        cur,
                        """
                        with bloat_estimate as (
                          select
                            case
                              when (s.n_live_tup + s.n_dead_tup) > 0
                              then round((s.n_dead_tup::float / (s.n_live_tup + s.n_dead_tup) * 100)::numeric, 2)
                              else 0
                            end as dead_tuple_percent,
                            case
                              when pg_total_relation_size(c.oid) > 0
                              then round((s.n_dead_tup * 100.0 / greatest(s.n_live_tup, 1))::numeric, 2)
                              else 0
                            end as estimated_bloat_percent
                          from pg_class c
                          join pg_namespace n on n.oid = c.relnamespace
                          left join pg_stat_user_tables s on s.relid = c.oid
                          where n.nspname = %(schema)s and c.relname = %(table)s
                        )
                        select dead_tuple_percent, estimated_bloat_percent
                        from bloat_estimate
                        """,
                        {"schema": table["schema"], "table": table["table"]}
                    )
                    bloat_info = cur.fetchone()
                    
                    if bloat_info:
                        dead_tuple_percent = bloat_info["dead_tuple_percent"]
                        estimated_bloat_percent = bloat_info["estimated_bloat_percent"]
                        
                        if dead_tuple_percent > 20:
                            table_analysis["issues"].append(f"High dead tuple ratio: {dead_tuple_percent}%")
                            table_analysis["recommendations"].append("Run VACUUM to clean up dead tuples")
                            table_analysis["health_score"] -= 20
                        elif dead_tuple_percent > 10:
                            table_analysis["issues"].append(f"Moderate dead tuple ratio: {dead_tuple_percent}%")
                            table_analysis["health_score"] -= 10

                # 2. Maintenance Analysis
                if include_maintenance:
                    # Check freeze risk
                    _execute_safe(
                        cur,
                        """
                        select current_setting('autovacuum_freeze_max_age')::bigint as freeze_max_age
                        """
                    )
                    freeze_settings = cur.fetchone() or {"freeze_max_age": 0}
                    freeze_max_age = freeze_settings["freeze_max_age"]
                    
                    age_percent = (table["frozenxid_age"] / freeze_max_age * 100) if freeze_max_age > 0 else 0
                    
                    if age_percent > 50:
                        table_analysis["issues"].append(f"High transaction ID age: {round(age_percent, 1)}% of freeze_max_age")
                        table_analysis["recommendations"].append("Prioritize freeze operations - table at risk of wraparound")
                        table_analysis["health_score"] -= 30
                        results["summary"]["critical_issues"] += 1
                    elif age_percent > 25:
                        table_analysis["issues"].append(f"Moderate transaction ID age: {round(age_percent, 1)}% of freeze_max_age")
                        table_analysis["health_score"] -= 15

                    # Check vacuum/analyze recency
                    days_since_vacuum = float(table["seconds_since_vacuum"]) / 86400.0 if table.get("seconds_since_vacuum") is not None else 999.0
                    days_since_analyze = float(table["seconds_since_analyze"]) / 86400.0 if table.get("seconds_since_analyze") is not None else 999.0
                    
                    if days_since_vacuum > 7:
                        table_analysis["issues"].append(f"No vacuum in {int(days_since_vacuum)} days")
                        table_analysis["health_score"] -= 10
                    
                    if days_since_analyze > 7:
                        table_analysis["issues"].append(f"No analyze in {int(days_since_analyze)} days")
                        table_analysis["health_score"] -= 5

                # 3. Autovacuum Recommendations
                if include_autovacuum:
                    if mod_rate_per_day > autovac_high_mod_threshold:
                        table_analysis["recommendations"].append("High modification rate - consider aggressive autovacuum settings")
                        table_analysis["autovacuum_suggestions"] = {
                            "autovacuum_vacuum_scale_factor": 0.1,
                            "autovacuum_vacuum_threshold": 50,
                            "autovacuum_vacuum_cost_delay": 0
                        }
                    elif mod_rate_per_day < autovac_low_mod_threshold:
                        table_analysis["recommendations"].append("Low modification rate - standard autovacuum settings sufficient")
                        table_analysis["autovacuum_suggestions"] = {
                            "autovacuum_vacuum_scale_factor": 0.2,
                            "autovacuum_vacuum_threshold": 100
                        }

                # 4. Materialized view candidate analysis
                read_ops = (table["seq_scan"] or 0) + (table["idx_scan"] or 0)
                write_ops = total_mods
                if write_ops > 0:
                    read_to_write_ratio = read_ops / write_ops
                else:
                    read_to_write_ratio = float("inf") if read_ops > 0 else 0.0

                mv_candidate = (
                    table_analysis["size_mb"] >= mv_min_size_mb
                    and mod_rate_per_day < mv_max_mods_per_day
                    and read_ops >= mv_min_reads
                    and read_to_write_ratio >= mv_min_ratio
                )

                if mv_candidate:
                    table_analysis["materialized_view_candidate"] = True
                    table_analysis["recommendations"].append(
                        "High read, low write workload - consider materialized views for common reporting queries"
                    )
                    results["summary"]["materialized_view_candidates"] += 1
                else:
                    table_analysis["materialized_view_candidate"] = False

                # Final health score adjustments
                if table_analysis["health_score"] < 70:
                    results["summary"]["tables_with_issues"] += 1
                
                table_analysis["health_score"] = max(0, min(100, table_analysis["health_score"]))
                results["tables"].append(table_analysis)

            # Calculate overall health score
            if results["tables"]:
                avg_health = sum(t["health_score"] for t in results["tables"]) / len(results["tables"])
                critical_ratio = results["summary"]["critical_issues"] / len(results["tables"])
                
                results["overall_health_score"] = max(0, avg_health - (critical_ratio * 20))

            # Generate summary recommendations
            if results["summary"]["critical_issues"] > 0:
                results["summary"]["recommendations"].append(f"URGENT: {results['summary']['critical_issues']} tables have critical issues requiring immediate attention")
            
            if results["summary"]["tables_with_issues"] > len(results["tables"]) * 0.5:
                results["summary"]["recommendations"].append("More than 50% of analyzed tables have health issues - consider database-wide maintenance")
            
            if results["overall_health_score"] < 70:
                results["summary"]["recommendations"].append("Overall database health is concerning - prioritize maintenance operations")

            detail = (detail_level or "full").lower()
            if detail not in {"full", "compact"}:
                raise ValueError("detail_level must be 'full' or 'compact'")

            tables = results.get("tables", [])
            max_table_count = max_tables if max_tables is not None else limit
            trimmed_tables, tables_truncated = _trim_list(tables, max_table_count)

            if detail == "compact":
                compact_tables: list[dict[str, Any]] = []
                for row in trimmed_tables:
                    compact_tables.append(
                        {
                            "schema": row.get("schema"),
                            "table": row.get("table"),
                            "size_mb": row.get("size_mb"),
                            "health_score": row.get("health_score"),
                            "issues_count": len(row.get("issues", [])),
                            "recommendations_count": len(row.get("recommendations", [])),
                        }
                    )
                results["tables"] = compact_tables
            else:
                results["tables"] = trimmed_tables

            if response_format == "legacy":
                results["_meta"] = {
                    "detail_level": detail,
                    "tables_returned": len(results.get("tables", [])),
                    "tables_truncated": tables_truncated,
                }
                return results
            if response_format != "envelope":
                raise ValueError("response_format must be 'legacy' or 'envelope'")

            return _build_response_envelope(
                tool="db_pg96_analyze_table_health",
                payload=results,
                summary={
                    "detail_level": detail,
                    "tables_returned": len(results.get("tables", [])),
                    "overall_health_score": results.get("overall_health_score"),
                    "tables_with_issues": results.get("summary", {}).get("tables_with_issues", 0),
                    "critical_issues": results.get("summary", {}).get("critical_issues", 0),
                },
                truncated=tables_truncated,
                hints_for_next_call=[
                    "Increase max_tables to inspect more tables.",
                    "Use detail_level='full' for per-table issue/recommendation detail.",
                ],
            )


@mcp.tool(tags={"public"})
def db_pg96_db_sec_perf_metrics(
    cache_hit_threshold: int | None = None,
    connection_usage_threshold: float | None = None,
    profile: str = "oltp",
    detail_level: str = "full",
    max_items_per_list: int | None = None,
    response_format: str = "legacy",
) -> dict[str, Any]:
    """
    Analyzes database security and performance metrics, identifying issues and providing optimization commands.
    
    Args:
        cache_hit_threshold: Minimum acceptable cache hit ratio percentage. If None, tuned by profile.
        connection_usage_threshold: Maximum acceptable connection usage ratio. If None, tuned by profile.
        profile: Workload profile to tune thresholds, e.g. "oltp" or "olap".
    
    Returns:
        Dictionary containing security metrics, performance metrics, issues found, and recommended fixes.
    """
    # Profile-based threshold logic
    profile_value = (profile or "oltp").lower()
    if profile_value == "olap":
        default_cache_threshold = 80
        default_conn_threshold = 0.9
        checkpoint_req_threshold = 50
        temp_file_threshold = 500
    else:  # Default to oltp
        default_cache_threshold = 95
        default_conn_threshold = 0.7
        checkpoint_req_threshold = 20
        temp_file_threshold = 50

    cache_hit_limit = cache_hit_threshold if cache_hit_threshold is not None else default_cache_threshold
    conn_usage_limit = connection_usage_threshold if connection_usage_threshold is not None else default_conn_threshold

    with pool.connection() as conn:
        with conn.cursor() as cur:
            results = {
                "security_metrics": {},
                "performance_metrics": {},
                "issues_found": [],
                "recommended_fixes": [],
                "profile_applied": profile_value
            }

            # 1. SSL/TLS Configuration
            _execute_safe(
                cur,
                """
                select
                  name,
                  setting,
                  context,
                  pending_restart
                from pg_settings
                where name in ('ssl', 'ssl_ciphers', 'ssl_cert_file', 'ssl_key_file', 'ssl_ca_file')
                order by name
                """
            )
            ssl_settings = cur.fetchall()
            results["security_metrics"]["ssl_settings"] = ssl_settings

            # Check if SSL is enabled
            ssl_enabled = any(s["name"] == "ssl" and s["setting"] == "on" for s in ssl_settings)
            if not ssl_enabled:
                results["issues_found"].append("SSL is not enabled - connections are not encrypted")
                results["recommended_fixes"].append("Enable SSL by setting ssl = on in postgresql.conf and configure certificates")

            # 2. Authentication and Connection Security
            _execute_safe_with_fallback(
                                cur,
                                """
                                select
                                    r.rolname as user,
                                    r.oid as usesysid,
                                    r.rolcreatedb as usecreatedb,
                                    r.rolsuper as usesuper,
                                    r.rolreplication as userepl,
                                    r.rolbypassrls as usebypassrls,
                                    s.passwd is not null as has_password,
                                    s.valuntil as password_expiry,
                                    s.valuntil - now() as time_until_expiry
                                from pg_roles r
                                left join pg_shadow s on s.usename = r.rolname
                                where r.rolname not like 'pg_%'
                                order by r.rolname
                                """,
                                """
                                select
                                    r.rolname as user,
                                    r.oid as usesysid,
                                    r.rolcreatedb as usecreatedb,
                                    r.rolsuper as usesuper,
                                    r.rolreplication as userepl,
                                    r.rolbypassrls as usebypassrls,
                                    null::boolean as has_password,
                                    null::timestamptz as password_expiry,
                                    null::interval as time_until_expiry
                                from pg_roles r
                                where r.rolname not like 'pg_%'
                                order by r.rolname
                                """,
            )
            user_security = cur.fetchall()
            
            # Summarize users to avoid truncation
            superusers = [u for u in user_security if u["usesuper"]]
            users_without_passwords = [u for u in user_security if not u["has_password"]]
            
            results["security_metrics"]["user_accounts_summary"] = {
                "total_users": len(user_security),
                "superuser_count": len(superusers),
                "no_password_count": len(users_without_passwords),
                "superusers": [u["user"] for u in superusers],
                "users_without_passwords": [u["user"] for u in users_without_passwords][:10] # Show first 10
            }

            # Check for superusers and password issues
            if len(superusers) > 1:
                results["issues_found"].append(f"Multiple superusers found: {[u['user'] for u in superusers]}")
                results["recommended_fixes"].append("Review superuser privileges and limit to minimum required")

            if users_without_passwords:
                results["issues_found"].append(f"Users without passwords: {len(users_without_passwords)} users detected")
                results["recommended_fixes"].append("Set strong passwords for all user accounts")

            # 3. Cache Hit Ratio Analysis
            _execute_safe(
                cur,
                """
                select
                  datname as database,
                  blks_hit,
                  blks_read,
                  case
                    when (blks_hit + blks_read) > 0
                    then round((blks_hit::float / (blks_hit + blks_read) * 100)::numeric, 2)
                    else 0
                  end as cache_hit_ratio
                from pg_stat_database
                where datname not like 'template%%'
                order by cache_hit_ratio asc
                """
            )
            cache_metrics = cur.fetchall()
            results["performance_metrics"]["cache_hit_ratios"] = cache_metrics

            # Identify databases with poor cache hit ratios
            poor_cache_databases = [db for db in cache_metrics if db["cache_hit_ratio"] < cache_hit_limit]
            if poor_cache_databases:
                results["issues_found"].append(f"Low cache hit ratios: {[f'{db['database']} ({db['cache_hit_ratio']}%)' for db in poor_cache_databases]}")
                results["recommended_fixes"].append(f"Consider increasing shared_buffers for better cache performance (threshold: {cache_hit_limit}% for {profile_value})")

            # 4. Connection Pool and Limits
            _execute_safe(
                cur,
                """
                select
                  current_setting('max_connections')::int as max_connections,
                  current_setting('superuser_reserved_connections')::int as reserved_connections,
                  count(*) as active_connections,
                  current_setting('max_connections')::int - count(*) as available_connections
                from pg_stat_activity
                where state != 'idle'
                """
            )
            connection_metrics = cur.fetchone() or {
                "max_connections": 0,
                "reserved_connections": 0,
                "active_connections": 0,
                "available_connections": 0,
            }
            results["performance_metrics"]["connection_usage"] = connection_metrics

            if connection_metrics["active_connections"] > connection_metrics["max_connections"] * conn_usage_limit:
                results["issues_found"].append(f"High connection usage: {connection_metrics['active_connections']}/{connection_metrics['max_connections']} connections active")
                results["recommended_fixes"].append(f"Consider increasing max_connections or implementing connection pooling (threshold: {int(conn_usage_limit*100)}% for {profile_value})")

            # 5. WAL and Checkpoint Performance
            _execute_safe(
                cur,
                """
                select
                  checkpoints_timed,
                  checkpoints_req,
                  checkpoint_write_time,
                  checkpoint_sync_time,
                  buffers_checkpoint,
                  buffers_clean,
                  buffers_backend,
                  case
                    when checkpoints_timed + checkpoints_req > 0
                    then round((checkpoints_req::float / (checkpoints_timed + checkpoints_req) * 100)::numeric, 2)
                    else 0
                  end as checkpoint_request_ratio
                from pg_stat_bgwriter
                """
            )
            checkpoint_metrics = cur.fetchone() or {
                "checkpoints_timed": 0,
                "checkpoints_req": 0,
                "checkpoint_write_time": 0,
                "checkpoint_sync_time": 0,
                "buffers_checkpoint": 0,
                "buffers_clean": 0,
                "buffers_backend": 0,
                "checkpoint_request_ratio": 0,
            }
            results["performance_metrics"]["checkpoint_stats"] = checkpoint_metrics

            if checkpoint_metrics["checkpoint_request_ratio"] > checkpoint_req_threshold:
                results["issues_found"].append(f"High checkpoint request ratio: {checkpoint_metrics['checkpoint_request_ratio']}%")
                results["recommended_fixes"].append(f"Consider increasing max_wal_size or checkpoint_timeout to reduce frequency (threshold: {checkpoint_req_threshold}% for {profile_value})")

            # 6. Lock and Deadlock Analysis
            _execute_safe(
                cur,
                """
                select
                  deadlocks,
                  conflicts,
                  temp_files,
                  temp_bytes
                from pg_stat_database
                where datname = current_database()
                """
            )
            lock_metrics = cur.fetchone() or {
                "deadlocks": 0,
                "conflicts": 0,
                "temp_files": 0,
                "temp_bytes": 0,
            }
            results["performance_metrics"]["lock_stats"] = lock_metrics

            if lock_metrics["deadlocks"] > 0:
                results["issues_found"].append(f"Deadlocks detected: {lock_metrics['deadlocks']}")
                results["recommended_fixes"].append("Review application locking patterns and transaction isolation levels")

            if lock_metrics["temp_files"] > temp_file_threshold:
                results["issues_found"].append(f"High temp file usage: {lock_metrics['temp_files']} files, {lock_metrics['temp_bytes']} bytes")
                results["recommended_fixes"].append(f"Consider increasing work_mem to reduce temporary file creation (threshold: {temp_file_threshold} for {profile_value})")

            # 7. Extension Security
            _execute_safe(
                cur,
                """
                select
                  extname as extension,
                  extversion as version,
                  n.nspname as schema
                from pg_extension e
                join pg_namespace n on n.oid = e.extnamespace
                where extname not in ('plpgsql')
                order by extname
                """
            )
            extensions = cur.fetchall()
            results["security_metrics"]["installed_extensions"] = extensions

            # Check for potentially risky extensions
            risky_extensions = ["dblink", "postgres_fdw", "file_fdw", "plpython3u", "plperlu"]
            installed_risky = [ext for ext in extensions if ext["extension"] in risky_extensions]
            if installed_risky:
                results["issues_found"].append(f"Potentially risky extensions installed: {[ext['extension'] for ext in installed_risky]}")
                results["recommended_fixes"].append("Review and restrict access to extensions that enable external connections or code execution")

            # 8. Generate specific configuration commands
            if not ssl_enabled:
                results["recommended_fixes"].append("# Generate SSL certificates and update postgresql.conf:")
                results["recommended_fixes"].append("# ssl = on")
                results["recommended_fixes"].append("# ssl_cert_file = 'server.crt'")
                results["recommended_fixes"].append("# ssl_key_file = 'server.key'")
                results["recommended_fixes"].append("# ssl_ca_file = 'root.crt'")

            if poor_cache_databases:
                results["recommended_fixes"].append("# Increase shared_buffers:")
                results["recommended_fixes"].append("# shared_buffers = 256MB  # Adjust based on available RAM")

            if connection_metrics["active_connections"] > connection_metrics["max_connections"] * conn_usage_limit:
                results["recommended_fixes"].append(f"# Increase max_connections (currently {connection_metrics['max_connections']}):")
                results["recommended_fixes"].append("# max_connections = 200  # Adjust based on workload")

            if checkpoint_metrics["checkpoint_request_ratio"] > checkpoint_req_threshold:
                results["recommended_fixes"].append("# Optimize checkpoint settings:")
                results["recommended_fixes"].append("# checkpoint_timeout = 15min")
                results["recommended_fixes"].append("# max_wal_size = 4GB")
                results["recommended_fixes"].append("# min_wal_size = 1GB")

            if lock_metrics["temp_files"] > temp_file_threshold:
                results["recommended_fixes"].append("# Increase work_mem (use caution, affects per-operation memory):")
                results["recommended_fixes"].append("# work_mem = 64MB  # Adjust based on concurrent connections")

            detail = (detail_level or "full").lower()
            if detail not in {"full", "compact"}:
                raise ValueError("detail_level must be 'full' or 'compact'")

            list_cap = max_items_per_list if max_items_per_list is not None else 10

            truncated = False

            cache_list = results["performance_metrics"].get("cache_hit_ratios", [])
            cache_trimmed, cache_truncated = _trim_list(cache_list, list_cap)
            results["performance_metrics"]["cache_hit_ratios"] = cache_trimmed
            truncated = truncated or cache_truncated

            ext_list = results["security_metrics"].get("installed_extensions", [])
            ext_trimmed, ext_truncated = _trim_list(ext_list, list_cap)
            results["security_metrics"]["installed_extensions"] = ext_trimmed
            truncated = truncated or ext_truncated

            issues = results.get("issues_found", [])
            issues_trimmed, issues_truncated = _trim_list(issues, list_cap)
            results["issues_found"] = issues_trimmed
            truncated = truncated or issues_truncated

            fixes = results.get("recommended_fixes", [])
            fixes_trimmed, fixes_truncated = _trim_list(fixes, list_cap)
            results["recommended_fixes"] = fixes_trimmed
            truncated = truncated or fixes_truncated

            if detail == "compact":
                results["security_metrics"] = {
                    "ssl_enabled": ssl_enabled,
                    "user_accounts_summary": results["security_metrics"].get("user_accounts_summary", {}),
                    "installed_extensions_count": len(ext_list),
                    "installed_extensions_sample": results["security_metrics"].get("installed_extensions", []),
                }
                results["performance_metrics"] = {
                    "connection_usage": results["performance_metrics"].get("connection_usage", {}),
                    "checkpoint_stats": results["performance_metrics"].get("checkpoint_stats", {}),
                    "lock_stats": results["performance_metrics"].get("lock_stats", {}),
                    "cache_hit_ratios_sample": results["performance_metrics"].get("cache_hit_ratios", []),
                }

            if response_format == "legacy":
                results["_meta"] = {
                    "detail_level": detail,
                    "max_items_per_list": list_cap,
                    "truncated": truncated,
                }
                return results
            if response_format != "envelope":
                raise ValueError("response_format must be 'legacy' or 'envelope'")

            return _build_response_envelope(
                tool="db_pg96_db_sec_perf_metrics",
                payload=results,
                summary={
                    "detail_level": detail,
                    "issues_count": len(results.get("issues_found", [])),
                    "profile_applied": results.get("profile_applied"),
                    "ssl_enabled": ssl_enabled,
                },
                truncated=truncated,
                hints_for_next_call=[
                    "Increase max_items_per_list to inspect more list entries.",
                    "Use detail_level='full' for expanded metric payloads.",
                ],
            )


@mcp.tool(tags={"public"})
def db_pg96_database_security_performance_metrics(
    cache_hit_threshold: int | None = None,
    connection_usage_threshold: float | None = None,
    profile: str = "oltp",
    detail_level: str = "full",
    max_items_per_list: int | None = None,
    response_format: str = "legacy",
) -> dict[str, Any]:
    """
    Alias for db_pg96_db_sec_perf_metrics to support clients expecting full-name tool convention.
    """
    return db_pg96_db_sec_perf_metrics(
        cache_hit_threshold=cache_hit_threshold,
        connection_usage_threshold=connection_usage_threshold,
        profile=profile,
        detail_level=detail_level,
        max_items_per_list=max_items_per_list,
        response_format=response_format,
    )


@mcp.tool(tags={"public"})
def db_pg96_recommend_partitioning(
    min_size_gb: float = 1.0,
    schema: str | None = None,
    limit: int = 50
) -> dict[str, Any]:
    """
    Suggests tables for partitioning based primarily on size and basic access patterns.
    
    Args:
        min_size_gb: Minimum total table size in gigabytes to consider as a candidate.
        schema: Optional schema name to filter tables. If None, all user schemas are considered.
        limit: Maximum number of candidate tables to return.
    
    Returns:
        Dictionary containing a summary and a list of candidate tables with size and access metrics.
    """
    if min_size_gb <= 0:
        raise ValueError("min_size_gb must be positive")
    if limit <= 0:
        raise ValueError("limit must be positive")

    size_bytes_threshold = int(min_size_gb * 1024 * 1024 * 1024)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(
                cur,
                """
                with params as (
                  select current_setting('block_size')::int as bs
                )
                select
                  c.oid,
                  n.nspname as schema,
                  c.relname as table,
                  (c.relpages::bigint * p.bs::bigint) as approx_size_bytes
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                cross join params p
                where c.relkind = 'r'
                  and n.nspname not in ('pg_catalog', 'information_schema')
                  and (%(schema)s::text is null or n.nspname = %(schema)s::text)
                order by (c.relpages::bigint * p.bs::bigint) desc
                limit %(limit)s
                """,
                {
                    "schema": schema,
                    "limit": limit,
                },
            )
            base_rows = cur.fetchall()

            results: dict[str, Any] = {
                "summary": {
                    "min_size_gb": float(min_size_gb),
                    "schema_filter": schema,
                    "total_candidates": 0,
                },
                "candidates": [],
            }

            if not base_rows:
                return results

            filtered_rows = [
                row for row in base_rows
                if row["approx_size_bytes"] >= size_bytes_threshold
            ]
            results["summary"]["total_candidates"] = len(filtered_rows)

            for row in filtered_rows:
                oid = row["oid"]

                _execute_safe(
                    cur,
                    """
                    select
                      s.n_live_tup as live_rows,
                      s.n_dead_tup as dead_rows,
                      s.seq_scan,
                      s.idx_scan,
                      s.n_tup_ins as inserts,
                      s.n_tup_upd as updates,
                      s.n_tup_del as deletes
                    from pg_stat_user_tables s
                    where s.relid = %(oid)s
                    """,
                    {"oid": oid},
                )
                stats = cur.fetchone() or {}

                approx_size_gb = row["approx_size_bytes"] / float(1024 * 1024 * 1024)
                live_rows = stats.get("live_rows") or 0
                dead_rows = stats.get("dead_rows") or 0
                seq_scan = stats.get("seq_scan") or 0
                idx_scan = stats.get("idx_scan") or 0
                inserts = stats.get("inserts") or 0
                updates = stats.get("updates") or 0
                deletes = stats.get("deletes") or 0

                total_reads = seq_scan + idx_scan
                total_writes = inserts + updates + deletes

                if total_reads > 0 or total_writes > 0:
                    if total_reads >= 10 * max(total_writes, 1):
                        workload_pattern = "read_heavy"
                    elif total_writes >= 5 * max(total_reads, 1):
                        workload_pattern = "write_heavy"
                    else:
                        workload_pattern = "mixed"
                else:
                    workload_pattern = "unknown"

                if approx_size_gb >= 10.0 or live_rows >= 100_000_000:
                    benefit = "high"
                elif approx_size_gb >= 1.0 or live_rows >= 10_000_000:
                    benefit = "medium"
                else:
                    benefit = "low"

                notes_parts = []
                if benefit == "high":
                    notes_parts.append("Very large table; partitioning likely to improve maintenance and query performance")
                elif benefit == "medium":
                    notes_parts.append("Large table; partitioning may help for time-based or tenant-based queries")
                else:
                    notes_parts.append("Borderline size for partitioning; consider only if query patterns benefit")

                if workload_pattern == "read_heavy":
                    notes_parts.append("Read-heavy workload")
                elif workload_pattern == "write_heavy":
                    notes_parts.append("Write-heavy workload")
                elif workload_pattern == "mixed":
                    notes_parts.append("Balanced read/write workload")

                candidate = {
                    "schema": row["schema"],
                    "table": row["table"],
                    "approx_size_gb": round(approx_size_gb, 3),
                    "live_rows": live_rows,
                    "dead_rows": dead_rows,
                    "seq_scan": seq_scan,
                    "idx_scan": idx_scan,
                    "total_reads": total_reads,
                    "total_writes": total_writes,
                    "workload_pattern": workload_pattern,
                    "estimated_partitioning_benefit": benefit,
                    "notes": "; ".join(notes_parts),
                }

                results["candidates"].append(candidate)

            return results


@mcp.tool(tags={"public"})
def db_pg96_analyze_sessions(
    include_idle: bool = True,
    include_active: bool = True,
    include_locked: bool = True,
    min_duration_seconds: int = 60,
    min_idle_seconds: int = 60
) -> dict[str, Any]:
    """
    Comprehensive session analysis combining active queries, idle sessions, and locks.
    
    Args:
        include_idle: Include idle and idle-in-transaction sessions.
        include_active: Include active query sessions.
        include_locked: Include sessions involved in locks.
        min_duration_seconds: Minimum query/transaction duration to include.
        min_idle_seconds: Minimum idle time for idle sessions.
    
    Returns:
        Dictionary containing session summary, detailed sessions, and recommendations.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            results = {
                "summary": {},
                "active_sessions": [],
                "idle_sessions": [],
                "locked_sessions": [],
                "recommendations": []
            }

            # Get overall session statistics
            _execute_safe(
                cur,
                """
                select
                  count(*) as total_sessions,
                  count(*) filter (where state = 'active') as active_count,
                  count(*) filter (where state like 'idle%') as idle_count,
                  count(*) filter (where wait_event is not null) as waiting_count
                from pg_stat_activity
                where pid <> pg_backend_pid()
                """
            )
            results["summary"] = cur.fetchone()

            # Active sessions with long-running queries/transactions
            if include_active:
                _execute_safe(
                    cur,
                    """
                    select
                      pid,
                      usename as user,
                      datname as database,
                      application_name,
                      client_addr::text as client_addr,
                      state,
                      now() - xact_start as xact_age,
                      now() - query_start as query_age,
                      wait_event_type,
                      wait_event,
                      left(query, 5000) as query
                    from pg_stat_activity
                    where pid <> pg_backend_pid()
                      and (
                        (query_start is not null and now() - query_start > make_interval(secs => %(min_duration)s))
                        or (xact_start is not null and now() - xact_start > make_interval(secs => %(min_duration)s))
                      )
                    order by greatest(coalesce(now() - query_start, interval '0'), coalesce(now() - xact_start, interval '0')) desc
                    """,
                    {"min_duration": min_duration_seconds}
                )
                results["active_sessions"] = cur.fetchall()

            # Idle sessions
            if include_idle:
                _execute_safe(
                    cur,
                    """
                    select
                      pid,
                      usename as user,
                      datname as database,
                      application_name,
                      state,
                      now() - backend_start as connection_duration,
                      now() - state_change as idle_duration,
                      left(query, 1000) as last_query
                    from pg_stat_activity
                    where state in ('idle', 'idle in transaction', 'idle in transaction (aborted)')
                      and pid <> pg_backend_pid()
                      and now() - state_change > make_interval(secs => %(min_idle)s)
                    order by state_change asc
                    """,
                    {"min_idle": min_idle_seconds}
                )
                results["idle_sessions"] = cur.fetchall()

            # Locked sessions (blocked and blocking)
            if include_locked:
                _execute_safe(
                    cur,
                    """
                    with lock_chains as (
                      select
                        bl.pid as blocked_pid,
                        a.usename as blocked_user,
                        a.datname as blocked_database,
                        a.application_name as blocked_application_name,
                        a.client_addr::text as blocked_client_addr,
                        a.state as blocked_state,
                        now() - a.query_start as blocked_execution_time,
                        left(a.query, 500) as blocked_query,
                        bl.locktype,
                        bl.mode as blocked_lock_mode,
                        -- Find the blocking session
                        (select pid from pg_locks where granted and pg_locks.locktype = bl.locktype 
                         and pg_locks.database = bl.database and pg_locks.relation = bl.relation 
                         and pg_locks.page = bl.page and pg_locks.tuple = bl.tuple 
                         and pg_locks.virtualxid = bl.virtualxid and pg_locks.transactionid = bl.transactionid 
                         and pg_locks.classid = bl.classid and pg_locks.objid = bl.objid 
                         and pg_locks.objsubid = bl.objsubid limit 1) as blocking_pid
                      from pg_catalog.pg_locks bl
                      join pg_catalog.pg_stat_activity a on a.pid = bl.pid
                      where not bl.granted
                        and bl.pid <> pg_backend_pid()
                    )
                    select
                      blocked_pid,
                      blocked_user,
                      blocked_database,
                      blocked_application_name,
                      blocked_client_addr,
                      blocked_state,
                      blocked_execution_time,
                      blocked_query,
                      blocked_lock_mode,
                      blocking_pid,
                      (select usename from pg_stat_activity where pid = blocking_pid) as blocking_user,
                      (select left(query, 200) from pg_stat_activity where pid = blocking_pid) as blocking_query
                    from lock_chains
                    where blocking_pid is not null
                    order by blocked_execution_time desc
                    """
                )
                results["locked_sessions"] = cur.fetchall()

            # Generate recommendations based on findings
            if results["active_sessions"]:
                longest_active = max(results["active_sessions"], key=lambda x: (x["query_age"] or x["xact_age"] or timedelta(0)))
                results["recommendations"].append(
                    f"Longest active session: PID {longest_active['pid']} ({longest_active['user']}) running for {longest_active['query_age']}"
                )

            if results["idle_sessions"]:
                longest_idle = max(results["idle_sessions"], key=lambda x: x["idle_duration"])
                results["recommendations"].append(
                    f"Longest idle session: PID {longest_idle['pid']} ({longest_idle['user']}) idle for {longest_idle['idle_duration']}"
                )

            if results["locked_sessions"]:
                results["recommendations"].append(
                    f"Found {len(results['locked_sessions'])} sessions waiting on locks. Consider reviewing blocking sessions."
                )

            return results


@mcp.tool(tags={"public"})
def db_pg96_kill_session(pid: int) -> dict[str, Any]:
    """
    Terminates a database session by its process ID (PID).
    Requires MCP_ALLOW_WRITE=true.

    Args:
        pid: The process ID of the session to terminate.

    Returns:
        Dictionary indicating success or failure of the termination attempt.
    """
    if not ALLOW_WRITE:
        raise ValueError("Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable killing sessions.")

    with pool.connection() as conn:
        with conn.cursor() as cur:
            logger.info(f"Terminating session with PID: {pid}")
            _execute_safe(
                cur,
                "select pg_terminate_backend(%(pid)s) as terminated",
                {"pid": pid}
            )
            row = cur.fetchone()
            terminated = row["terminated"] if row else False
            return {
                "pid": pid,
                "terminated": terminated,
                "message": f"Session {pid} terminated." if terminated else f"Failed to terminate session {pid} or session not found."
            }




@mcp.tool(tags={"public"})
def db_pg96_server_info() -> dict[str, Any]:
    """
    Retrieves information about the current PostgreSQL server connection and version.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(
                cur,
                """
                select
                  current_database() as database,
                  current_user as user,
                  inet_server_addr()::text as server_addr,
                  inet_server_port() as server_port,
                  version() as version
                """
            )
            row = cur.fetchone()
            if row is None:
                raise RuntimeError("Failed to retrieve server info: database query returned no rows")
                
            db_name = ORIGINAL_DB_NAME if ORIGINAL_DB_NAME else row["database"]
            server_addr = ORIGINAL_DB_HOST if ORIGINAL_DB_HOST else row["server_addr"]
            server_port = ORIGINAL_DB_PORT if ORIGINAL_DB_PORT else row["server_port"]
            return {
                "database": db_name,
                "user": row["user"],
                "server_addr": server_addr,
                "server_port": server_port,
                "version": row["version"],
                "allow_write": ALLOW_WRITE,
                "default_max_rows": DEFAULT_MAX_ROWS,
                "statement_timeout_ms": STATEMENT_TIMEOUT_MS,
            }


@mcp.tool(tags={"public"})
def db_pg96_get_db_parameters(pattern: str | None = None) -> list[dict[str, Any]]:
    """
    Retrieves database configuration parameters (GUCs).

    Args:
        pattern: Optional regex pattern to filter parameter names (e.g., 'max_connections' or 'shared_.*').

    Returns:
        List of database parameters with their settings, units, and descriptions.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if pattern:
                _execute_safe(
                    cur,
                    """
                    select
                      name,
                      setting,
                      unit,
                      category,
                      short_desc,
                      context,
                      vartype,
                      min_val,
                      max_val,
                      enumvals,
                      boot_val,
                      reset_val,
                      pending_restart
                    from pg_settings
                    where name ~* %(pattern)s
                    order by name
                    """,
                    {"pattern": pattern},
                )
            else:
                _execute_safe(
                    cur,
                    """
                    select
                      name,
                      setting,
                      unit,
                      category,
                      short_desc,
                      context,
                      vartype,
                      min_val,
                      max_val,
                      enumvals,
                      boot_val,
                      reset_val,
                      pending_restart
                    from pg_settings
                    order by name
                    """
                )
            return cur.fetchall()


@mcp.tool(tags={"public"})
def db_pg96_list_objects(
    object_type: str,
    schema: str | None = None,
    owner: str | None = None,
    name_pattern: str | None = None,
    order_by: str | None = None,
    limit: int = 50,
    detail_level: str = "full",
    max_items: int | None = None,
    response_format: str = "legacy",
) -> list[dict[str, Any]] | dict[str, Any]:
    """
    Consolidated tool to list database objects with filtering and sorting options.

    Args:
        object_type: Type of objects to list.
                     Supported: 'database', 'schema', 'table', 'view', 'index', 'function', 'sequence', 'temp_object'.
        schema: Filter by schema name.
                For 'schema' type, it acts as an exact match filter.
                For tables/views/etc., it filters by parent schema.
        owner: Filter by object owner.
        name_pattern: Filter object name by pattern (ILIKE).
        order_by: Column to sort by. Defaults depend on object_type.
                  Common options: 'name', 'size'.
                  For tables: 'name', 'size', 'rows', 'dead_tuples', 'dead_ratio', 'vacuum', 'analyze'.
                  For indexes: 'name', 'size', 'scans'.
        limit: Maximum number of results (default: 50).

    Returns:
        List of objects with relevant details (name, schema, owner, size, stats, etc.).
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            params: dict[str, Any] = {"limit": limit}
            filters = []
            
            # Helper for name filtering
            if name_pattern:
                params['name_pattern'] = name_pattern
            if owner:
                params['owner'] = owner
            if schema:
                params['schema'] = schema

            query = ""
            sort_clause = ""
            group_by = ""

            if object_type == 'database':
                query = """
                    SELECT
                        d.datname as name,
                        pg_size_pretty(pg_database_size(d.datname)) as size_pretty,
                        pg_database_size(d.datname) as size_bytes,
                        d.datallowconn as allow_connections,
                        r.rolname as owner
                    FROM pg_database d
                    JOIN pg_roles r ON d.datdba = r.oid
                """
                if owner:
                    filters.append("r.rolname = %(owner)s")
                if name_pattern:
                    filters.append("d.datname ILIKE %(name_pattern)s")
                
                sort_clause = "ORDER BY pg_database_size(d.datname) DESC"
                if order_by == 'name':
                    sort_clause = "ORDER BY d.datname"
                elif order_by == 'size':
                    sort_clause = "ORDER BY pg_database_size(d.datname) DESC"

            elif object_type == 'schema':
                query = """
                    SELECT
                        n.nspname as name,
                        r.rolname as owner,
                        pg_size_pretty(sum(pg_total_relation_size(c.oid))) as size_pretty,
                        sum(pg_total_relation_size(c.oid)) as size_bytes
                    FROM pg_namespace n
                    JOIN pg_roles r ON n.nspowner = r.oid
                    LEFT JOIN pg_class c ON n.oid = c.relnamespace AND c.relkind IN ('r', 'm', 'p')
                """
                if owner:
                    filters.append("r.rolname = %(owner)s")
                if name_pattern:
                    filters.append("n.nspname ILIKE %(name_pattern)s")
                if schema:
                    filters.append("n.nspname = %(schema)s")
                else:
                    filters.append("n.nspname NOT LIKE 'pg_%%' AND n.nspname <> 'information_schema'")

                group_by = "GROUP BY n.nspname, r.rolname"
                sort_clause = "ORDER BY n.nspname"
                if order_by == 'size':
                    sort_clause = "ORDER BY sum(pg_total_relation_size(c.oid)) DESC"

            elif object_type == 'table':
                # Comprehensive table query with stats
                query = """
                    SELECT
                        n.nspname as schema,
                        c.relname as name,
                        r.rolname as owner,
                        pg_size_pretty(pg_total_relation_size(c.oid)) as size_pretty,
                        pg_total_relation_size(c.oid) as size_bytes,
                        pg_size_pretty(pg_relation_size(c.oid)) as table_size_pretty,
                        pg_size_pretty(pg_total_relation_size(c.oid) - pg_relation_size(c.oid)) as index_size_pretty,
                        c.reltuples::bigint as estimated_rows,
                        st.n_live_tup as live_rows,
                        st.n_dead_tup as dead_rows,
                        round((st.n_dead_tup::numeric / greatest(st.n_live_tup + st.n_dead_tup, 1)::numeric) * 100, 2) as dead_ratio,
                        st.last_vacuum,
                        st.last_autovacuum,
                        st.last_analyze,
                        st.last_autoanalyze,
                        COALESCE(st.vacuum_count, 0) + COALESCE(st.autovacuum_count, 0) as total_vacuums,
                        COALESCE(st.analyze_count, 0) + COALESCE(st.autoanalyze_count, 0) as total_analyzes
                    FROM pg_class c
                    JOIN pg_namespace n ON c.relnamespace = n.oid
                    JOIN pg_roles r ON c.relowner = r.oid
                    LEFT JOIN pg_stat_user_tables st ON c.oid = st.relid
                """
                filters.append("c.relkind = 'r'")
                if name_pattern:
                    filters.append("c.relname ILIKE %(name_pattern)s")
                if schema:
                    filters.append("n.nspname = %(schema)s")
                else:
                    filters.append("n.nspname NOT IN ('pg_catalog', 'information_schema')")
                if owner:
                    filters.append("r.rolname = %(owner)s")

                sort_clause = "ORDER BY 1, 2" # schema, name
                if order_by == 'size':
                    sort_clause = "ORDER BY pg_total_relation_size(c.oid) DESC"
                elif order_by == 'rows':
                    sort_clause = "ORDER BY c.reltuples DESC"
                elif order_by == 'dead_tuples':
                    sort_clause = "ORDER BY st.n_dead_tup DESC NULLS LAST"
                elif order_by == 'dead_ratio':
                    sort_clause = "ORDER BY 11 DESC NULLS LAST" # dead_ratio column index (approx) - actually safer to use column alias in some PGs but numeric index is standard
                elif order_by == 'vacuum':
                    sort_clause = "ORDER BY GREATEST(st.last_vacuum, st.last_autovacuum) DESC NULLS LAST"
                elif order_by == 'analyze':
                    sort_clause = "ORDER BY GREATEST(st.last_analyze, st.last_autoanalyze) DESC NULLS LAST"

            elif object_type == 'index':
                query = """
                    SELECT
                        n.nspname as schema,
                        t.relname as table,
                        c.relname as name,
                        r.rolname as owner,
                        pg_size_pretty(pg_relation_size(c.oid)) as size_pretty,
                        pg_relation_size(c.oid) as size_bytes,
                        si.idx_scan as scans,
                        si.idx_tup_read as tuples_read,
                        si.idx_tup_fetch as tuples_fetched
                    FROM pg_class c
                    JOIN pg_namespace n ON c.relnamespace = n.oid
                    JOIN pg_roles r ON c.relowner = r.oid
                    JOIN pg_index i ON c.oid = i.indexrelid
                    JOIN pg_class t ON i.indrelid = t.oid
                    LEFT JOIN pg_stat_user_indexes si ON c.oid = si.indexrelid
                """
                filters.append("c.relkind = 'i'")
                if name_pattern:
                    filters.append("c.relname ILIKE %(name_pattern)s")
                if schema:
                    filters.append("n.nspname = %(schema)s")
                else:
                    filters.append("n.nspname NOT IN ('pg_catalog', 'information_schema')")
                if owner:
                    filters.append("r.rolname = %(owner)s")

                sort_clause = "ORDER BY 1, 2, 3" # schema, table, name
                if order_by == 'size':
                    sort_clause = "ORDER BY pg_relation_size(c.oid) DESC"
                elif order_by == 'scans' or order_by == 'usage':
                    sort_clause = "ORDER BY si.idx_scan DESC NULLS LAST"

            elif object_type == 'view':
                 query = """
                    SELECT
                        n.nspname as schema,
                        c.relname as name,
                        r.rolname as owner,
                        pg_size_pretty(pg_total_relation_size(c.oid)) as size_pretty,
                        pg_total_relation_size(c.oid) as size_bytes
                    FROM pg_class c
                    JOIN pg_namespace n ON c.relnamespace = n.oid
                    JOIN pg_roles r ON c.relowner = r.oid
                """
                 filters.append("c.relkind = 'v'")
                 if name_pattern:
                    filters.append("c.relname ILIKE %(name_pattern)s")
                 if schema:
                    filters.append("n.nspname = %(schema)s")
                 else:
                    filters.append("n.nspname NOT IN ('pg_catalog', 'information_schema')")
                 if owner:
                    filters.append("r.rolname = %(owner)s")
                 sort_clause = "ORDER BY 1, 2"

            elif object_type == 'sequence':
                 query = """
                    SELECT
                        n.nspname as schema,
                        c.relname as name,
                        r.rolname as owner
                    FROM pg_class c
                    JOIN pg_namespace n ON c.relnamespace = n.oid
                    JOIN pg_roles r ON c.relowner = r.oid
                """
                 filters.append("c.relkind = 'S'")
                 if name_pattern:
                    filters.append("c.relname ILIKE %(name_pattern)s")
                 if schema:
                    filters.append("n.nspname = %(schema)s")
                 else:
                    filters.append("n.nspname NOT IN ('pg_catalog', 'information_schema')")
                 if owner:
                    filters.append("r.rolname = %(owner)s")
                 sort_clause = "ORDER BY 1, 2"

            elif object_type == 'function':
                     query = """
                        SELECT
                            n.nspname as schema,
                            p.proname as name,
                            pg_get_function_result(p.oid) as result_type,
                            pg_get_function_arguments(p.oid) as arguments,
                            r.rolname as owner
                        FROM pg_proc p
                        JOIN pg_namespace n ON p.pronamespace = n.oid
                        JOIN pg_roles r ON p.proowner = r.oid
                     """
                     if name_pattern:
                        filters.append("p.proname ILIKE %(name_pattern)s")
                     if schema:
                        filters.append("n.nspname = %(schema)s")
                     else:
                        filters.append("n.nspname NOT IN ('pg_catalog', 'information_schema')")
                     if owner:
                        filters.append("r.rolname = %(owner)s")
                     
                     sort_clause = "ORDER BY 1, 2"

            elif object_type == 'temp_object':
                 query = """
                    SELECT
                      n.nspname as schema,
                      count(*) as object_count,
                      pg_size_pretty(sum(pg_total_relation_size(c.oid))) as total_size
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                 """
                 filters.append("n.nspname LIKE 'pg_temp%%'")
                 group_by = "GROUP BY n.nspname"
                 sort_clause = "ORDER BY sum(pg_total_relation_size(c.oid)) DESC"

            else:
                 return [{"error": f"Unsupported object_type: {object_type}"}]

            where_clause = "WHERE " + " AND ".join(filters) if filters else ""
            full_sql = f"{query} {where_clause} {group_by} {sort_clause} LIMIT %(limit)s"
            
            _execute_safe(cur, full_sql, params)
            rows = cur.fetchall()

            detail = (detail_level or "full").lower()
            if detail not in {"full", "compact"}:
                raise ValueError("detail_level must be 'full' or 'compact'")

            max_rows = max_items if max_items is not None else limit
            trimmed_rows, rows_truncated = _trim_list(rows, max_rows)

            if detail == "compact":
                compact_map: dict[str, list[str]] = {
                    "database": ["name", "size_pretty", "owner"],
                    "schema": ["name", "owner", "size_pretty"],
                    "table": ["schema", "name", "size_pretty", "estimated_rows", "dead_ratio"],
                    "index": ["schema", "table", "name", "size_pretty", "scans"],
                    "view": ["schema", "name", "size_pretty"],
                    "sequence": ["schema", "name", "owner"],
                    "function": ["schema", "name", "arguments", "result_type"],
                    "temp_object": ["schema", "object_count", "total_size"],
                }
                keep_fields = compact_map.get(object_type, [])
                if keep_fields:
                    trimmed_rows = [
                        {k: row.get(k) for k in keep_fields if k in row}
                        for row in trimmed_rows
                    ]

            if response_format == "legacy":
                return trimmed_rows
            if response_format != "envelope":
                raise ValueError("response_format must be 'legacy' or 'envelope'")

            return _build_response_envelope(
                tool="db_pg96_list_objects",
                payload=trimmed_rows,
                summary={
                    "object_type": object_type,
                    "detail_level": detail,
                    "returned": len(trimmed_rows),
                    "limit_requested": limit,
                },
                truncated=rows_truncated,
                hints_for_next_call=[
                    "Increase max_items to inspect more results.",
                    "Use detail_level='full' for all object fields.",
                ],
            )




@mcp.tool(tags={"public"})
def db_pg96_analyze_indexes(
    schema: str | None = None,
    limit: int = 50,
    detail_level: str = "full",
    max_items_per_category: int | None = None,
    response_format: str = "legacy",
) -> dict[str, Any]:
    """
    Identify unused and duplicate indexes.
    
    Args:
        schema: Optional schema name to filter.
        limit: Maximum number of rows to return for each category.

    Returns:
        Dictionary containing lists of unused, duplicate, missing, and redundant indexes.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            results: dict[str, Any] = {
                "unused_indexes": [],
                "duplicate_indexes": [],
                "missing_indexes": [],
                "redundant_indexes": []
            }

            # 1. Unused Indexes
            _execute_safe(
                cur,
                """
                select
                  schemaname as schema,
                  relname as table,
                  indexrelname as index,
                  pg_size_pretty(pg_relation_size(i.indexrelid)) as size,
                  idx_scan as scans
                from pg_stat_user_indexes i
                join pg_index using (indexrelid)
                where schemaname not in ('pg_catalog', 'information_schema')
                  and (%(schema)s::text is null or schemaname = %(schema)s::text)
                  and indisunique = false
                  and idx_scan = 0
                order by pg_relation_size(i.indexrelid) desc
                limit %(limit)s
                """,
                {"schema": schema, "limit": limit}
            )
            results["unused_indexes"] = cur.fetchall()

            # 2. Duplicate Indexes
            _execute_safe(
                cur,
                """
                select
                  n.nspname as schema,
                  t.relname as table,
                  (select array_agg(a.attname) from pg_attribute a where a.attrelid = t.oid and a.attnum = any(idx.indkey)) as columns,
                  array_agg(i.relname) as indexes,
                  count(*) as dup_count
                from pg_index idx
                join pg_class t on t.oid = idx.indrelid
                join pg_class i on i.oid = idx.indexrelid
                join pg_namespace n on n.oid = t.relnamespace
                where n.nspname not in ('pg_catalog', 'information_schema')
                  and (%(schema)s::text is null or n.nspname = %(schema)s::text)
                group by n.nspname, t.relname, t.oid, idx.indkey
                having count(*) > 1
                limit %(limit)s
                """,
                {"schema": schema, "limit": limit}
            )
            results["duplicate_indexes"] = cur.fetchall()
            results["missing_indexes"] = []
            results["redundant_indexes"] = []

            detail = (detail_level or "full").lower()
            if detail not in {"full", "compact"}:
                raise ValueError("detail_level must be 'full' or 'compact'")

            list_cap = max_items_per_category if max_items_per_category is not None else limit
            truncated = False

            for key in ("unused_indexes", "duplicate_indexes", "missing_indexes", "redundant_indexes"):
                trimmed, was_truncated = _trim_list(results.get(key, []), list_cap)
                truncated = truncated or was_truncated
                if detail == "compact":
                    compact_rows = []
                    for row in trimmed:
                        if key == "unused_indexes":
                            compact_rows.append(
                                {
                                    "schema": row.get("schema"),
                                    "table": row.get("table"),
                                    "index": row.get("index"),
                                    "size": row.get("size"),
                                    "scans": row.get("scans"),
                                }
                            )
                        elif key == "duplicate_indexes":
                            compact_rows.append(
                                {
                                    "schema": row.get("schema"),
                                    "table": row.get("table"),
                                    "dup_count": row.get("dup_count"),
                                    "indexes": row.get("indexes"),
                                }
                            )
                        else:
                            compact_rows.append(row)
                    results[key] = compact_rows
                else:
                    results[key] = trimmed

            if response_format == "legacy":
                results["_meta"] = {
                    "detail_level": detail,
                    "max_items_per_category": list_cap,
                    "truncated": truncated,
                }
                return results
            if response_format != "envelope":
                raise ValueError("response_format must be 'legacy' or 'envelope'")

            return _build_response_envelope(
                tool="db_pg96_analyze_indexes",
                payload=results,
                summary={
                    "detail_level": detail,
                    "unused_indexes": len(results.get("unused_indexes", [])),
                    "duplicate_indexes": len(results.get("duplicate_indexes", [])),
                },
                truncated=truncated,
                hints_for_next_call=[
                    "Increase max_items_per_category to inspect more index entries.",
                    "Use detail_level='full' for complete rows.",
                ],
            )


@mcp.tool(tags={"public"})
def db_pg96_analyze_logical_data_model(
    schema: str = "public",
    include_views: bool = False,
    max_entities: Optional[int] = None,
    include_attributes: bool = True,
    detail_level: str = "full",
    response_format: str = "legacy",
) -> dict[str, Any]:
    """
    Generate a logical data model (LDM) for a schema and produce issues and recommendations.

    The model includes entities (tables), attributes (columns), identifiers (PK/UK), and relationships (FK).

    Args:
        schema: Schema to analyze (default: "public").
        include_views: Include views/materialized views as entities (default: False).
        max_entities: Maximum number of entities to include (default: 200).
        include_attributes: Include full attribute details (default: True).

    Returns:
        Dictionary containing logical model, issues, and recommendations.
    """
    def _snake_case(name: str) -> bool:
        return bool(re.match(r"^[a-z][a-z0-9_]*$", name))

    def _action(code: str) -> str:
        mapping = {
            "a": "NO ACTION",
            "r": "RESTRICT",
            "c": "CASCADE",
            "n": "SET NULL",
            "d": "SET DEFAULT",
        }
        return mapping.get(code, code)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(cur, "select now() at time zone 'utc' as generated_at_utc")
            generated_at_row = cur.fetchone() or {}
            generated_at = generated_at_row.get("generated_at_utc")
            generated_at_iso = generated_at.isoformat() if isinstance(generated_at, (datetime, date)) else str(generated_at)

            relkinds = ["r", "p"]
            if include_views:
                relkinds.extend(["v", "m"])

            _execute_safe(
                cur,
                """
                select
                  c.oid,
                  n.nspname as schema,
                  c.relname as name,
                  c.relkind
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where n.nspname = %(schema)s
                  and c.relkind = any(%(relkinds)s)
                order by c.relname
                """,
                {"schema": schema, "relkinds": relkinds},
            )
            table_rows = cur.fetchall()
            table_rows = table_rows[:max_entities] if max_entities and max_entities > 0 else table_rows
            table_names = [r["name"] for r in table_rows]

            columns_by_table: dict[str, list[dict[str, Any]]] = {}
            if include_attributes and table_names:
                _execute_safe(
                    cur,
                    """
                    select
                      table_name,
                      column_name,
                      ordinal_position,
                      is_nullable,
                      data_type,
                      udt_name,
                      character_maximum_length,
                      numeric_precision,
                      numeric_scale,
                      column_default
                    from information_schema.columns
                    where table_schema = %(schema)s
                      and table_name = any(%(tables)s)
                    order by table_name, ordinal_position
                    """,
                    {"schema": schema, "tables": table_names},
                )
                for row in cur.fetchall():
                    t = row["table_name"]
                    columns_by_table.setdefault(t, []).append({
                        "name": row["column_name"],
                        "position": row["ordinal_position"],
                        "data_type": row["data_type"],
                        "udt_name": row["udt_name"],
                        "nullable": (row["is_nullable"] == "YES"),
                        "max_length": row["character_maximum_length"],
                        "numeric_precision": row["numeric_precision"],
                        "numeric_scale": row["numeric_scale"],
                        "default": row["column_default"],
                    })

            _execute_safe(
                cur,
                """
                select
                  n.nspname as schema,
                  c.relname as table,
                  con.conname as name,
                  con.contype as type,
                  array_agg(att.attname order by ck.ord) as columns
                from pg_constraint con
                join pg_class c on c.oid = con.conrelid
                join pg_namespace n on n.oid = c.relnamespace
                join unnest(con.conkey) with ordinality as ck(attnum, ord) on true
                join pg_attribute att on att.attrelid = c.oid and att.attnum = ck.attnum
                where n.nspname = %(schema)s
                  and c.relname = any(%(tables)s)
                  and con.contype in ('p', 'u')
                group by n.nspname, c.relname, con.conname, con.contype
                """,
                {"schema": schema, "tables": table_names},
            )
            pk_by_table: dict[str, list[str]] = {}
            uniques_by_table: dict[str, list[list[str]]] = {}
            for row in cur.fetchall():
                if row["type"] == "p":
                    pk_by_table[row["table"]] = row["columns"]
                else:
                    uniques_by_table.setdefault(row["table"], []).append(row["columns"])

            _execute_safe(
                cur,
                """
                select
                  n.nspname as schema,
                  c.relname as table,
                  con.conname as name,
                  array_agg(att.attname order by l.ord) as local_columns,
                  rn.nspname as ref_schema,
                  rc.relname as ref_table,
                  array_agg(ratt.attname order by l.ord) as ref_columns,
                  con.confupdtype as on_update,
                  con.confdeltype as on_delete
                from pg_constraint con
                join pg_class c on c.oid = con.conrelid
                join pg_namespace n on n.oid = c.relnamespace
                join pg_class rc on rc.oid = con.confrelid
                join pg_namespace rn on rn.oid = rc.relnamespace
                join unnest(con.conkey) with ordinality as l(attnum, ord) on true
                join unnest(con.confkey) with ordinality as r(attnum, ord) on r.ord = l.ord
                join pg_attribute att on att.attrelid = c.oid and att.attnum = l.attnum
                join pg_attribute ratt on ratt.attrelid = rc.oid and ratt.attnum = r.attnum
                where n.nspname = %(schema)s
                  and c.relname = any(%(tables)s)
                  and con.contype = 'f'
                group by n.nspname, c.relname, con.conname, rn.nspname, rc.relname, con.confupdtype, con.confdeltype
                order by c.relname, con.conname
                """,
                {"schema": schema, "tables": table_names},
            )
            fk_rows = cur.fetchall()

            _execute_safe(
                cur,
                """
                select
                  n.nspname as schema,
                  t.relname as table,
                  i.relname as index,
                  ix.indisunique as is_unique,
                  ix.indisprimary as is_primary,
                  array_agg(case when k.attnum > 0 then a.attname else null end order by k.ord) as columns
                from pg_index ix
                join pg_class i on i.oid = ix.indexrelid
                join pg_class t on t.oid = ix.indrelid
                join pg_namespace n on n.oid = t.relnamespace
                join unnest(ix.indkey) with ordinality as k(attnum, ord) on true
                left join pg_attribute a on a.attrelid = t.oid and a.attnum = k.attnum
                where n.nspname = %(schema)s
                  and t.relname = any(%(tables)s)
                group by n.nspname, t.relname, i.relname, ix.indisunique, ix.indisprimary
                order by t.relname, i.relname
                """,
                {"schema": schema, "tables": table_names},
            )
            indexes_by_table: dict[str, list[dict[str, Any]]] = {}
            for row in cur.fetchall():
                cols_raw = row["columns"] or []
                cols = [c for c in cols_raw if c is not None]
                indexes_by_table.setdefault(row["table"], []).append({
                    "name": row["index"],
                    "columns": cols,
                    "is_unique": bool(row["is_unique"]),
                    "is_primary": bool(row["is_primary"]),
                })

            entity_map: dict[str, dict[str, Any]] = {}
            issues = {
                "entities": [],
                "attributes": [],
                "relationships": [],
                "identifiers": [],
                "normalization": [],
            }
            recommendations = {
                "entities": [],
                "attributes": [],
                "relationships": [],
                "identifiers": [],
                "normalization": [],
            }

            for t in table_rows:
                table_name = t["name"]
                attrs = columns_by_table.get(table_name, [])
                pk_cols = pk_by_table.get(table_name, [])
                uniqs = uniques_by_table.get(table_name, [])
                fks: list[dict[str, Any]] = []

                col_nullable: dict[str, bool] = {a["name"]: bool(a.get("nullable")) for a in attrs}
                col_types: dict[str, str] = {a["name"]: str(a.get("data_type") or "") for a in attrs}
                col_udt: dict[str, str] = {a["name"]: str(a.get("udt_name") or "") for a in attrs}

                for fk in fk_rows:
                    if fk["table"] != table_name:
                        continue
                    local_cols = fk["local_columns"] or []
                    optional = any(col_nullable.get(c, False) for c in local_cols)
                    fks.append({
                        "name": fk["name"],
                        "local_columns": local_cols,
                        "ref_schema": fk["ref_schema"],
                        "ref_table": fk["ref_table"],
                        "ref_columns": fk["ref_columns"] or [],
                        "on_update": _action(fk["on_update"]),
                        "on_delete": _action(fk["on_delete"]),
                        "optional": optional,
                    })

                if not _snake_case(table_name):
                    issues["entities"].append({
                        "entity": f"{schema}.{table_name}",
                        "issue": "Non-snake_case entity name",
                    })
                    recommendations["entities"].append({
                        "entity": f"{schema}.{table_name}",
                        "recommendation": "Standardize entity naming to snake_case for consistency.",
                    })

                if not pk_cols and t["relkind"] in ("r", "p"):
                    issues["identifiers"].append({
                        "entity": f"{schema}.{table_name}",
                        "issue": "Missing primary key",
                    })
                    recommendations["identifiers"].append({
                        "entity": f"{schema}.{table_name}",
                        "recommendation": "Add a primary key to support entity identity, replication, and FK references.",
                    })

                if len(pk_cols) > 1 and len(attrs) > len(pk_cols):
                    issues["normalization"].append({
                        "entity": f"{schema}.{table_name}",
                        "issue": "Composite primary key with non-key attributes requires 2NF review",
                        "details": {"primary_key": pk_cols},
                    })
                    recommendations["normalization"].append({
                        "entity": f"{schema}.{table_name}",
                        "recommendation": "Review for partial dependencies; consider surrogate key if appropriate.",
                    })

                if include_attributes:
                    for a in attrs:
                        col = a["name"]
                        if not _snake_case(col):
                            issues["attributes"].append({
                                "entity": f"{schema}.{table_name}",
                                "attribute": col,
                                "issue": "Non-snake_case attribute name",
                            })
                            recommendations["attributes"].append({
                                "entity": f"{schema}.{table_name}",
                                "attribute": col,
                                "recommendation": "Standardize attribute naming to snake_case for consistency.",
                            })

                        udt = col_udt.get(col, "")
                        dt = col_types.get(col, "")
                        is_array = (dt.upper() == "ARRAY") or udt.startswith("_")
                        is_json = dt in ("json", "jsonb") or udt in ("json", "jsonb")
                        if is_array or is_json:
                            issues["normalization"].append({
                                "entity": f"{schema}.{table_name}",
                                "attribute": col,
                                "issue": "Potential denormalization / non-1NF attribute type",
                                "details": {"data_type": dt, "udt_name": udt},
                            })
                            recommendations["normalization"].append({
                                "entity": f"{schema}.{table_name}",
                                "attribute": col,
                                "recommendation": "Review whether this should be modeled as a related entity (child table) or reference data.",
                            })

                fk_indexes = indexes_by_table.get(table_name, [])
                for fk in fks:
                    local_cols = fk["local_columns"]
                    if not local_cols:
                        continue
                    indexed = any(idx.get("columns", [])[:len(local_cols)] == local_cols for idx in fk_indexes)
                    if not indexed:
                        issues["relationships"].append({
                            "entity": f"{schema}.{table_name}",
                            "relationship": fk["name"],
                            "issue": "Foreign key columns are not covered by a leading index",
                            "details": {"columns": local_cols},
                        })
                        recommendations["relationships"].append({
                            "entity": f"{schema}.{table_name}",
                            "relationship": fk["name"],
                            "recommendation": f"Create an index on ({', '.join(local_cols)}) to improve join performance and FK maintenance.",
                        })

                col_names = [a["name"] for a in attrs]
                repeated_groups = {}
                for c in col_names:
                    m = re.match(r"^(.*)_(\d+)$", c)
                    if m:
                        base = m.group(1)
                        repeated_groups.setdefault(base, 0)
                        repeated_groups[base] += 1
                for base, count in repeated_groups.items():
                    if count >= 2:
                        issues["normalization"].append({
                            "entity": f"{schema}.{table_name}",
                            "issue": "Potential repeating group pattern in attributes",
                            "details": {"base": base, "count": count},
                        })
                        recommendations["normalization"].append({
                            "entity": f"{schema}.{table_name}",
                            "recommendation": "Consider normalizing repeating groups into a child entity with one row per repeated value.",
                        })

                for c in col_names:
                    if c.endswith("_id"):
                        base = c[:-3]
                        if f"{base}_name" in col_names or f"{base}_code" in col_names:
                            issues["normalization"].append({
                                "entity": f"{schema}.{table_name}",
                                "issue": "Potential transitive dependency / duplicated reference data",
                                "details": {"id_column": c},
                            })
                            recommendations["normalization"].append({
                                "entity": f"{schema}.{table_name}",
                                "recommendation": f"Consider storing only {c} and retrieving related descriptive attributes via relationship joins.",
                            })

                entity_map[table_name] = {
                    "schema": schema,
                    "name": table_name,
                    "kind": t["relkind"],
                    "attributes": attrs if include_attributes else [],
                    "primary_key": pk_cols,
                    "unique_constraints": uniqs,
                    "foreign_keys": fks,
                }

            relationships: list[dict[str, Any]] = []
            for fk in fk_rows:
                relationships.append({
                    "name": fk["name"],
                    "from_entity": f"{schema}.{fk['table']}",
                    "to_entity": f"{fk['ref_schema']}.{fk['ref_table']}",
                    "local_columns": fk["local_columns"] or [],
                    "ref_columns": fk["ref_columns"] or [],
                    "on_update": _action(fk["on_update"]),
                    "on_delete": _action(fk["on_delete"]),
                })

            summary = {
                "schema": schema,
                "generated_at_utc": generated_at_iso,
                "entities": len(entity_map),
                "relationships": len(relationships),
                "issues_count": {k: len(v) for k, v in issues.items()},
            }

            detail = (detail_level or "full").lower()
            if detail not in {"full", "compact"}:
                raise ValueError("detail_level must be 'full' or 'compact'")

            result_data = {
                "summary": summary,
                "logical_model": {
                    "entities": list(entity_map.values()),
                    "relationships": relationships,
                },
                "issues": issues,
                "recommendations": recommendations,
            }

            compact_preview = {
                "entities": [
                    {
                        "schema": e.get("schema"),
                        "name": e.get("name"),
                        "kind": e.get("kind"),
                        "attributes_count": len(e.get("attributes", [])),
                        "primary_key": e.get("primary_key", []),
                        "foreign_keys_count": len(e.get("foreign_keys", [])),
                    }
                    for e in result_data["logical_model"]["entities"][:20]
                ],
                "relationships": [
                    {
                        "name": r.get("name"),
                        "from_entity": r.get("from_entity"),
                        "to_entity": r.get("to_entity"),
                    }
                    for r in result_data["logical_model"]["relationships"][:20]
                ],
                "issues_sample": {k: v[:10] for k, v in issues.items()},
                "recommendations_sample": {k: v[:10] for k, v in recommendations.items()},
            }
            
            # Cache the result
            analysis_id = str(uuid.uuid4())
            DATA_MODEL_CACHE[analysis_id] = result_data
            
            # Construct URL
            # Use MCP_PORT if set, otherwise default to 8085 for UI to avoid 8000 conflicts
            port = os.environ.get("MCP_PORT", "8085")
            host = os.environ.get("MCP_HOST", "localhost")
            if host == "0.0.0.0":
                host = "localhost"
            
            url = f"http://{host}:{port}/data-model-analysis?id={analysis_id}"
            
            legacy_response = {
                "message": "Analysis complete. View the interactive report at the URL below.",
                "report_url": url,
                "summary": summary
            }

            if response_format == "legacy":
                legacy_response["_meta"] = {
                    "detail_level": detail,
                    "analysis_id": analysis_id,
                }
                return legacy_response
            if response_format != "envelope":
                raise ValueError("response_format must be 'legacy' or 'envelope'")

            return _build_response_envelope(
                tool="db_pg96_analyze_logical_data_model",
                payload={
                    "message": legacy_response["message"],
                    "report_url": legacy_response["report_url"],
                    "summary": summary,
                    "analysis_id": analysis_id,
                    "preview": compact_preview if detail == "compact" else None,
                },
                summary={
                    "detail_level": detail,
                    "entities": summary.get("entities"),
                    "relationships": summary.get("relationships"),
                },
                truncated=(detail == "compact"),
                hints_for_next_call=[
                    "Open report_url for full interactive analysis details.",
                    "Use detail_level='compact' for lightweight preview fields.",
                ],
            )






@mcp.tool(tags={"public"})
def db_pg96_describe_table(schema: str, table: str) -> dict[str, Any]:
    """
    Get detailed information about a table's structure, including columns, indexes, and size.

    Args:
        schema: The schema the table belongs to.
        table: The name of the table to describe.

    Returns:
        Dictionary containing schema, table name, columns, indexes, sizes, and approximate row count.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(
                cur,
                """
                select
                  c.ordinal_position,
                  c.column_name,
                  c.data_type,
                  c.is_nullable,
                  c.column_default
                from information_schema.columns c
                where c.table_schema = %(schema)s
                  and c.table_name = %(table)s
                order by c.ordinal_position
                """,
                {"schema": schema, "table": table},
            )
            columns = cur.fetchall()

            _execute_safe(
                cur,
                """
                select
                  i.indexname as index_name,
                  i.indexdef as index_def
                from pg_indexes i
                where i.schemaname = %(schema)s
                  and i.tablename = %(table)s
                order by i.indexname
                """,
                {"schema": schema, "table": table},
            )
            indexes = cur.fetchall()

            _execute_safe(
                cur,
                """
                select
                  pg_total_relation_size(format('%%I.%%I', %(schema)s::text, %(table)s::text)) as total_size_bytes,
                  pg_relation_size(format('%%I.%%I', %(schema)s::text, %(table)s::text)) as heap_size_bytes
                """,
                {"schema": schema, "table": table},
            )
            size_row = cur.fetchone()

            _execute_safe(
                cur,
                """
                select
                  reltuples::bigint as approx_rows
                from pg_class
                where oid = format('%%I.%%I', %(schema)s::text, %(table)s::text)::regclass
                """,
                {"schema": schema, "table": table},
            )
            approx = cur.fetchone()

            return {
                "schema": schema,
                "table": table,
                "columns": columns,
                "indexes": indexes,
                "total_size_bytes": size_row["total_size_bytes"] if size_row else None,
                "heap_size_bytes": size_row["heap_size_bytes"] if size_row else None,
                "approx_rows": approx["approx_rows"] if approx else None,
            }


@mcp.tool(tags={"public"})
def db_pg96_run_query(
    sql: str,
    params_json: str | None = None,
    max_rows: int | None = None,
    source_prompt: str | None = None,
) -> dict[str, Any]:
    """
    Execute a read-only SQL query against the database.

    Note:
        This tool attempts to enforce read-only execution by analyzing the SQL string.
        Complex queries or obfuscation might bypass this check. 
        Always operate with a user that has restricted permissions at the database level.

    Args:
        sql: The SQL query to execute.
        params_json: Optional JSON string of parameters to bind to the query.
        max_rows: Maximum number of rows to return (default: 500).

    Returns:
        Dictionary containing columns, rows, and truncation status.
    """
    _require_readonly(sql)
    limit = max_rows if max_rows is not None else DEFAULT_MAX_ROWS
    if limit < 0:
        raise ValueError("max_rows must be >= 0")
    sql_fingerprint = hashlib.sha256(sql.encode("utf-8")).hexdigest()
    params_fingerprint = (
        hashlib.sha256(params_json.encode("utf-8")).hexdigest() if params_json is not None else None
    )
    logger.info(f"run_query called. sql_len={len(sql)} max_rows={limit} sql_sha256={sql_fingerprint}")
    logger.debug(f"run_query params_sha256={params_fingerprint}")
    _write_audit_event(
        tool_name="db_pg96_run_query",
        sql_text=sql,
        source_prompt=source_prompt,
        params_json=params_json,
    )
    params: dict[str, Any] | None = None
    if params_json:
        params = json.loads(params_json)
        if not isinstance(params, dict):
            raise ValueError("params_json must decode to a JSON object")

    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(cur, sql, params)
            rows_plus_one = _fetch_limited(cur, limit + 1 if limit >= 0 else 1)
            truncated = len(rows_plus_one) > limit
            rows = rows_plus_one[:limit]
            if cur.description:
                first = cur.description[0]
                columns = (
                    [d.name for d in cur.description]
                    if hasattr(first, "name")
                    else [d[0] for d in cur.description]
                )
            else:
                columns = []
            return {
                "columns": columns,
                "rows": rows,
                "returned_rows": len(rows),
                "truncated": truncated,
            }


@mcp.tool(tags={"public"})
def db_pg96_explain_query(
    sql: str,
    analyze: bool = False,
    buffers: bool = False,
    verbose: bool = False,
    settings: bool = False,
    output_format: str = "json",
    source_prompt: str | None = None,
) -> dict[str, Any]:
    """
    Get the execution plan for a query.

    Args:
        sql: The SQL query to explain.
        analyze: If True, executes the query to get actual runtimes (default: False).
        buffers: If True, includes buffer usage (requires analyze=True).
        verbose: If True, includes detailed information.
        settings: If True, includes configuration options.
        output_format: Output format, either 'json' or 'text' (default: 'json').

    Returns:
        Dictionary containing the plan format and the plan content (json or text).
    """
    sql_fingerprint = hashlib.sha256(sql.encode("utf-8")).hexdigest()
    logger.info(
        f"explain_query called. output_format={output_format.strip().lower()} analyze={analyze} buffers={buffers} "
        f"verbose={verbose} settings={settings} sql_len={len(sql)} sql_sha256={sql_fingerprint}"
    )
    _write_audit_event(
        tool_name="db_pg96_explain_query",
        sql_text=sql,
        source_prompt=source_prompt,
    )
    _require_readonly(sql)
    fmt = output_format.strip().lower()
    if fmt not in {"json", "text"}:
        raise ValueError("output_format must be 'json' or 'text'")

    opts: list[str] = []
    if analyze:
        opts.append("ANALYZE")
    if buffers:
        opts.append("BUFFERS")
    if verbose:
        opts.append("VERBOSE")
    if settings:
        opts.append("SETTINGS")
    opts.append(f"FORMAT {fmt.upper()}")
    stmt = f"EXPLAIN ({', '.join(opts)}) {sql}"

    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(cur, stmt)
            rows = cur.fetchall()
            if fmt == "json":
                plan = rows[0]["QUERY PLAN"] if rows else None
                return {"format": "json", "plan": plan}
            text = "\n".join(r["QUERY PLAN"] for r in rows)
            return {"format": "text", "plan": text}


@mcp.tool(tags={"public"})
def db_pg96_ping() -> dict[str, Any]:
    """
    Check if the MCP server is responsive.

    Returns:
        Dictionary with "ok": True if the server is responsive.
    """
    return {"ok": True}


@mcp.tool(tags={"public"})
def db_pg96_server_info_mcp() -> dict[str, Any]:
    """
    Get information about the MCP server configuration and status.

    Returns:
        Dictionary containing server name, version, status, transport type, and connected database name.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(
                cur,
                """
                select current_database() as database
                """
            )
            row = cur.fetchone()
            database_name = row["database"] if row and "database" in row else "unknown"
    return {
        "name": mcp.name,
        "version": "1.0.0",
        "status": "healthy",
        "transport": os.environ.get("MCP_TRANSPORT", "http"),
        "database": ORIGINAL_DB_NAME or database_name
    }


def _configure_fastmcp_runtime() -> None:
    cert_file = os.environ.get("SSL_CERT_FILE")
    if cert_file and not os.path.exists(cert_file):
        os.environ.pop("SSL_CERT_FILE", None)
    try:
        import fastmcp

        fastmcp.settings.check_for_updates = "off"
    except Exception:
        pass


DATA_MODEL_CACHE = {}

DATA_MODEL_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Data Model Analysis</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/svg-pan-zoom@3.6.1/dist/svg-pan-zoom.min.js"></script>
    <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        mermaid.initialize({ startOnLoad: false, theme: 'default', maxTextSize: 1000000 });
        window.mermaid = mermaid;
    </script>
    <style>
        .mermaid { background: white; }
    </style>
</head>
<body class="bg-gray-100 min-h-screen p-4 md:p-8">
    <div class="max-w-7xl mx-auto bg-white shadow-xl rounded-lg overflow-hidden">
        <!-- Header -->
        <div class="bg-indigo-600 p-6 text-white">
            <h1 class="text-3xl font-bold">Logical Data Model Analysis</h1>
            <div class="mt-2 flex items-center text-indigo-100 text-sm">
                <span id="schemaName" class="font-mono bg-indigo-700 px-2 py-1 rounded mr-4">schema: public</span>
                <span id="generatedAt">Generated at: ...</span>
            </div>
        </div>

        <!-- Summary Stats -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-0 border-b border-gray-200">
            <div class="p-6 border-r border-gray-200 text-center hover:bg-gray-50 transition">
                <div class="text-sm text-gray-500 uppercase tracking-wide font-semibold">Entities</div>
                <div class="text-3xl font-bold text-gray-800 mt-1" id="countEntities">-</div>
            </div>
            <div class="p-6 border-r border-gray-200 text-center hover:bg-gray-50 transition">
                <div class="text-sm text-gray-500 uppercase tracking-wide font-semibold">Relationships</div>
                <div class="text-3xl font-bold text-gray-800 mt-1" id="countRelationships">-</div>
            </div>
            <div class="p-6 border-r border-gray-200 text-center hover:bg-gray-50 transition">
                <div class="text-sm text-gray-500 uppercase tracking-wide font-semibold">Issues</div>
                <div class="text-3xl font-bold text-red-600 mt-1" id="countIssues">-</div>
            </div>
            <div class="p-6 text-center hover:bg-gray-50 transition" title="Score = 100 - (2 * Total Issues). A higher score indicates better adherence to database design best practices (normalization, naming conventions, indexing).">
                <div class="text-sm text-gray-500 uppercase tracking-wide font-semibold">Score</div>
                <div class="text-3xl font-bold text-green-600 mt-1" id="modelScore">-</div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="p-6 space-y-8">
            
            <!-- Diagram Section -->
            <section>
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-xl font-bold text-gray-800 flex items-center">
                        <svg class="w-5 h-5 mr-2 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"></path></svg>
                        Entity Relationship Diagram
                    </h2>
                    <button onclick="renderMermaid()" class="text-sm text-indigo-600 hover:text-indigo-800 font-medium">Redraw</button>
                </div>
                <div class="overflow-x-auto border border-gray-200 rounded-lg bg-gray-50 p-4 min-h-[300px] flex items-center justify-center">
                    <div class="mermaid w-full text-center" id="mermaidGraph">
                        %% Loading diagram...
                    </div>
                </div>
            </section>

            <!-- Findings & Recommendations Grid -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <!-- Issues -->
                <section class="bg-red-50 rounded-lg p-6 border border-red-100">
                    <h2 class="text-xl font-bold text-red-800 mb-4 flex items-center">
                        <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                        Key Findings & Issues
                    </h2>
                    <div id="issuesList" class="space-y-3">
                        <!-- Issues injected here -->
                    </div>
                </section>

                <!-- Recommendations -->
                <section class="bg-blue-50 rounded-lg p-6 border border-blue-100">
                    <h2 class="text-xl font-bold text-blue-800 mb-4 flex items-center">
                        <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"></path></svg>
                        Recommendations
                    </h2>
                    <div id="recommendationsList" class="space-y-3">
                        <!-- Recommendations injected here -->
                    </div>
                </section>
            </div>

            <!-- Detailed Analysis -->
            <section>
                <h2 class="text-xl font-bold text-gray-800 mb-4">Detailed Entity Analysis</h2>
                <div class="overflow-hidden border border-gray-200 rounded-lg shadow-sm">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Entity</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Kind</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Structure</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Constraints</th>
                            </tr>
                        </thead>
                        <tbody id="entityTableBody" class="bg-white divide-y divide-gray-200">
                            <!-- Rows injected here -->
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    </div>

    <script>
        const urlParams = new URLSearchParams(window.location.search);
        const id = urlParams.get('id');

        async function renderMermaid(graphDefinition) {
            const element = document.getElementById('mermaidGraph');
            if (graphDefinition) {
                element.textContent = graphDefinition;
                element.removeAttribute('data-processed');
                // Clean up previous instance
                if (window.panZoomInstance) {
                    window.panZoomInstance.destroy();
                    window.panZoomInstance = null;
                }
            }
            
            await window.mermaid.run({
                nodes: [element]
            });

            const svg = element.querySelector('svg');
            if (svg) {
                // Ensure SVG has explicit dimensions for pan-zoom to work correctly
                svg.style.height = '600px'; 
                svg.style.width = '100%';
                
                try {
                    window.panZoomInstance = svgPanZoom(svg, {
                        zoomEnabled: true,
                        controlIconsEnabled: true,
                        fit: true,
                        center: true,
                        minZoom: 0.1,
                        maxZoom: 10
                    });
                } catch (e) {
                    console.error("PanZoom initialization failed", e);
                }
            }
        }

        async function loadData() {
            if (!id) {
                document.body.innerHTML = '<div class="p-8 text-red-600 text-center font-bold">No analysis ID provided</div>';
                return;
            }

            try {
                const response = await fetch(`/api/data-model/${id}`);
                if (!response.ok) throw new Error('Analysis not found');
                const data = await response.json();
                
                renderDashboard(data);
            } catch (err) {
                console.error(err);
                document.body.innerHTML = `<div class="p-8 text-red-600 text-center font-bold">Error loading analysis: ${err.message}</div>`;
            }
        }

        const ITEMS_PER_PAGE = 20;
        let currentIssuesPage = 1;
        let currentRecsPage = 1;
        let allIssuesData = [];
        let allRecsData = [];

        function renderPaginatedList(containerId, items, page, type) {
            const container = document.getElementById(containerId);
            const start = (page - 1) * ITEMS_PER_PAGE;
            const end = start + ITEMS_PER_PAGE;
            const pageItems = items.slice(start, end);
            const totalPages = Math.ceil(items.length / ITEMS_PER_PAGE);

            if (items.length === 0) {
                 if (type === 'issue') {
                    container.innerHTML = '<div class="text-green-600 italic">No significant issues found. Great job!</div>';
                 } else {
                    container.innerHTML = '<div class="text-gray-500 italic">No specific recommendations at this time.</div>';
                 }
                 return;
            }

            const listHtml = pageItems.map(i => {
                if (type === 'issue') {
                    return `
                    <div class="bg-white p-3 rounded border-l-4 border-red-500 shadow-sm text-sm">
                        <div class="font-bold text-gray-800">${i.entity || 'General'}</div>
                        <div class="text-gray-600">${i.issue}</div>
                         ${i.details ? `<div class="text-xs text-gray-500 mt-1">${typeof i.details === 'string' ? i.details : JSON.stringify(i.details)}</div>` : ''}
                    </div>`;
                } else {
                     return `
                    <div class="bg-white p-3 rounded border-l-4 border-blue-500 shadow-sm text-sm">
                        <div class="font-bold text-gray-800">${i.entity || 'General'}</div>
                        <div class="text-gray-600">${i.recommendation}</div>
                    </div>`;
                }
            }).join('');

            const controlsHtml = totalPages > 1 ? `
                <div class="flex justify-between items-center mt-4 text-sm">
                    <button onclick="changePage('${type}', -1)" ${page === 1 ? 'disabled' : ''} class="px-3 py-1 bg-gray-200 rounded hover:bg-gray-300 disabled:opacity-50 disabled:cursor-not-allowed">Previous</button>
                    <span>Page ${page} of ${totalPages} (${items.length} items)</span>
                    <button onclick="changePage('${type}', 1)" ${page === totalPages ? 'disabled' : ''} class="px-3 py-1 bg-gray-200 rounded hover:bg-gray-300 disabled:opacity-50 disabled:cursor-not-allowed">Next</button>
                </div>
            ` : `<div class="mt-2 text-xs text-gray-500 text-right">Showing all ${items.length} items</div>`;

            container.innerHTML = listHtml + controlsHtml;
        }

        window.changePage = function(type, delta) {
            if (type === 'issue') {
                const totalPages = Math.ceil(allIssuesData.length / ITEMS_PER_PAGE);
                const newPage = currentIssuesPage + delta;
                if (newPage >= 1 && newPage <= totalPages) {
                    currentIssuesPage = newPage;
                    renderPaginatedList('issuesList', allIssuesData, currentIssuesPage, 'issue');
                }
            } else if (type === 'rec') {
                const totalPages = Math.ceil(allRecsData.length / ITEMS_PER_PAGE);
                const newPage = currentRecsPage + delta;
                if (newPage >= 1 && newPage <= totalPages) {
                    currentRecsPage = newPage;
                    renderPaginatedList('recommendationsList', allRecsData, currentRecsPage, 'rec');
                }
            }
        }

        function renderDashboard(data) {
            const summary = data.summary;
            const issues = data.issues;
            const recommendations = data.recommendations;
            const model = data.logical_model;

            // Summary
            document.getElementById('schemaName').textContent = `schema: ${summary.schema}`;
            document.getElementById('generatedAt').textContent = `Generated at: ${new Date(summary.generated_at_utc).toLocaleString()}`;
            document.getElementById('countEntities').textContent = summary.entities;
            document.getElementById('countRelationships').textContent = summary.relationships;
            
            const totalIssues = Object.values(summary.issues_count).reduce((a, b) => a + b, 0);
            document.getElementById('countIssues').textContent = totalIssues;
            
            // Simple Score calculation (100 - issues * 2)
            const score = Math.max(0, 100 - (totalIssues * 2));
            document.getElementById('modelScore').textContent = score + '/100';

            // Issues List Initialization
            allIssuesData = [
                ...issues.entities, 
                ...issues.identifiers, 
                ...issues.normalization, 
                ...issues.relationships, 
                ...issues.attributes
            ];
            renderPaginatedList('issuesList', allIssuesData, currentIssuesPage, 'issue');

            // Recommendations List Initialization
            allRecsData = [
                ...recommendations.entities,
                ...recommendations.identifiers,
                ...recommendations.normalization,
                ...recommendations.relationships,
                ...recommendations.attributes
            ];
            renderPaginatedList('recommendationsList', allRecsData, currentRecsPage, 'rec');

            // Detailed Entity Table
            const entityTable = document.getElementById('entityTableBody');
            entityTable.innerHTML = model.entities.map(e => `
                <tr class="hover:bg-gray-50">
                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${e.name}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${e.kind === 'r' ? 'Table' : e.kind === 'v' ? 'View' : e.kind}</td>
                    <td class="px-6 py-4 text-sm text-gray-500">
                        <div>${e.attributes.length} columns</div>
                        <div class="text-xs text-gray-400 mt-1">${e.attributes.slice(0, 3).map(a => a.name).join(', ')}${e.attributes.length > 3 ? '...' : ''}</div>
                    </td>
                    <td class="px-6 py-4 text-sm text-gray-500">
                        ${e.primary_key.length ? `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 mr-1">PK: ${e.primary_key.join(', ')}</span>` : '<span class="text-red-400 text-xs">No PK</span>'}
                        ${e.unique_constraints.length ? `<div class="mt-1"><span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">UKs: ${e.unique_constraints.length}</span></div>` : ''}
                    </td>
                </tr>
            `).join('');

            // Generate Mermaid Diagram
            const graph = generateMermaid(model);
            renderMermaid(graph);
        }

        function generateMermaid(model) {
            let s = 'erDiagram\\n';
            
            // Helper to sanitize names for Mermaid
            const safeName = (name) => name.replace(/[^a-zA-Z0-9_]/g, '_');
            const safeType = (type) => type.replace(/\\s+/g, '_');

            // Entities
            model.entities.forEach(e => {
                const entityName = safeName(e.name);
                s += `    ${entityName} {\n`;
                // Add PKs first
                e.attributes.forEach(a => {
                    const isPk = e.primary_key.includes(a.name);
                    const isFk = e.foreign_keys.some(fk => fk.local_columns.includes(a.name));
                    
                    let type = safeType(a.data_type);
                    if (a.max_length) type += `(${a.max_length})`;
                    
                    let markers = [];
                    if (isPk) markers.push('PK');
                    if (isFk) markers.push('FK');
                    
                    // Attribute name might need quotes if it has special chars, but for ERD
                    // Mermaid expects word-like tokens. We'll use safeName just in case.
                    s += `        ${type} ${safeName(a.name)} ${markers.length ? '"' + markers.join(', ') + '"' : ''}\n`;
                });
                s += '    }\\n';
            });

            // Relationships
            model.relationships.forEach(r => {
                // Determine cardinality (basic assumption for now: 1 to Many)
                // If unique constraint exists on local columns, it might be 1 to 1
                // For now, we use ||--o{ as default
                const from = r.to_entity.split('.')[1]; // ref table (parent)
                const to = r.from_entity.split('.')[1]; // local table (child)
                
                // Avoid self-references or missing entities crashing mermaid
                if (from && to) {
                    const label = r.name.replace(/"/g, "'"); // Escape quotes in label
                    s += `    ${safeName(from)} ||--o{ ${safeName(to)} : "${label}"\n`;
                }
            });

            return s;
        }

        window.onload = loadData;
    </script>
</body>
</html>
"""

@mcp.custom_route("/data-model-analysis", methods=["GET"])
async def data_model_analysis_ui(_request: Request) -> HTMLResponse:
    return HTMLResponse(DATA_MODEL_HTML)

def _make_json_serializable(obj: Any) -> Any:
    """Recursively convert objects to JSON-serializable types."""
    if isinstance(obj, dict):
        return {k: _make_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_make_json_serializable(v) for v in obj]
    elif isinstance(obj, tuple):
        return tuple(_make_json_serializable(v) for v in obj)
    elif isinstance(obj, (datetime, date)):
        return obj.isoformat()
    elif isinstance(obj, decimal.Decimal):
        return float(obj)
    elif isinstance(obj, uuid.UUID):
        return str(obj)
    return obj

@mcp.custom_route("/api/data-model/{result_id}", methods=["GET"])
async def get_data_model_result(request: Request) -> JSONResponse:
    result_id = request.path_params["result_id"]
    data = DATA_MODEL_CACHE.get(result_id)
    if not data:
        return JSONResponse({"error": "Analysis not found or expired"}, status_code=404)
    
    try:
        # Ensure data is serializable (handle Decimal, UUID, datetime, etc.)
        safe_data = _make_json_serializable(data)
        return JSONResponse(safe_data)
    except Exception as e:
        logger.error(f"Serialization error for result {result_id}: {e}")
        return JSONResponse({"error": f"Internal serialization error: {str(e)}"}, status_code=500)


SESSION_MONITOR_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>DB Sessions Monitor</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: sans-serif; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { text-align: center; }
        .stats { display: flex; justify-content: space-around; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .stat-box { text-align: center; padding: 10px; border: 1px solid #ddd; border-radius: 5px; min-width: 100px; }
        .stat-value { font-size: 24px; font-weight: bold; }
        .stat-label { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>PostgreSQL Sessions Monitor</h1>
        
        <div class="stats">
            <div class="stat-box">
                <div id="activeVal" class="stat-value">-</div>
                <div class="stat-label">Active</div>
            </div>
            <div class="stat-box">
                <div id="idleVal" class="stat-value">-</div>
                <div class="stat-label">Idle</div>
            </div>
            <div class="stat-box">
                <div id="idleTxnVal" class="stat-value">-</div>
                <div class="stat-label">Idle in TXN</div>
            </div>
            <div class="stat-box">
                <div id="totalVal" class="stat-value">-</div>
                <div class="stat-label">Total</div>
            </div>
        </div>

        <canvas id="sessionsChart"></canvas>
    </div>
    <script>
        const ctx = document.getElementById('sessionsChart').getContext('2d');
        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Active',
                        borderColor: 'rgb(75, 192, 192)',
                        backgroundColor: 'rgba(75, 192, 192, 0.1)',
                        data: [],
                        tension: 0.1,
                        fill: true
                    },
                    {
                        label: 'Idle',
                        borderColor: 'rgb(255, 205, 86)',
                        backgroundColor: 'rgba(255, 205, 86, 0.1)',
                        data: [],
                        tension: 0.1,
                        fill: true
                    },
                    {
                        label: 'Idle in TXN',
                        borderColor: 'rgb(255, 99, 132)',
                        backgroundColor: 'rgba(255, 99, 132, 0.1)',
                        data: [],
                        tension: 0.1,
                        fill: true
                    },
                    {
                        label: 'Total',
                        borderColor: 'rgb(54, 162, 235)',
                        borderDash: [5, 5],
                        data: [],
                        tension: 0.1,
                        fill: false
                    }
                ]
            },
            options: {
                responsive: true,
                scales: {
                    x: { title: { display: true, text: 'Time' } },
                    y: { beginAtZero: true, title: { display: true, text: 'Count' } }
                }
            }
        });

        async function fetchData() {
            try {
                const response = await fetch('/api/sessions');
                const data = await response.json();
                const now = new Date().toLocaleTimeString();

                // Update text stats
                document.getElementById('activeVal').textContent = data.active;
                document.getElementById('idleVal').textContent = data.idle;
                document.getElementById('idleTxnVal').textContent = data.idle_in_transaction;
                document.getElementById('totalVal').textContent = data.total;

                // Update chart
                if (chart.data.labels.length > 20) {
                    chart.data.labels.shift();
                    chart.data.datasets[0].data.shift();
                    chart.data.datasets[1].data.shift();
                    chart.data.datasets[2].data.shift();
                    chart.data.datasets[3].data.shift();
                }

                chart.data.labels.push(now);
                chart.data.datasets[0].data.push(data.active);
                chart.data.datasets[1].data.push(data.idle);
                chart.data.datasets[2].data.push(data.idle_in_transaction);
                chart.data.datasets[3].data.push(data.total);
                chart.update();
            } catch (error) {
                console.error('Error fetching data:', error);
            }
        }

        // Fetch every 5 seconds
        setInterval(fetchData, 5000);
        fetchData(); // Initial fetch
    </script>
</body>
</html>
"""

@mcp.custom_route("/sessions-monitor", methods=["GET"])
async def sessions_monitor(_request: Request) -> HTMLResponse:
    return HTMLResponse(SESSION_MONITOR_HTML)

@mcp.custom_route("/api/sessions", methods=["GET"])
async def api_sessions(_request: Request) -> JSONResponse:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            # Query for session counts
            # Active: state = 'active'
            # Idle: state = 'idle' only
            # Idle in TXN: state in ('idle in transaction', 'idle in transaction (aborted)')
            # Total: count(*)
            _execute_safe(
                cur,
                """
                SELECT
                    sum(case when state = 'active' then 1 else 0 end) as active,
                    sum(case when state = 'idle' then 1 else 0 end) as idle,
                    sum(case when state in ('idle in transaction', 'idle in transaction (aborted)') then 1 else 0 end) as idle_in_transaction,
                    count(*) as total
                FROM pg_stat_activity
                """
            )
            row = cur.fetchone()
            active = row["active"] if row and row["active"] is not None else 0
            idle = row["idle"] if row and row["idle"] is not None else 0
            idle_in_transaction = row["idle_in_transaction"] if row and row["idle_in_transaction"] is not None else 0
            total = row["total"] if row and row["total"] is not None else 0
            
            return JSONResponse({
                "active": active,
                "idle": idle,
                "idle_in_transaction": idle_in_transaction,
                "total": total,
                "timestamp": time.time()
            })

async def health_check(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "healthy"})

@mcp.tool(tags={"public"})
def db_pg96_monitor_sessions() -> str:
    """
    Get the link to the real-time database sessions monitor dashboard.
    
    Returns:
        A message containing the URL to the sessions monitor dashboard.
    """
    port = os.environ.get("MCP_PORT", "8000")
    host = os.environ.get("MCP_HOST", "localhost")
    if host == "0.0.0.0":
        host = "localhost"
        
    url = f"http://{host}:{port}/sessions-monitor"
    return f"Monitor available at: {url}"


def main() -> None:
    _configure_fastmcp_runtime()

    transport = os.environ.get("MCP_TRANSPORT", "http").strip().lower()
    host = os.environ.get("MCP_HOST", "0.0.0.0")
    # Default to 8085 to avoid common 8000 conflicts
    port = _env_int("MCP_PORT", 8085)
    
    stateless = _env_bool("MCP_STATELESS", False)
    json_resp = _env_bool("MCP_JSON_RESPONSE", False)
    
    # SSL Configuration for HTTPS
    ssl_cert = os.environ.get("MCP_SSL_CERT")
    ssl_key = os.environ.get("MCP_SSL_KEY")
    
    if transport in {"http", "sse"}:
        run_kwargs = {
            "transport": transport,
            "host": host,
            "port": port,
            "stateless_http": stateless,
            "json_response": json_resp,
            "middleware": [
                Middleware(APIKeyMiddleware),
                Middleware(BrowserFriendlyMiddleware)
            ]
        }
        
        if ssl_cert and ssl_key:
            run_kwargs["ssl_certfile"] = ssl_cert
            run_kwargs["ssl_keyfile"] = ssl_key
            logger.info(f"Starting MCP server with HTTPS enabled using cert: {ssl_cert}")
        
        mcp.run(**run_kwargs)
    elif transport == "stdio":
        # Hybrid mode: Start HTTP server in background for UI/Custom Routes
        def run_http_background(server_ready: threading.Event, host: str, port: int):
            """Runs the HTTP server in a background thread and signals readiness."""
            logger.info(f"Starting background HTTP server for UI on http://{host}:{port}")
            try:
                # Suppress Uvicorn logs to prevent stdout pollution
                logging.getLogger("uvicorn").setLevel(logging.WARNING)
                logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
                logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

                # Create a new event loop for this thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                app = mcp.http_app()
                app.add_middleware(APIKeyMiddleware)
                app.add_middleware(BrowserFriendlyMiddleware)

                config = uvicorn.Config(
                    app,
                    host=host,
                    port=port,
                    log_level="warning",
                    loop="asyncio",
                )

                server = uvicorn.Server(config)

                async def _monitor_startup() -> None:
                    for _ in range(300):
                        if getattr(server, "started", False):
                            logger.info("Background HTTP server has started.")
                            server_ready.set()
                            return
                        await asyncio.sleep(0.05)
                    if not server_ready.is_set():
                        logger.warning("Background HTTP server startup monitor timed out.")
                        server_ready.set()

                async def _serve_with_monitor() -> None:
                    monitor_task = asyncio.create_task(_monitor_startup())
                    try:
                        await server.serve()
                    finally:
                        monitor_task.cancel()

                loop.run_until_complete(_serve_with_monitor())
            except Exception as e:
                logger.error(f"Background HTTP server failed to start: {e}", exc_info=True)
                # Ensure the event is set even on failure to unblock the main thread
                if not server_ready.is_set():
                    server_ready.set()

        # Start HTTP server thread
        server_ready = threading.Event()
        http_thread = threading.Thread(
            target=run_http_background,
            args=(server_ready, host, port),
            daemon=False,  # Use non-daemon thread for cleaner shutdown
            name="MCPBackgroundHttpThread"
        )
        http_thread.start()

        # Wait for the server to be ready, with a timeout
        logger.info("Waiting for background HTTP server to start...")
        ready = server_ready.wait(timeout=15.0) # Wait up to 15 seconds

        if ready:
            # A small sleep to allow routes to fully initialize
            time.sleep(0.5)
            logger.info(f"Background HTTP server started. UI available at http://{host}:{port}/")
        else:
            logger.error("Background HTTP server failed to start within the timeout period.")

        # Run stdio transport in main thread
        logger.info("Starting MCP STDIO transport...")
        mcp.run(transport="stdio")
    else:
        raise ValueError(f"Unknown transport: {transport}. Supported transports: http, sse, stdio")


if __name__ == "__main__":
    main()


