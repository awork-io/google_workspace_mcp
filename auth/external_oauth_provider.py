"""
External OAuth Provider for Google Workspace MCP

Extends FastMCP's GoogleProvider to support external OAuth flows where
access tokens (ya29.*) are issued by external systems and need validation.

This provider acts as a Resource Server only - it validates tokens issued by
Google's Authorization Server but does not issue tokens itself.
"""

import functools
import logging
import os
import time
from typing import Optional

from starlette.responses import JSONResponse
from starlette.routing import Route
from fastmcp.server.auth.providers.google import GoogleProvider
from fastmcp.server.auth import AccessToken
from google.oauth2.credentials import Credentials

from auth.oauth_types import WorkspaceAccessToken

logger = logging.getLogger(__name__)

# Google's OAuth 2.0 Authorization Server.
#
# This is the canonical issuer as returned by Google's OpenID discovery
# document (https://accounts.google.com/.well-known/openid-configuration),
# which reports `"issuer": "https://accounts.google.com"` WITHOUT a trailing
# slash. RFC 8414 §3.3 requires clients to compare the issuer advertised in our
# protected-resource metadata against that value using an exact string match.
GOOGLE_ISSUER_URL = "https://accounts.google.com"


def _canonicalize_authorization_servers(route: Route) -> Route:
    """Rebuild a protected-resource metadata route to emit the canonical issuer.

    The MCP SDK models ``authorization_servers`` as ``list[AnyHttpUrl]``, and
    Pydantic normalizes a bare-host URL by appending a trailing slash. As a
    result the metadata advertises ``https://accounts.google.com/`` even though
    we pass the slash-less canonical form. Google's OpenID discovery reports the
    issuer without the slash, so the SDK's RFC 8414 §3.3 exact-match check on the
    401 token-refresh path fails and clients are forced to re-authorize.

    The SDK route serves the metadata straight from a frozen Pydantic model, so
    we cannot mutate it in place. Instead we read the served payload once from
    the SDK's handler, rewrite the ``authorization_servers`` entries back to
    their canonical (slash-less) form, and serve that fixed payload from an
    equivalent CORS-wrapped handler.
    """
    from mcp.server.auth.handlers.metadata import ProtectedResourceMetadataHandler
    from mcp.server.auth.routes import cors_middleware

    metadata_handler = _find_metadata_handler(route.endpoint)
    if not isinstance(metadata_handler, ProtectedResourceMetadataHandler):
        # Unexpected route shape; leave it untouched rather than break discovery.
        logger.warning(
            "ExternalOAuthProvider: could not canonicalize issuer for route %s",
            route.path,
        )
        return route

    payload = metadata_handler.metadata.model_dump(mode="json", exclude_none=True)
    servers = payload.get("authorization_servers")
    if isinstance(servers, list):
        payload["authorization_servers"] = [
            GOOGLE_ISSUER_URL if s == GOOGLE_ISSUER_URL + "/" else s for s in servers
        ]

    async def handle(_request):
        return JSONResponse(
            payload, headers={"Cache-Control": "public, max-age=3600"}
        )

    return Route(
        route.path,
        endpoint=cors_middleware(handle, ["GET", "OPTIONS"]),
        methods=route.methods,
    )


def _find_metadata_handler(endpoint):
    """Reach the ProtectedResourceMetadataHandler behind the SDK route.

    The SDK builds ``CORSMiddleware(app=request_response(handler.handle))``;
    ``handler.handle`` is a bound method captured in the request_response
    closure, so we walk the closure cells to recover its ``__self__``.
    """
    from mcp.server.auth.handlers.metadata import ProtectedResourceMetadataHandler

    app = getattr(endpoint, "app", None)
    for cell in getattr(app, "__closure__", None) or ():
        candidate = getattr(cell.cell_contents, "__self__", None)
        if isinstance(candidate, ProtectedResourceMetadataHandler):
            return candidate
    return None

# Configurable session time in seconds (default: 1 hour, max: 24 hours)
_DEFAULT_SESSION_TIME = 3600
_MAX_SESSION_TIME = 86400


@functools.lru_cache(maxsize=1)
def get_session_time() -> int:
    """Parse SESSION_TIME from environment with fallback, min/max clamp.

    Result is cached; changes require a server restart.
    """
    raw = os.getenv("SESSION_TIME", "")
    if not raw:
        return _DEFAULT_SESSION_TIME
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "Invalid SESSION_TIME=%r, falling back to %d", raw, _DEFAULT_SESSION_TIME
        )
        return _DEFAULT_SESSION_TIME
    clamped = max(1, min(value, _MAX_SESSION_TIME))
    if clamped != value:
        logger.warning(
            "SESSION_TIME=%d clamped to %d (allowed range: 1–%d)",
            value,
            clamped,
            _MAX_SESSION_TIME,
        )
    return clamped


class ExternalOAuthProvider(GoogleProvider):
    """
    Extended GoogleProvider that supports validating external Google OAuth access tokens.

    This provider handles ya29.* access tokens by calling Google's userinfo API,
    while maintaining compatibility with standard JWT ID tokens.

    Unlike the standard GoogleProvider, this acts as a Resource Server only:
    - Does NOT create /authorize, /token, /register endpoints
    - Only advertises Google's authorization server in metadata
    - Only validates tokens, does not issue them
    """

    def __init__(
        self,
        client_id: str,
        client_secret: Optional[str] = None,
        resource_server_url: Optional[str] = None,
        **kwargs,
    ):
        """Initialize and store client credentials for token validation."""
        self._resource_server_url = resource_server_url
        super().__init__(client_id=client_id, client_secret=client_secret, **kwargs)
        # Store credentials as they're not exposed by parent class
        self._client_id = client_id
        self._client_secret = client_secret
        # Store as string - Pydantic validates it when passed to models
        self.resource_server_url = self._resource_server_url

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        """
        Verify a token - supports both JWT ID tokens and ya29.* access tokens.

        For ya29.* access tokens (issued externally), validates by calling
        Google's userinfo API. For JWT tokens, delegates to parent class.

        Args:
            token: Token string to verify (JWT or ya29.* access token)

        Returns:
            AccessToken object if valid, None otherwise
        """
        # For ya29.* access tokens, validate using Google's userinfo API
        if token.startswith("ya29."):
            logger.debug("Validating external Google OAuth access token")

            try:
                from auth.google_auth import get_user_info

                # Create minimal Credentials object for userinfo API call
                credentials = Credentials(
                    token=token,
                    token_uri="https://oauth2.googleapis.com/token",
                    client_id=self._client_id,
                    client_secret=self._client_secret,
                )

                # Validate token by calling userinfo API
                user_info = get_user_info(credentials, skip_valid_check=True)

                if user_info and user_info.get("email"):
                    session_time = get_session_time()
                    # Token is valid - create AccessToken object
                    logger.info(
                        f"Validated external access token for: {user_info['email']}"
                    )

                    scope_list = list(getattr(self, "required_scopes", []) or [])
                    access_token = WorkspaceAccessToken(
                        token=token,
                        scopes=scope_list,
                        expires_at=int(time.time()) + session_time,
                        claims={
                            "email": user_info["email"],
                            "sub": user_info.get("id"),
                        },
                        client_id=self._client_id,
                        email=user_info["email"],
                        sub=user_info.get("id"),
                    )
                    return access_token
                else:
                    logger.error("Could not get user info from access token")
                    return None

            except Exception as e:
                logger.error(f"Error validating external access token: {e}")
                return None

        # For JWT tokens, use parent class implementation
        return await super().verify_token(token)

    def get_routes(self, **kwargs) -> list[Route]:
        """
        Get OAuth routes for external provider mode.

        Returns only protected resource metadata routes that point to Google
        as the authorization server. Does not create authorization server routes
        (/authorize, /token, etc.) since tokens are issued by Google directly.

        Args:
            **kwargs: Additional arguments passed by FastMCP (e.g., mcp_path)

        Returns:
            List of routes - only protected resource metadata
        """
        from mcp.server.auth.routes import create_protected_resource_routes

        if not self.resource_server_url:
            logger.warning(
                "ExternalOAuthProvider: resource_server_url not set, no routes created"
            )
            return []

        # Create protected resource routes that point to Google as the authorization server
        # Pass strings directly - Pydantic validates them during model construction
        protected_routes = create_protected_resource_routes(
            resource_url=self.resource_server_url,
            authorization_servers=[GOOGLE_ISSUER_URL],
            scopes_supported=self.required_scopes,
            resource_name="Google Workspace MCP",
            resource_documentation=None,
        )

        # Rewrite the advertised authorization_servers back to the canonical
        # slash-less issuer (Pydantic's AnyHttpUrl re-adds the trailing slash),
        # so the SDK's RFC 8414 §3.3 exact-match check on the 401 refresh path
        # succeeds instead of forcing a re-authorization.
        protected_routes = [
            _canonicalize_authorization_servers(route) for route in protected_routes
        ]

        logger.info(
            f"ExternalOAuthProvider: Created protected resource routes pointing to {GOOGLE_ISSUER_URL}"
        )
        return protected_routes
