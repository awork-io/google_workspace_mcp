from types import SimpleNamespace

import pytest

import core.server as server_module


def test_configure_server_for_http_allows_legacy_oauth_callback(monkeypatch):
    calls = []

    monkeypatch.setattr(server_module, "get_transport_mode", lambda: "streamable-http")
    monkeypatch.setattr(
        server_module, "set_auth_provider", lambda provider: calls.append(provider)
    )
    monkeypatch.setattr(
        server_module,
        "_ensure_legacy_callback_route",
        lambda: calls.append("callback"),
    )
    monkeypatch.setattr(server_module, "_auth_provider", object())
    monkeypatch.setattr(server_module.server, "auth", object())
    monkeypatch.setattr(
        "auth.oauth_config.get_oauth_config",
        lambda: SimpleNamespace(
            is_oauth21_enabled=lambda: False,
            is_configured=lambda: True,
        ),
    )

    server_module.configure_server_for_http()

    assert server_module.server.auth is None
    assert server_module._auth_provider is None
    assert calls == [None, "callback"]


def test_configure_server_for_http_rejects_unconfigured_oauth21(monkeypatch):
    monkeypatch.setattr(server_module, "get_transport_mode", lambda: "streamable-http")
    monkeypatch.setattr(
        "auth.oauth_config.get_oauth_config",
        lambda: SimpleNamespace(
            is_oauth21_enabled=lambda: True,
            is_configured=lambda: False,
        ),
    )

    with pytest.raises(RuntimeError, match="requires GOOGLE_OAUTH_CLIENT_ID"):
        server_module.configure_server_for_http()


def test_configure_server_for_http_uses_protocol_auth_required_scopes(monkeypatch):
    captured = {}

    class FakeGoogleProvider:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            self.client_registration_options = SimpleNamespace(
                valid_scopes=kwargs.get("valid_scopes"),
                default_scopes=None,
            )
            default_scope = " ".join(kwargs.get("required_scopes", []))
            self._default_scope_str = default_scope
            self._cimd_manager = SimpleNamespace(default_scope=default_scope)

    monkeypatch.setattr(server_module, "get_transport_mode", lambda: "streamable-http")
    monkeypatch.setattr(server_module, "GoogleProvider", FakeGoogleProvider)
    monkeypatch.setattr(
        server_module,
        "get_current_scopes",
        lambda: [
            "https://www.googleapis.com/auth/drive.file",
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid",
        ],
    )
    monkeypatch.setattr(server_module, "set_auth_provider", lambda provider: None)

    # Capture and restore globals that configure_server_for_http() mutates directly
    monkeypatch.setattr(server_module, "_auth_provider", server_module._auth_provider)
    monkeypatch.setattr(server_module.server, "auth", server_module.server.auth)

    monkeypatch.setattr(
        "auth.oauth_config.get_oauth_config",
        lambda: SimpleNamespace(
            is_oauth21_enabled=lambda: True,
            is_configured=lambda: True,
            is_public_client=lambda: False,
            is_external_oauth21_provider=lambda: False,
            client_id="client-id",
            client_secret="client-secret",
            get_oauth_base_url=lambda: "https://workspace-mcp.example.test",
            redirect_path="/oauth2callback",
        ),
    )

    server_module.configure_server_for_http()

    assert captured["required_scopes"] == sorted(server_module.PROTOCOL_AUTH_SCOPES)
    assert captured["valid_scopes"] == sorted(server_module.get_current_scopes())
    assert (
        server_module.server.auth.client_registration_options.default_scopes
        == sorted(server_module.get_current_scopes())
    )
    expected_default_scope = " ".join(sorted(server_module.get_current_scopes()))
    assert server_module.server.auth._default_scope_str == expected_default_scope
    assert (
        server_module.server.auth._cimd_manager.default_scope == expected_default_scope
    )


def test_configure_server_for_http_supports_public_client_with_jwt_key(monkeypatch):
    captured = {}

    class FakeGoogleProvider:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            self.client_registration_options = SimpleNamespace(
                valid_scopes=kwargs.get("valid_scopes"),
                default_scopes=None,
            )

    monkeypatch.setenv(
        "FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY",
        "this-is-a-long-enough-jwt-signing-key",
    )
    monkeypatch.setattr(server_module, "get_transport_mode", lambda: "streamable-http")
    monkeypatch.setattr(server_module, "GoogleProvider", FakeGoogleProvider)
    monkeypatch.setattr(
        server_module,
        "get_current_scopes",
        lambda: [
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid",
        ],
    )
    monkeypatch.setattr(server_module, "set_auth_provider", lambda provider: None)
    monkeypatch.setattr(server_module, "_auth_provider", server_module._auth_provider)
    monkeypatch.setattr(server_module.server, "auth", server_module.server.auth)

    monkeypatch.setattr(
        "auth.oauth_config.get_oauth_config",
        lambda: SimpleNamespace(
            is_oauth21_enabled=lambda: True,
            is_configured=lambda: True,
            is_public_client=lambda: True,
            is_external_oauth21_provider=lambda: False,
            client_id="public-client-id",
            client_secret=None,
            get_oauth_base_url=lambda: "https://workspace-mcp.example.test",
            redirect_path="/oauth2callback",
        ),
    )

    server_module.configure_server_for_http()

    assert captured["client_id"] == "public-client-id"
    assert captured["client_secret"] is None
    assert captured["jwt_signing_key"]


def test_configure_server_for_http_rejects_public_client_without_jwt_key(
    monkeypatch,
):
    monkeypatch.delenv("FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY", raising=False)
    monkeypatch.setattr(server_module, "get_transport_mode", lambda: "streamable-http")
    monkeypatch.setattr(server_module, "GoogleProvider", object)
    monkeypatch.setattr(server_module, "set_auth_provider", lambda provider: None)
    monkeypatch.setattr(server_module, "_auth_provider", server_module._auth_provider)
    monkeypatch.setattr(server_module.server, "auth", server_module.server.auth)
    monkeypatch.setattr(
        "auth.oauth_config.get_oauth_config",
        lambda: SimpleNamespace(
            is_oauth21_enabled=lambda: True,
            is_configured=lambda: True,
            is_public_client=lambda: True,
            is_external_oauth21_provider=lambda: False,
            client_id="public-client-id",
            client_secret=None,
            get_oauth_base_url=lambda: "https://workspace-mcp.example.test",
            redirect_path="/oauth2callback",
        ),
    )

    with pytest.raises(
        ValueError,
        match="Public client OAuth 2.1 requires FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY",
    ):
        server_module.configure_server_for_http()


@pytest.mark.parametrize("selectable_access", [False, True])
def test_configure_server_for_http_passes_external_provider_settings(
    monkeypatch, selectable_access
):
    """ExternalOAuthProvider must receive the derived jwt_signing_key.

    Regression test: previously the key was derived but not forwarded,
    causing a startup failure when client_secret was absent.
    """
    captured = {}

    class FakeExternalOAuthProvider:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setenv(
        "FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY",
        "this-is-a-long-enough-jwt-signing-key",
    )
    monkeypatch.setenv("WORKSPACE_MCP_SELECTABLE_ACCESS", str(int(selectable_access)))
    monkeypatch.setattr(server_module, "get_transport_mode", lambda: "streamable-http")
    monkeypatch.setattr(server_module, "set_auth_provider", lambda provider: None)
    monkeypatch.setattr(server_module, "_auth_provider", server_module._auth_provider)
    monkeypatch.setattr(server_module.server, "auth", server_module.server.auth)
    monkeypatch.setattr(
        server_module,
        "get_current_scopes",
        lambda: [
            *server_module.PROTOCOL_AUTH_SCOPES,
            "https://www.googleapis.com/auth/calendar",
        ],
    )
    monkeypatch.setattr(
        "auth.external_oauth_provider.ExternalOAuthProvider",
        FakeExternalOAuthProvider,
    )
    monkeypatch.setattr(
        "auth.oauth_config.get_oauth_config",
        lambda: SimpleNamespace(
            is_oauth21_enabled=lambda: True,
            is_configured=lambda: True,
            is_external_oauth21_provider=lambda: True,
            client_id="client-id",
            client_secret=None,
            get_oauth_base_url=lambda: "https://workspace-mcp.example.test",
            redirect_path="/oauth2callback",
        ),
    )

    server_module.configure_server_for_http()

    assert "jwt_signing_key" in captured, (
        "jwt_signing_key must be forwarded to ExternalOAuthProvider"
    )
    assert isinstance(captured["jwt_signing_key"], bytes), (
        "jwt_signing_key must be a bytes object"
    )
    assert len(captured["jwt_signing_key"]) > 0, "jwt_signing_key must be non-empty"
    if selectable_access:
        assert captured["required_scopes"] == sorted(server_module.PROTOCOL_AUTH_SCOPES)
        assert set(captured["selectable_scopes"]) == {
            *server_module.get_current_scopes(),
            "https://www.googleapis.com/auth/calendar.readonly",
        }
    else:
        assert captured["required_scopes"] == sorted(server_module.get_current_scopes())
        assert captured["selectable_scopes"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("grant_type", ["read", "full", "expired", "missing_identity"])
async def test_selectable_external_oauth_uses_google_grant_for_tools(
    monkeypatch, grant_type
):
    import httpx
    import time
    from key_value.aio.stores.memory import MemoryStore

    import auth.service_decorator as service_decorator
    from auth.external_oauth_provider import ExternalOAuthProvider
    from auth.scopes import (
        CALENDAR_EVENTS_SCOPE,
        CALENDAR_READONLY_SCOPE,
        CALENDAR_SCOPE,
        GMAIL_READONLY_SCOPE,
        PROTOCOL_AUTH_SCOPES,
    )

    provider = ExternalOAuthProvider(
        client_id="test-client",
        client_secret="test-secret",
        base_url="https://workspace-mcp.example.test",
        resource_server_url="https://workspace-mcp.example.test",
        required_scopes=PROTOCOL_AUTH_SCOPES,
        selectable_scopes=[
            *PROTOCOL_AUTH_SCOPES,
            CALENDAR_SCOPE,
            CALENDAR_READONLY_SCOPE,
        ],
        client_storage=MemoryStore(),
    )
    original_client = httpx.AsyncClient
    calendar_scope = CALENDAR_SCOPE if grant_type == "full" else CALENDAR_READONLY_SCOPE
    identity_scopes = "openid" if grant_type == "missing_identity" else "openid email"
    lifetime = -1 if grant_type == "expired" else 60

    def respond(request):
        assert request.method == "POST"
        assert str(request.url) == "https://oauth2.googleapis.com/tokeninfo"
        assert request.content == b"access_token=ya29.test-token"
        return httpx.Response(
            200,
            json={
                "email": "user@example.test",
                "email_verified": "true",
                "sub": "test-user",
                "exp": str(int(time.time()) + lifetime),
                "scope": f"{identity_scopes} {calendar_scope}",
            },
        )

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: original_client(
            transport=httpx.MockTransport(respond), **kwargs
        ),
    )

    token = await provider.verify_token("ya29.test-token")

    if grant_type in {"expired", "missing_identity"}:
        assert token is None
        return

    assert token is not None
    assert set(token.scopes) == {*PROTOCOL_AUTH_SCOPES, calendar_scope}
    monkeypatch.setattr(service_decorator, "get_auth_provider", lambda: provider)
    monkeypatch.setattr(service_decorator, "get_access_token", lambda: token)
    monkeypatch.setattr(
        "auth.oauth21_session_store.is_external_oauth21_provider", lambda: True
    )

    def build_service(service, version, credentials):
        headers = {}
        credentials.before_request(None, "GET", "https://www.googleapis.com", headers)
        assert headers["authorization"] == "Bearer ya29.test-token"
        return service

    monkeypatch.setattr(service_decorator, "build", build_service)

    async def authorize(service, scope):
        return await service_decorator.get_authenticated_google_service_oauth21(
            service_name=service,
            version="v1",
            tool_name="test_tool",
            user_google_email="user@example.test",
            required_scopes=[scope],
        )

    assert await authorize("calendar", CALENDAR_READONLY_SCOPE) == (
        "calendar",
        "user@example.test",
    )
    if grant_type == "full":
        assert await authorize("calendar", CALENDAR_EVENTS_SCOPE) == (
            "calendar",
            "user@example.test",
        )
    else:
        with pytest.raises(
            service_decorator.GoogleAuthenticationError, match="lack required scopes"
        ):
            await authorize("calendar", CALENDAR_EVENTS_SCOPE)
    with pytest.raises(
        service_decorator.GoogleAuthenticationError, match="lack required scopes"
    ):
        await authorize("gmail", GMAIL_READONLY_SCOPE)
