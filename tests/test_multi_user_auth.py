import asyncio
import os
import time

from cryptography.fernet import Fernet
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull


class MemoryKV:
    def __init__(self): self.data = {}
    async def get(self, key): return self.data.get(key)
    async def set(self, key, value, ttl=None): self.data[key] = value
    async def delete(self, key): self.data.pop(key, None)


def _provider(monkeypatch):
    monkeypatch.setenv("KV_REST_API_URL", "https://example.invalid")
    monkeypatch.setenv("KV_REST_API_TOKEN", "test")
    monkeypatch.setenv("BASECAMP_MCP_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("BASECAMP_MULTIUSER_REDIRECT_URI", "https://example.test/basecamp/callback")
    monkeypatch.setenv("BASECAMP_CLIENT_ID", "basecamp-client")
    monkeypatch.setenv("BASECAMP_CLIENT_SECRET", "basecamp-secret")
    monkeypatch.setenv("USER_AGENT", "test@example.com")
    from multi_user_auth import BasecampOAuthProvider
    provider = BasecampOAuthProvider(); provider.kv = MemoryKV()
    return provider


def _client():
    return OAuthClientInformationFull(
        client_id="claude", client_secret=None, redirect_uris=["https://claude.ai/callback"],
        grant_types=["authorization_code", "refresh_token"], response_types=["code"],
        token_endpoint_auth_method="none",
    )


def test_mcp_tokens_are_bound_to_the_authorized_person(monkeypatch):
    provider = _provider(monkeypatch)
    async def run():
        client = _client(); await provider.register_client(client)
        issued = await provider._issue("person-a", client, ["basecamp"])
        access = await provider.load_access_token(issued.access_token)
        assert access.subject == "person-a"
        assert await provider.load_access_token(issued.refresh_token) is None
        refresh = await provider.load_refresh_token(client, issued.refresh_token)
        renewed = await provider.exchange_refresh_token(client, refresh, ["basecamp"])
        assert (await provider.load_access_token(renewed.access_token)).subject == "person-a"
        assert await provider.load_access_token(issued.access_token) is not None
    asyncio.run(run())


def test_basecamp_tokens_are_encrypted_and_isolated(monkeypatch):
    provider = _provider(monkeypatch)
    async def run():
        raw = {"access_token":"person-a-access", "refresh_token":"person-a-refresh", "account_id":"1", "expires_at":time.time()+3600}
        await provider.kv.set(__import__('multi_user_auth')._key('basecamp','person-a'), {"token": provider._crypt(raw)})
        stored = await provider.kv.get(__import__('multi_user_auth')._key('basecamp','person-a'))
        assert "person-a-access" not in stored["token"]
        assert (await provider.basecamp_token("person-a"))["access_token"] == "person-a-access"
        assert await provider.basecamp_token("person-b") is None
    asyncio.run(run())


def test_callback_preserves_claude_state_and_creates_one_time_code(monkeypatch):
    provider = _provider(monkeypatch)
    import multi_user_auth
    class FakeOAuth:
        def __init__(self, **kwargs): pass
        def exchange_code_for_token(self, code): return {"access_token":"bc-access", "refresh_token":"bc-refresh", "expires_in":1209600}
        def get_identity(self, access): return {"identity":{"id": "person-a"}, "accounts":[{"product":"bc3", "id":123}]}
    monkeypatch.setattr(multi_user_auth, "BasecampOAuth", FakeOAuth)
    async def run():
        client = _client(); await provider.register_client(client)
        params = AuthorizationParams(state="claude-state", scopes=["basecamp"], code_challenge="challenge", redirect_uri="https://claude.ai/callback", redirect_uri_provided_explicitly=True)
        url = await provider.authorize(client, params)
        state = url.split("state=")[1]
        scope = {"type":"http", "method":"GET", "path":"/basecamp/callback", "query_string":f"state={state}&code=basecamp-code".encode(), "headers":[]}
        response = await provider.callback(__import__('starlette.requests',fromlist=['Request']).Request(scope))
        assert response.status_code == 302
        assert "state=claude-state" in response.headers["location"]
        code = response.headers["location"].split("code=")[1].split("&")[0]
        assert (await provider.load_authorization_code(client, code)).subject == "person-a"
    asyncio.run(run())
