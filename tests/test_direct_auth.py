import asyncio
import base64
import hashlib
import json
import re
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastmcp import FastMCP

from paperless_mcp_oidc import server
from paperless_mcp_oidc.config import Settings
from paperless_mcp_oidc.direct_auth import DirectAuthProvider

MCP = "https://mcp.example.com"
PAPERLESS = "https://paperless.example.com"
CALLBACK = "https://client.example.com/callback"
VERIFIER = "a" * 43
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")


@asynccontextmanager
async def make_client(provider):
    mcp = FastMCP("Test", auth=provider)

    @mcp.tool
    async def read_documents() -> dict:
        paperless = await server.get_client()
        return {
            "documents": await paperless.get("/api/documents/"),
            "outbox": Path(paperless.outbox_dir).name,
        }

    app = mcp.http_app(path="/mcp", stateless_http=True, json_response=True)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=MCP,
        ) as client,
    ):
        yield client


async def register(client):
    response = await client.post(
        "/register",
        json={
            "client_name": "<Client>",
            "redirect_uris": [CALLBACK],
            "token_endpoint_auth_method": "none",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["client_id"]


async def login(client, client_id, credentials):
    begin = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": CALLBACK,
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            "state": "client-state",
            "resource": f"{MCP}/mcp",
        },
    )
    assert begin.status_code == 302, begin.text
    url = begin.headers["location"]
    page = await client.get(url)
    assert page.status_code == 200
    assert "&lt;Client&gt;" in page.text
    assert "no-store" in page.headers["cache-control"]
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    form = {"csrf": csrf, **credentials}
    rejected = await client.post(url, data=form, headers={"Origin": "https://other.example.com"})
    assert rejected.status_code == 403
    response = await client.post(url, data=form, headers={"Origin": MCP})
    return response, url, form


@pytest.fixture
def config(tmp_path):
    return Settings(
        auth_mode="direct",
        paperless_base_url=PAPERLESS,
        mcp_base_url=MCP,
        direct_auth_db_path=str(tmp_path / "auth.sqlite"),
        paperless_outbox_dir=str(tmp_path / "outbox"),
        paperless_host_header="paperless.internal",
        paperless_api_token="shared-token",
    )


@pytest.mark.parametrize("use_password", [True, False])
async def test_direct_oauth_flow(config, monkeypatch, respx_mock, use_password):
    monkeypatch.setattr(server, "settings", config)
    provider = server._build_auth()
    monkeypatch.setattr(server, "_auth", provider)
    api_token = "paperless-token"
    upstream_login = respx_mock.post(f"{PAPERLESS}/api/token/").respond(json={"token": api_token})
    upstream_profile = respx_mock.get(f"{PAPERLESS}/api/ui_settings/").respond(json={"user": {"id": 42}})
    credentials = (
        {"username": "alice", "password": "my-password", "mfa": "123456"}
        if use_password
        else {"api_key": api_token}
    )
    async with make_client(provider) as client:
        discovery = await client.get("/.well-known/oauth-protected-resource/mcp")
        assert discovery.json()["resource"] == f"{MCP}/mcp"
        unauthorized = await client.post("/mcp", json={})
        assert unauthorized.status_code == 401
        client_id = await register(client)
        other_id = await register(client)
        response, url, form = await login(client, client_id, credentials)
        assert response.status_code == 303, response.text
        assert api_token not in response.headers["location"]
        query = parse_qs(urlsplit(response.headers["location"]).query)
        assert query["state"] == ["client-state"]
        code = query["code"][0]
        replay = await client.post(url, data=form, headers={"Origin": MCP})
        assert replay.status_code == 400
        exchange = {
            "client_id": client_id,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": VERIFIER,
            "redirect_uri": CALLBACK,
        }
        for invalid in ({"client_id": other_id}, {"code_verifier": "b" * 43}):
            result = await client.post("/token", data={**exchange, **invalid})
            assert result.json()["error"] == "invalid_grant"
        wrong_resource = await client.post(
            "/token", data={**exchange, "resource": "https://elsewhere.test/mcp"}
        )
        assert wrong_resource.json()["error"] == "invalid_target"
        issued = await client.post("/token", data={**exchange, "resource": f"{MCP}/mcp"})
        assert issued.status_code == 200, issued.text
        replay = await client.post("/token", data=exchange)
        assert replay.json()["error"] == "invalid_grant"
        first = issued.json()
        access = await provider.verify_token(first["access_token"])
        assert access.subject == "paperless-42"
        assert access.resource == f"{MCP}/mcp"
        assert api_token not in issued.text

    if use_password:
        assert json.loads(upstream_login.calls.last.request.content) == {
            "username": "alice",
            "password": "my-password",
            "code": "123456",
        }
    else:
        assert not upstream_login.called
    assert upstream_profile.calls.last.request.headers["Authorization"] == f"Token {api_token}"
    assert upstream_profile.calls.last.request.headers["Host"] == "paperless.internal"

    restarted = DirectAuthProvider(config)
    monkeypatch.setattr(server, "_auth", restarted)
    documents = respx_mock.get(f"{PAPERLESS}/api/documents/").respond(json={"results": []})
    async with make_client(restarted) as client:
        result = await client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {first['access_token']}",
                "Accept": "application/json, text/event-stream",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_documents", "arguments": {}},
            },
        )
        assert result.status_code == 200, result.text
        assert result.json()["result"]["structuredContent"] == {
            "documents": {"results": []},
            "outbox": server.outbox_segment("paperless-42"),
        }
        assert documents.calls.last.request.headers["Authorization"] == f"Token {api_token}"
        refresh = {
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": first["refresh_token"],
        }
        wrong_client = await client.post("/token", data={**refresh, "client_id": other_id})
        assert wrong_client.json()["error"] == "invalid_grant"
        results = await asyncio.gather(*(client.post("/token", data=refresh) for _ in range(2)))
        assert sum(result.status_code == 200 for result in results) == 1
        second = next(result.json() for result in results if result.status_code == 200)
        assert await restarted.verify_token(first["access_token"]) is None
        assert await restarted.verify_token(second["access_token"]) is not None
        revoked = await client.post(
            "/revoke", data={"client_id": client_id, "token": second["refresh_token"]}
        )
        assert revoked.status_code == 200
        assert await restarted.verify_token(second["access_token"]) is None


async def test_direct_login_rejects_invalid_key(config, respx_mock):
    upstream = respx_mock.get(f"{PAPERLESS}/api/ui_settings/").respond(401)
    async with make_client(DirectAuthProvider(config)) as client:
        response, _, _ = await login(client, await register(client), {"api_key": "bad-token"})
    assert upstream.called
    assert response.status_code == 401
    assert "bad-token" not in response.text
    assert "location" not in response.headers
