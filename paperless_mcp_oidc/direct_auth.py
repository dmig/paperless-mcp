"""First-party OAuth login backed by each user's Paperless API token."""

import asyncio
import html
import json
import re
import secrets
import time
from urllib.parse import parse_qs, urlsplit

import httpx
from fastmcp.server.auth import AccessToken, OAuthProvider
from fastmcp.server.auth.auth import TokenHandler
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.routes import cors_middleware
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import BaseModel
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from .config import Settings
from .direct_store import DirectStore, digest

LOGIN_PATH = "/paperless-login"
LOGIN_TTL = 600
CODE_TTL = 120
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 86400
FORM_LIMIT = 8192
BROWSER_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
}
OAUTH_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class LoginRequest(BaseModel):
    client_id: str
    client_name: str
    params: AuthorizationParams
    resource: str


class PaperlessLoginError(Exception):
    pass


class DirectAuthProvider(OAuthProvider):
    def __init__(self, config: Settings):
        super().__init__(
            base_url=config.mcp_base_url,
            client_registration_options=ClientRegistrationOptions(enabled=True),
            revocation_options=RevocationOptions(enabled=True),
        )
        self.store = DirectStore(config.direct_auth_db_path)
        self.paperless_url = config.paperless_base_url.rstrip("/")
        self.paperless_headers = {"Accept": "application/json"}
        if config.paperless_host_header:
            self.paperless_headers["Host"] = config.paperless_host_header
        self.timeout = config.http_timeout_seconds
        self.login_url = config.mcp_base_url.rstrip("/") + LOGIN_PATH
        base = urlsplit(config.mcp_base_url)
        self.origin = f"{base.scheme}://{base.netloc}"
        self.secure_cookie = base.scheme == "https"

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        routes = super().get_routes(mcp_path)
        return [
            *(route for route in routes if route.path not in {"/token", "/revoke"}),
            Route("/token", cors_middleware(self.exchange, ["POST", "OPTIONS"]), methods=["POST", "OPTIONS"]),
            Route("/revoke", cors_middleware(self.revoke, ["POST", "OPTIONS"]), methods=["POST", "OPTIONS"]),
            Route(LOGIN_PATH, self.login, methods=["GET", "POST"]),
        ]

    async def exchange(self, request: Request) -> Response:
        form = await request.form()
        resources = form.getlist("resource")
        if resources and resources != [str(self._resource_url)]:
            return JSONResponse({"error": "invalid_target"}, status_code=400, headers=OAUTH_HEADERS)
        return await TokenHandler(provider=self, client_authenticator=ClientAuthenticator(self)).handle(
            request
        )

    async def revoke(self, request: Request) -> Response:
        # The SDK revocation model requires a form client_secret even for public clients.
        try:
            client = await ClientAuthenticator(self).authenticate_request(request)
        except AuthenticationError:
            return JSONResponse({"error": "invalid_client"}, status_code=401, headers=OAUTH_HEADERS)
        token = (await request.form()).get("token")
        if not isinstance(token, str) or not token:
            return JSONResponse({"error": "invalid_request"}, status_code=400, headers=OAUTH_HEADERS)
        await asyncio.to_thread(self.store.revoke, token, client.client_id)
        return Response(status_code=200, headers=OAUTH_HEADERS)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        row = await asyncio.to_thread(self.store.state, "client", client_id)
        return OAuthClientInformationFull.model_validate_json(row["data"]) if row else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        for uri in client_info.redirect_uris or []:
            loopback = uri.host in {"127.0.0.1", "[::1]", "localhost"}
            if (
                not uri.host
                or uri.fragment is not None
                or uri.username is not None
                or uri.password is not None
                or (uri.scheme != "https" and not (uri.scheme == "http" and loopback))
            ):
                raise RegistrationError("invalid_redirect_uri", "Use an HTTPS or loopback HTTP redirect URI.")
        await asyncio.to_thread(
            self.store.remember, "client", client_info.client_id, client_info.model_dump_json()
        )

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        resource = str(self._resource_url) if self._resource_url else None
        if not resource or (params.resource is not None and params.resource != resource):
            raise AuthorizeError("invalid_target", "Use this server's MCP resource URL.")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.code_challenge):
            raise AuthorizeError("invalid_request", "A valid S256 PKCE challenge is required.")
        flow = secrets.token_urlsafe(32)
        login = LoginRequest(
            client_id=client.client_id,
            client_name=client.client_name or "MCP client",
            params=params,
            resource=resource,
        )
        await asyncio.to_thread(
            self.store.remember, "login", digest(flow), login.model_dump_json(), int(time.time()) + LOGIN_TTL
        )
        return f"{self.login_url}?flow={flow}"

    async def login(self, request: Request) -> Response:
        flow = request.query_params.get("flow", "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", flow):
            return self._expired()
        row = await asyncio.to_thread(self.store.state, "login", digest(flow))
        if row is None:
            return self._expired()
        login = LoginRequest.model_validate_json(row["data"])
        cookie = f"{'__Host-' if self.secure_cookie else ''}paperless-login-{flow}"
        if request.method == "GET":
            csrf = secrets.token_urlsafe(32)
            response = self._page(login, csrf)
            response.set_cookie(
                cookie, csrf, max_age=LOGIN_TTL, httponly=True, secure=self.secure_cookie, samesite="strict"
            )
            return response

        if request.headers.get("origin") != self.origin or not request.cookies.get(cookie):
            return HTMLResponse("Open the login page again.", 403, headers=BROWSER_HEADERS)
        form = await self._read_form(request)
        csrf = form.get("csrf", "")
        if not secrets.compare_digest(csrf.encode(), request.cookies[cookie].encode()):
            return HTMLResponse("Open the login page again.", 403, headers=BROWSER_HEADERS)
        try:
            paperless_token, subject = await self._authenticate(form)
        except PaperlessLoginError as exc:
            return self._page(login, csrf, str(exc), 401)
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
            return self._page(login, csrf, "Paperless sign-in is temporarily unavailable.", 502)

        code = secrets.token_urlsafe(32)
        expires = int(time.time()) + CODE_TTL
        authorization = AuthorizationCode(
            code=digest(code),
            client_id=login.client_id,
            scopes=login.params.scopes or [],
            expires_at=expires,
            code_challenge=login.params.code_challenge,
            redirect_uri=login.params.redirect_uri,
            redirect_uri_provided_explicitly=login.params.redirect_uri_provided_explicitly,
            resource=login.resource,
            subject=subject,
        )
        saved = await asyncio.to_thread(
            self.store.complete_login, flow, code, authorization.model_dump_json(), expires, paperless_token
        )
        if not saved:
            return self._expired()
        response = RedirectResponse(
            construct_redirect_uri(str(login.params.redirect_uri), code=code, state=login.params.state),
            status_code=303,
            headers=BROWSER_HEADERS,
        )
        response.delete_cookie(cookie, secure=self.secure_cookie, httponly=True, samesite="strict")
        return response

    @staticmethod
    async def _read_form(request: Request) -> dict[str, str]:
        if request.headers.get("content-type", "").split(";")[0] != "application/x-www-form-urlencoded":
            return {}
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > FORM_LIMIT:
                return {}
            body.extend(chunk)
        try:
            return {k: v[0] for k, v in parse_qs(body.decode(), max_num_fields=8).items() if len(v) == 1}
        except ValueError:
            return {}

    @staticmethod
    def _expired() -> HTMLResponse:
        return HTMLResponse(
            "This login request has expired. Reconnect from your MCP client.", 400, headers=BROWSER_HEADERS
        )

    @staticmethod
    def _page(login: LoginRequest, csrf: str, error: str = "", status: int = 200) -> HTMLResponse:
        client = html.escape(login.client_name)
        destination = html.escape(str(login.params.redirect_uri))
        hidden = f'<input type="hidden" name="csrf" value="{html.escape(csrf, quote=True)}">'
        message = f'<p role="alert">{html.escape(error)}</p>' if error else ""
        return HTMLResponse(
            f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Paperless sign-in</title></head>
<body><main>
<h1>Sign in to Paperless</h1>
<p>Signing in gives {client} access to Paperless with your account permissions.</p>
<p>Client callback: <bdi>{destination}</bdi></p>
{message}
<h2>Username and password</h2>
<form method="post">{hidden}
<p><label>Username <input name="username" autocomplete="username" required></label></p>
<p><label>Password
<input type="password" name="password" autocomplete="current-password" required></label></p>
<p><label>MFA code (if enabled) <input name="mfa" autocomplete="one-time-code"></label></p>
<button type="submit">Sign in and authorize</button>
</form>
<h2>Paperless API key</h2>
<form method="post" autocomplete="off">{hidden}
<p><label>API key <input type="password" name="api_key" required></label></p>
<button type="submit">Authorize with API key</button>
</form></main></body></html>""",
            status_code=status,
            headers=BROWSER_HEADERS,
        )

    async def _authenticate(self, form: dict[str, str]) -> tuple[str, str]:
        api_key = form.get("api_key", "").strip()
        username, password = form.get("username", "").strip(), form.get("password", "")
        rejected = "Paperless did not accept those credentials. Check your login or API key."
        async with httpx.AsyncClient(timeout=self.timeout, headers=self.paperless_headers) as client:
            if api_key:
                if username or password:
                    raise PaperlessLoginError("Choose one sign-in method.")
            else:
                if not username or not password:
                    raise PaperlessLoginError("Enter your Paperless credentials or API key.")
                credentials = {"username": username, "password": password}
                if form.get("mfa", "").strip():
                    credentials["code"] = form["mfa"].strip()
                response = await client.post(f"{self.paperless_url}/api/token/", json=credentials)
                if response.status_code in (400, 401, 403):
                    raise PaperlessLoginError(rejected)
                response.raise_for_status()
                api_key = response.json()["token"]

            if not isinstance(api_key, str) or not re.fullmatch(r"[!-~]{1,256}", api_key):
                raise PaperlessLoginError(rejected)
            subject = await self._paperless_subject(client, api_key)
            if subject is None:
                raise PaperlessLoginError(rejected)
            return api_key, subject

    async def _paperless_subject(self, client: httpx.AsyncClient, api_key: str) -> str | None:
        response = await client.get(
            f"{self.paperless_url}/api/ui_settings/", headers={"Authorization": f"Token {api_key}"}
        )
        if response.status_code in (401, 403):
            return None
        response.raise_for_status()
        user_id = response.json()["user"]["id"]
        if type(user_id) is not int or user_id <= 0:
            raise ValueError("Invalid Paperless user identifier")
        return f"paperless-{user_id}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        row = await asyncio.to_thread(self.store.state, "code", digest(authorization_code))
        if row:
            code = AuthorizationCode.model_validate_json(row["data"])
            if code.client_id == client.client_id:
                return code.model_copy(update={"code": authorization_code})
        return None

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        return await self._issue(authorization_code.code, authorization_code, authorization_code.scopes)

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        row = await asyncio.to_thread(self.store.grant, refresh_token, refresh=True)
        if row and row["client_id"] == client.client_id:
            return RefreshToken(
                token=refresh_token,
                client_id=row["client_id"],
                scopes=json.loads(row["scopes"]),
                expires_at=row["refresh_expires"],
                resource=row["resource"],
                subject=row["subject"],
            )
        return None

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        row = await asyncio.to_thread(self.store.grant, refresh_token.token, refresh=True)
        if row is None or row["client_id"] != client.client_id:
            raise TokenError("invalid_grant", "The refresh token expired or was already used.")
        try:
            async with httpx.AsyncClient(timeout=self.timeout, headers=self.paperless_headers) as http:
                subject = await self._paperless_subject(http, row["paperless_token"])
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
            raise HTTPException(503, "Paperless is temporarily unavailable.") from None
        if subject != refresh_token.subject:
            await self.revoke_token(refresh_token)
            raise TokenError("invalid_grant", "The Paperless authorization is no longer valid.")
        return await self._issue(refresh_token.token, refresh_token, scopes)

    async def _issue(
        self, previous: str, grant: AuthorizationCode | RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = int(time.time())
        if grant.resource != str(self._resource_url):
            raise TokenError("invalid_grant", "The grant belongs to a different MCP resource.")
        refresh_expires = now + REFRESH_TTL if isinstance(grant, AuthorizationCode) else grant.expires_at
        if refresh_expires is None or refresh_expires <= now:
            raise TokenError("invalid_grant", "The grant has expired.")
        access_expires = min(now + ACCESS_TTL, refresh_expires)
        saved = await asyncio.to_thread(
            self.store.issue,
            previous,
            access,
            refresh,
            access_expires,
            refresh_expires,
            grant.client_id,
            grant.subject,
            json.dumps(scopes),
            grant.resource,
            rotate=isinstance(grant, RefreshToken),
        )
        if not saved:
            raise TokenError("invalid_grant", "The grant has expired or was already used.")
        return OAuthToken(
            access_token=access,
            refresh_token=refresh,
            expires_in=access_expires - now,
            scope=" ".join(scopes) or None,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        row = await asyncio.to_thread(self.store.grant, token)
        if row and row["resource"] == str(self._resource_url):
            return AccessToken(
                token=token,
                client_id=row["client_id"],
                scopes=json.loads(row["scopes"]),
                expires_at=row["access_expires"],
                resource=row["resource"],
                subject=row["subject"],
            )
        return None

    async def paperless_token(self, token: AccessToken) -> str | None:
        row = await asyncio.to_thread(self.store.grant, token.token)
        if row and row["client_id"] == token.client_id and row["subject"] == token.subject:
            return row["paperless_token"]
        return None

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        await asyncio.to_thread(self.store.revoke, token.token, token.client_id)
