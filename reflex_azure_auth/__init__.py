"""Integrate Azure (Microsoft identity platform) authentication with Reflex applications.

This module implements a minimal OpenID Connect (OIDC) Authorization Code
flow with PKCE against the Microsoft identity platform (Azure AD). It exposes
an `AzureAuthState` Reflex state and helper functions to register the
authentication endpoints.
"""

import base64
import contextlib
import datetime
import hashlib
import json
import os
import secrets
from collections.abc import Callable
from typing import TypedDict
from urllib.parse import urlencode, urlparse

import httpx
import reflex as rx
from authlib.jose import JsonWebKey, jwt
from reflex_enterprise import App

# Simple cached OIDC metadata + JWKS loader
_OIDC_CACHE: dict[str, object] = {}


async def _fetch_oidc_metadata(issuer: str) -> dict:
    key = f"metadata:{issuer}"
    if key in _OIDC_CACHE:
        return _OIDC_CACHE[key]
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=10)
        resp.raise_for_status()
        md = resp.json()
        _OIDC_CACHE[key] = md
        print(md)
        return md


async def _fetch_jwks(jwks_uri: str) -> dict:
    key = f"jwks:{jwks_uri}"
    if key in _OIDC_CACHE:
        return _OIDC_CACHE[key]
    async with httpx.AsyncClient() as client:
        resp = await client.get(jwks_uri, timeout=10)
        resp.raise_for_status()
        jwks = resp.json()
        _OIDC_CACHE[key] = jwks
        return jwks


async def verify_jwt(
    token: str, audience: str | None = None, issuer: str | None = None
) -> dict:
    """Verify a JWT using OIDC discovery and JWKS per Microsoft docs.

    Returns the token claims if valid, otherwise raises.
    """
    if issuer is None:
        issuer = azure_issuer_uri()
    # fetch metadata
    md = await _fetch_oidc_metadata(issuer)
    jwks_uri = md.get("jwks_uri")
    if not jwks_uri:
        raise RuntimeError("jwks_uri not found in oidc metadata")
    jwks = await _fetch_jwks(jwks_uri)

    # Build JsonWebKey set
    key_set = JsonWebKey.import_key_set(jwks)

    # authlib expects a dict of options
    claims_options = {
        "iss": {"essential": True, "values": [issuer]},
    }
    if audience:
        # authlib will check aud if provided in options
        claims_options["aud"] = {"essential": True, "values": [audience]}

    claims = jwt.decode(token, key_set)
    # validate claims manually per MS guidance
    aud = claims.get("aud")
    if audience and aud != audience and (isinstance(aud, list) and audience not in aud):
        raise RuntimeError(f"Invalid audience: {claims.get('aud')} != {audience}")
    if claims.get("iss") != issuer:
        raise RuntimeError(f"Invalid issuer: {claims.get('iss')} != {issuer}")
    # expiration check
    exp = claims.get("exp")
    if exp is None or int(exp) < int(datetime.datetime.utcnow().timestamp()):
        raise RuntimeError("Token expired")
    return claims


def _b64_json_decode(payload: str) -> dict:
    """Decode a base64url-encoded JSON payload."""
    with contextlib.suppress(Exception):
        rem = len(payload) % 4
        if rem:
            payload += "=" * (4 - rem)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    return {}


def _get_jwt_header_payload(token: str) -> tuple[dict, dict]:
    """Return the JWT header without verifying the signature."""
    with contextlib.suppress(Exception):
        parts = token.split(".")
        if len(parts) < 2:
            return {}, {}
        return (
            _b64_json_decode(parts[0]),
            _b64_json_decode(parts[1]),
        )
    return {}


def _compute_at_hash(access_token: str, alg: str | None) -> str:
    """Compute at_hash value per OIDC spec for a given access token and alg."""
    if not alg:
        alg = "RS256"
    # map alg to hash
    if alg.endswith("256"):
        h = hashlib.sha256(access_token.encode("utf-8")).digest()
    elif alg.endswith("384"):
        h = hashlib.sha384(access_token.encode("utf-8")).digest()
    elif alg.endswith("512"):
        h = hashlib.sha512(access_token.encode("utf-8")).digest()
    else:
        h = hashlib.sha256(access_token.encode("utf-8")).digest()
    # left-most half
    half = h[: len(h) // 2]
    at_hash = base64.urlsafe_b64encode(half).decode("ascii").rstrip("=")
    return at_hash


def client_id() -> str:
    """Get the Azure client ID from environment variables.

    Returns:
        The Azure client ID from the AZURE_CLIENT_ID environment variable,
        or an empty string if not set.
    """
    return os.environ.get("AZURE_CLIENT_ID", "")


def client_secret() -> str:
    """Get the Azure client secret from environment variables.

    Returns:
        The Azure client secret from the AZURE_CLIENT_SECRET environment variable,
        or an empty string if not set.
    """
    return os.environ.get("AZURE_CLIENT_SECRET", "")


def audience() -> str:
    """Get the Azure audience (optional) from environment variables.

    Returns:
        The audience from the AZURE_AUDIENCE environment variable,
        or "api://default" if not set.
    """
    return os.environ.get("AZURE_AUDIENCE", "api://default")


def azure_issuer_uri() -> str:
    """Construct an Azure issuer/authority endpoint URL for a given service.

    Args:
        service: The service endpoint name for the Microsoft identity platform
                 (e.g., 'authorize', 'token', 'userinfo', 'logout'). If None,
                 returns the base issuer/authority URL from environment.

    Returns:
        The complete URL for the specified endpoint.

    Raises:
        RuntimeError: If the AZURE_ISSUER_URI environment variable is not set.
    """
    azure_issuer_uri = os.environ.get("AZURE_ISSUER_URI")
    if not azure_issuer_uri:
        raise RuntimeError("AZURE_ISSUER_URI environment variable is not set.")
    return azure_issuer_uri


async def azure_issuer_endpoint(service: str) -> str:
    """Construct an Azure issuer/authority endpoint URL for a given service.

    Args:
        service: The service endpoint name for the Microsoft identity platform
                 (e.g., 'authorize', 'token', 'userinfo', 'logout'). If None,
                 returns the base issuer/authority URL from environment.

    Returns:
        The complete URL for the specified endpoint.

    Raises:
        RuntimeError: If the AZURE_ISSUER_URI environment variable is not set.
    """
    return (await _fetch_oidc_metadata(azure_issuer_uri()))[service]


class AzureUserInfo(TypedDict):
    """TypedDict representing user information from Azure / Microsoft identity platform.

    Contains user profile data returned by the /userinfo endpoint following
    successful authentication (OpenID Connect standard claims).
    """

    sub: str
    email: str | None
    name: str | None
    given_name: str | None
    middle_name: str | None
    family_name: str | None
    picture: str | None
    locale: str | None


# Microsoft API returns these without the underscore... not sure why
user_info_mapping = {
    "givenname": "given_name",
    "middlename": "middle_name",
    "familyname": "family_name",
}


def user_info_from_dict(data: dict) -> AzureUserInfo:
    """Convert a dictionary to an AzureUserInfo object."""
    for mapped_name, real_name in user_info_mapping.items():
        if mapped_name in data and real_name not in data:
            data[real_name] = data.pop(mapped_name)
    return AzureUserInfo(
        sub=data["sub"],
        email=data.get("email"),
        name=data.get("name"),
        given_name=data.get("given_name"),
        middle_name=data.get("middle_name"),
        family_name=data.get("family_name"),
        picture=data.get("picture"),
        locale=data.get("locale"),
    )


class AzureAuthState(rx.State):
    """Reflex state class for managing Azure (Microsoft) authentication.

    This state class implements the OAuth 2.0 Authorization Code flow with
    PKCE for the Microsoft identity platform, including token storage,
    validation, and user information retrieval.
    """

    access_token: str = rx.LocalStorage()
    id_token: str = rx.LocalStorage()

    app_state: str
    code_verifier: str
    nonce: str
    redirect_to_url: str
    error_message: str

    _requested_scopes: str = "openid email profile"
    _expected_at_hash: str | None = None

    async def _validate_tokens(self, expiration_only: bool = False) -> bool:
        if not self.access_token or not self.id_token:
            return False

        # Ensure token is not expired and verify signature/claims using OIDC
        try:
            if self.id_token:
                id_claims = _get_jwt_header_payload(self.id_token)[1]
                if int(id_claims.get("exp", 0)) < int(
                    datetime.datetime.utcnow().timestamp()
                ):
                    return False
        except Exception:
            return False

        if expiration_only:
            return True

        # NOTE: full token validation is not currently implemented.

        try:
            id_claims = await verify_jwt(
                self.id_token, audience=client_id(), issuer=azure_issuer_uri()
            )
        except Exception as e:
            print(f"ID token verification failed: {e}")  # noqa: T201
            return False

        # validate nonce
        try:
            if (
                hasattr(self, "nonce")
                and id_claims.get("nonce")
                and id_claims.get("nonce") != self.nonce
            ):
                print("Nonce mismatch")  # noqa: T201
                return False
        except Exception:
            return False

        # validate at_hash if present
        try:
            at_hash_claim = id_claims.get("at_hash")
            if (
                at_hash_claim
                and hasattr(self, "_expected_at_hash")
                and self._expected_at_hash
            ):
                if at_hash_claim != self._expected_at_hash:
                    print("at_hash mismatch")  # noqa: T201
                    return False
        except Exception:
            return False

        return True

    @rx.var(interval=datetime.timedelta(minutes=30))
    async def userinfo(self) -> AzureUserInfo | None:
        """Get the authenticated user's information from the Microsoft identity platform.

        This property retrieves the user's profile information from the
        userinfo endpoint using the stored access token. The result is cached
        for 30 minutes and automatically revalidated.
        """
        if not await self._validate_tokens(expiration_only=True):
            return None

        # Get the latest userinfo
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                await azure_issuer_endpoint("userinfo_endpoint"),
                headers={"Authorization": f"Bearer {self.access_token}"},
            )
            with contextlib.suppress(Exception):
                resp.raise_for_status()
                return user_info_from_dict(resp.json())
            return None

    def _redirect_uri(self) -> str:
        current_url = urlparse(self.router.url)
        return current_url._replace(
            path="/authorization-code/callback", query=None, fragment=None
        ).geturl()

    def _index_uri(self) -> str:
        current_url = urlparse(self.router.url)
        return current_url._replace(path="/", query=None, fragment=None).geturl()

    @rx.event
    async def redirect_to_login(self):
        """Initiate the OAuth 2.0 authorization code flow with PKCE against Azure.

        Generates state and code verifier, builds the authorization URL, and
        redirects the user to the Microsoft authorization endpoint.
        """
        # store app state and code verifier in session
        self.app_state = secrets.token_urlsafe(64)
        self.code_verifier = secrets.token_urlsafe(64)
        self.redirect_to_url = self.router.url

        # calculate code challenge
        hashed = hashlib.sha256(self.code_verifier.encode("ascii")).digest()
        encoded = base64.urlsafe_b64encode(hashed)
        code_challenge = encoded.decode("ascii").strip("=")

        # store nonce for ID token validation
        self.nonce = secrets.token_urlsafe(48)

        # get request params
        query_params = {
            "client_id": client_id(),
            "redirect_uri": self._redirect_uri(),
            "scope": self._requested_scopes,
            "state": self.app_state,
            "nonce": self.nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
            "response_mode": "query",
        }

        # build request_uri
        request_uri = f"{await azure_issuer_endpoint('authorization_endpoint')}?{urlencode(query_params)}"
        return rx.redirect(request_uri)

    @rx.event
    async def redirect_to_logout(self):
        """Initiate the OAuth 2.0 logout flow against Azure.

        Builds the logout URL with the ID token hint and redirects the user.
        """
        # store app state in session
        self.app_state = secrets.token_urlsafe(64)

        # get request params
        query_params = {
            "id_token_hint": self.id_token,
            "post_logout_redirect_uri": self._index_uri(),
            "state": self.app_state,
        }

        # build request_uri
        request_uri = f"{await azure_issuer_endpoint('end_session_endpoint')}?{urlencode(query_params)}"
        self.reset()
        return rx.redirect(request_uri)

    @rx.event
    async def auth_callback(self):
        """Handle the OAuth 2.0 authorization callback from Azure.

        Validates state, exchanges authorization code for tokens using PKCE,
        and stores tokens for future use.
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        code = self.router.page.params.get("code")
        app_state = self.router.page.params.get("state")
        if app_state != self.app_state:
            self.error_message = "App state mismatch. Possible CSRF attack."
            return rx.toast.error("Authentication error")
        if not code:
            self.error_message = "No code provided in the callback."
            return rx.toast.error("Authentication error")
        query_params = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._redirect_uri(),
            "code_verifier": self.code_verifier,
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                await azure_issuer_endpoint("token_endpoint"),
                headers=headers,
                data=query_params,
                auth=(client_id(), client_secret()),
            )
            exchange = resp.json()

        # Get tokens and validate
        if not exchange.get("token_type"):
            self.error_message = "Unsupported token type. Should be 'Bearer'."
            return rx.toast.error("Authentication error")
        self.access_token = exchange["access_token"]
        self.id_token = exchange["id_token"]

        # compute at_hash and store for additional validation
        try:
            header = _get_jwt_header_payload(self.id_token)[0]
            alg = header.get("alg")
            at_hash = _compute_at_hash(self.access_token, alg)
            # store expected at_hash in a transient property (not persisted)
            self._expected_at_hash = at_hash
        except Exception:
            self._expected_at_hash = None

        return rx.redirect(self.redirect_to_url)


def _authentication_loading_page() -> rx.Component:
    return rx.container(
        rx.vstack(
            rx.cond(
                ~rx.State.is_hydrated | ~AzureAuthState.userinfo,
                rx.hstack(
                    rx.heading("Validating Authentication..."),
                    rx.spinner(),
                    width="50%",
                    justify="between",
                ),
                rx.heading("Redirecting to app..."),
            ),
        ),
    )


def register_auth_endpoints(
    app: App,
    loading_page: Callable[[], rx.Component] = _authentication_loading_page,
):
    """Register the Azure (Microsoft identity platform) authentication endpoints with the Reflex app.

    This function sets up the necessary OAuth callback endpoint for handling
    authentication responses from the Microsoft identity platform. The callback
    endpoint handles the authorization code exchange and redirects users.

    Args:
        app: The Reflex Enterprise app instance to register endpoints with.
        loading_page: A callable that returns a Reflex component to display
                     while authentication is being processed. Defaults to
                     the built-in loading page.

    Raises:
        ValueError: If the app does not have an API configured.
        TypeError: If the app is not an instance of reflex_enterprise.App.
    """
    if app._api is None:
        raise ValueError("The app must have an API to register auth endpoints.")
    if not isinstance(app, App):
        raise TypeError("The app must be an instance of reflex_enterprise.App.")
    app.add_page(
        loading_page,
        route="/authorization-code/callback",
        on_load=AzureAuthState.auth_callback,
        title="Azure Auth Callback",
    )
