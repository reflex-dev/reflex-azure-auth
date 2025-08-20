"""Reflex state for Azure authentication."""

import base64
import datetime
import hashlib
import secrets
from urllib.parse import urlencode, urlparse

import httpx
import reflex as rx

from .config import client_id, client_secret
from .message_listener import WindowMessage
from .oidc import (
    _compute_at_hash,
    _get_jwt_header_payload,
    azure_issuer_endpoint,
    azure_issuer_uri,
    verify_jwt,
)
from .types import AzureUserInfo, user_info_from_dict


class AzureAuthState(rx.State):
    """Reflex state class for managing Azure (Microsoft) authentication.

    This state class implements the OAuth 2.0 Authorization Code flow with
    PKCE for the Microsoft identity platform, including token storage,
    validation, and user information retrieval.
    """

    access_token: str = rx.Cookie()
    id_token: str = rx.Cookie()

    app_state: str
    code_verifier: str
    nonce: str
    redirect_to_url: str
    error_message: str

    is_iframed: bool = False
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
                    datetime.datetime.now(datetime.timezone.utc).timestamp()
                ):
                    return False
        except Exception:
            return False

        if expiration_only:
            return True

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
            ) and at_hash_claim != self._expected_at_hash:
                print("at_hash mismatch")  # noqa: T201
                return False
        except Exception:
            return False

        return True

    async def _update_userinfo(self):
        if not await self._validate_tokens(expiration_only=True):
            self.access_token = ""
            self.id_token = ""
            return None

        # Get the latest userinfo
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                await azure_issuer_endpoint("userinfo_endpoint"),
                headers={"Authorization": f"Bearer {self.access_token}"},
            )
            try:
                resp.raise_for_status()
                return user_info_from_dict(resp.json())
            except Exception:
                self.access_token = ""
                self.id_token = ""
            return None

    @rx.var(interval=datetime.timedelta(minutes=30))
    async def userinfo(self) -> AzureUserInfo | None:
        """Get the authenticated user's information from the Microsoft identity platform.

        This property retrieves the user's profile information from the
        userinfo endpoint using the stored access token. The result is cached
        for 30 minutes and automatically revalidated.
        """
        return await self._update_userinfo()

    def _redirect_uri(self) -> str:
        current_url = urlparse(self.router.url)
        return current_url._replace(
            path="/authorization-code/callback", query=None, fragment=None
        ).geturl()

    def _index_uri(self) -> str:
        current_url = urlparse(self.router.url)
        return current_url._replace(path="/", query=None, fragment=None).geturl()

    @rx.event
    async def redirect_to_login_popup(self):
        """Open a small popup window to initiate the login flow.

        This is used when the app detects it's embedded and needs to open a
        dedicated popup for the authorization flow.
        """
        return rx.call_script(
            "window.open('/popup-login', 'login', 'width=600,height=600')"
        )

    @rx.event
    async def redirect_to_logout_popup(self):
        """Open a small popup window to initiate the logout flow."""
        return rx.call_script(
            "window.open('/popup-logout', 'logout', 'width=600,height=600')"
        )

    @rx.event
    async def redirect_to_login(self):
        """Initiate the OAuth 2.0 authorization code flow with PKCE against Azure.

        Generates state and code verifier, builds the authorization URL, and
        redirects the user to the Microsoft authorization endpoint.
        """
        if self.is_iframed:
            return type(self).redirect_to_login_popup()
        if await self._validate_tokens():
            return rx.toast("You are logged in.")

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
        if self.is_iframed:
            return type(self).redirect_to_logout_popup()

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
        await self._set_tokens(
            access_token=exchange["access_token"],
            id_token=exchange["id_token"],
        )

        return rx.redirect(self.redirect_to_url)

    async def _set_tokens(self, access_token: str, id_token: str):
        self.access_token = access_token
        self.id_token = id_token

        # compute at_hash and store for additional validation
        try:
            header = _get_jwt_header_payload(self.id_token)[0]
            alg = header.get("alg")
            at_hash = _compute_at_hash(self.access_token, alg)
            # store expected at_hash in a transient property (not persisted)
            self._expected_at_hash = at_hash
        except Exception:
            self._expected_at_hash = None

        await self._validate_tokens()

    @rx.var
    def origin(self) -> str:
        """Return the app origin URL (used as postMessage target origin)."""
        return self._index_uri().rstrip("/")

    @rx.event
    def check_if_iframed(self):
        """Run a short client-side check to determine whether the page is iframed.

        The result is reported to `check_if_iframed_cb`.
        """
        return rx.call_function(
            """() => {
    try {
        return window.self !== window.top;
    } catch (e) {
        // This catch block handles potential security errors (Same-Origin Policy)
        // if the iframe content and the parent are from different origins.
        // In such cases, access to window.top might be restricted, implying it's in an iframe.
        return true;
    }
}""",
            callback=type(self).check_if_iframed_cb,
        )

    @rx.event
    def check_if_iframed_cb(self, is_iframed: bool):
        """Callback invoked with the iframe detection result.

        Args:
            is_iframed: True if the page is inside an iframe or cross-origin
                access prevented detection.
        """
        self.is_iframed = is_iframed

    @rx.event
    async def on_iframe_auth_success(self, event: WindowMessage):
        """Handle an authentication success message posted from a child window.

        The message payload is expected to include `access_token`, `id_token`,
        and an optional `nonce`. Tokens are stored via `_set_tokens`.
        """
        if event["data"].get("type") != "auth":
            return
        self.nonce = event["data"].get("nonce", self.nonce)
        await self._set_tokens(
            access_token=event["data"].get("access_token"),
            id_token=event["data"].get("id_token"),
        )

    @rx.event
    def post_auth_message(self):
        """Post tokens back to the opening window and close the popup.

        This is called on the popup page when authentication has completed and
        the tokens are available in `self.access_token` / `self.id_token`.
        """
        payload = {
            "type": "auth",
            "access_token": self.access_token,
            "id_token": self.id_token,
            "nonce": self.nonce,
        }
        return [
            rx.call_function(
                rx.vars.FunctionStringVar.create("window.opener.postMessage")(
                    payload, self.origin
                )
            ),
            rx.call_script("window.setTimeout(() => window.close(), 500)"),
        ]
