"""Helpers to register authentication endpoints on a Reflex Enterprise app."""

from typing import Callable

import reflex as rx
from reflex_enterprise import App

from .state import (
    AUTHORIZATION_CODE_ENDPOINT,
    POPUP_LOGIN_ENDPOINT,
    POPUP_LOGOUT_ENDPOINT,
    AzureAuthState,
)
from .ui import _authentication_loading_page, _authentication_popup_logout


def register_auth_endpoints(
    app: App,
    loading_page: Callable[[], rx.Component] = _authentication_loading_page,
    popup_login_page: Callable[[], rx.Component] = _authentication_loading_page,
    popup_logout_page: Callable[[], rx.Component] = _authentication_popup_logout,
):
    """Register the Azure (Microsoft identity platform) authentication endpoints with the Reflex app.

    This function sets up the necessary OAuth callback endpoint for handling
    authentication responses from the Microsoft identity platform. The callback
    endpoint handles the authorization code exchange and redirects users.
    """
    if not isinstance(app, App):
        raise TypeError("The app must be an instance of reflex_enterprise.App.")
    app.add_page(
        loading_page,
        route=AUTHORIZATION_CODE_ENDPOINT,
        on_load=AzureAuthState.auth_callback,
        title="Azure Auth Callback",
    )
    app.add_page(
        popup_login_page,
        route=POPUP_LOGIN_ENDPOINT,
        on_load=AzureAuthState.redirect_to_login,
        title="Azure Auth Initiator",
    )
    app.add_page(
        popup_logout_page,
        route=POPUP_LOGOUT_ENDPOINT,
        on_load=AzureAuthState.redirect_to_logout,
        title="Azure Auth Logout",
    )
