"""Helpers to register authentication endpoints on a Reflex Enterprise app."""

from typing import Callable

import reflex as rx
from reflex_enterprise import App

from .state import AzureAuthState
from .ui import (
    _authentication_loading_page,
    _authentication_logout,
    _authentication_popup,
)


def register_auth_endpoints(
    app: App,
    loading_page: Callable[[], rx.Component] = _authentication_loading_page,
):
    """Register the Azure (Microsoft identity platform) authentication endpoints with the Reflex app.

    This function sets up the necessary OAuth callback endpoint for handling
    authentication responses from the Microsoft identity platform. The callback
    endpoint handles the authorization code exchange and redirects users.
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
    app.add_page(
        _authentication_popup,
        route="/popup-login",
        on_load=AzureAuthState.redirect_to_login,
        title="Azure Auth Initiator",
    )
    app.add_page(
        _authentication_logout,
        route="/popup-logout",
        on_load=AzureAuthState.redirect_to_logout,
        title="Azure Auth Logout",
    )
