"""UI helpers and components for Azure auth pages and buttons."""

import reflex as rx

from .message_listener import message_listener
from .state import AzureAuthState


def azure_login_button(*children) -> rx.Component:
    """Return a login button component that initiates Azure auth.

    If `children` are provided they will be placed inside the clickable
    element; otherwise a default button label is used. The component wires up
    the message listener (for iframe flows), the click handler, and a mount
    handler that checks whether the page is embedded in an iframe.
    """
    if not children:
        children = [rx.button("Login with Microsoft")]
    return rx.el.div(
        *children,
        rx.cond(
            AzureAuthState.is_iframed,
            message_listener(
                allowed_origin=AzureAuthState.origin,
                on_message=AzureAuthState.on_iframe_auth_success,
            ),
        ),
        on_click=AzureAuthState.redirect_to_login,
        on_mount=AzureAuthState.check_if_iframed,
    )


def _authentication_loading_page() -> rx.Component:
    """Small loading page shown while authentication is validated.

    This page is registered by the package as the callback target when the
    authorization response is being processed.
    """
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


def _authentication_popup_logout() -> rx.Component:
    """Simple page shown during the logout flow.

    Registered at `/reflex-azure-auth/popup-logout` to complete the sign-out handshake.
    """
    return rx.container(
        rx.heading("Complete logout process."),
    )
