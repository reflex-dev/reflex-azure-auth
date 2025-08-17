"""Welcome to Reflex! This file outlines the steps to create a basic app."""

import reflex as rx
import reflex_enterprise as rxe

from reflex_azure_auth import AzureAuthState, register_auth_endpoints


def index():
    return rx.container(
        rx.vstack(
            rx.heading("Azure (Microsoft) Auth Demo"),
            rx.cond(
                rx.State.is_hydrated,
                rx.cond(
                    AzureAuthState.userinfo,
                    rx.vstack(
                        rx.text(f"Welcome, {AzureAuthState.userinfo['name']}!"),
                        rx.text(AzureAuthState.userinfo.to_string()),
                        rx.button("Logout", on_click=AzureAuthState.redirect_to_logout),
                    ),
                    rx.button(
                        "Log In with Microsoft",
                        on_click=AzureAuthState.redirect_to_login,
                    ),
                ),
                rx.spinner(),
            ),
        ),
    )


app = rxe.App()
app.add_page(index, title="Azure (Microsoft) Auth Demo")
register_auth_endpoints(app)
