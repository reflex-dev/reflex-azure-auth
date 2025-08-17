# reflex-azure-auth

This package requires the `reflex_enterprise` package to be installed.

## Installation

```bash
pip install reflex-azure-auth
```

## Usage

### Set Up an Azure (Microsoft identity platform) Application

Create a new Application (App Registration) in the Azure portal and set up a .env file with the following variables:

```env
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret
AZURE_ISSUER_URI=your tenant issuer or authority URL
```

Reflex will need to access these variables to authenticate users via OpenID Connect on the Microsoft identity platform.

#### Step-by-step: App Registration

1. Sign in to the Azure portal and open "Azure Active Directory" → "App registrations".
2. Click "New registration".
    - Name: choose a friendly name (example: "Reflex Demo App").
    - Supported account types: choose the tenant(s) you want (single or multi-tenant).
    - Redirect URI: add the authorization callback path for your app, e.g. `https://your-app.example.com/authorization-code/callback` (use `http://localhost:3000/authorization-code/callback` for local development).
3. Register the app and copy the "Application (client) ID" → this is `AZURE_CLIENT_ID`.
4. Under "Certificates & secrets" create a new client secret and copy the value → this is `AZURE_CLIENT_SECRET`.
5. Under "Expose an API" or "API permissions" add the scopes your app needs. For typical OpenID Connect sign-in, request the `openid`, `profile`, and `email` scopes. If you need access to a custom API, expose an application ID URI (e.g. `api://<client-id>`) and create delegated scopes.
6. Determine your issuer (authority) URL:
    - For a single tenant: `https://login.microsoftonline.com/<your-tenant-id>`
    - For common/multi-tenant flows: `https://login.microsoftonline.com/common`
    Use the `AZURE_ISSUER_URI` env var to set this (you can include the `/v2.0` suffix or we default to `v2.0` for endpoint assembly).

Example .env (local development):

```env
AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000
AZURE_CLIENT_SECRET=very-secret-value
AZURE_ISSUER_URI=https://login.microsoftonline.com/common
AZURE_AUDIENCE=api://default
```

Notes:
- Redirect URIs must match exactly. For Reflex demo pages running locally, use the full local URL including the `/authorization-code/callback` path.
- Use `openid email profile` in the authorization request to receive an ID token containing standard claims (sub, name, email).
- When testing with a real tenant, use the tenant-specific issuer URL (recommended for production).

### Register Auth Callback

```python
from reflex_enterprise import App
from reflex_azure_auth import register_auth_endpoints

...

app = App()
register_auth_endpoints(app)
```

### Check `AzureAuthState.userinfo` for user identity/validity

```python
import reflex as rx
from reflex_azure_auth import AzureAuthState

@rx.page()
def index():
    return rx.container(
        rx.vstack(
            rx.heading("Azure (Microsoft) Auth Demo"),
            rx.cond(
                rx.State.is_hydrated,
                rx.cond(
                    AzureAuthState.userinfo,
                    rx.vstack(
                        rx.text(f"Welcome, {AzureAuthState.userinfo["name"]}!"),
                        rx.text(AzureAuthState.userinfo.to_string()),
                        rx.button("Logout", on_click=AzureAuthState.redirect_to_logout),
                    ),
                    rx.button("Log In with Microsoft", on_click=AzureAuthState.redirect_to_login),
                ),
                rx.spinner(),
            ),
        ),
    )
```

### Validate the Tokens

tokens to ensure they have not been tampered with. Use
Before performing privileged backend operations, it is important to validate the
tokens to ensure they have not been tampered with. Use
`AzureAuthState._validate_tokens()` helper method to validate the tokens.
