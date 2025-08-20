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
5. Under "Expose an API" or "API permissions" add the scopes your app needs. For typical OpenID Connect sign-in, request the `openid`, `profile`, and `email` scopes.
6. Determine your issuer (authority) URL as `AZURE_ISSUER_URI` env var.
    - For a single tenant: `https://login.microsoftonline.com/<your-tenant-id>/v2.0`
    - For common/multi-tenant flows: `https://login.microsoftonline.com/common/v2.0`
7. For multi-tenant apps, you can use the `AZURE_VALID_TENANT_IDS` env var to specify which comma-separated tenant IDs are allowed.

Example .env (local development):

```env
AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000
AZURE_CLIENT_SECRET=very-secret-value
AZURE_ISSUER_URI=https://login.microsoftonline.com/consumers/v2.0
AZURE_VALID_TENANT_IDS=00000000-0000-0000-0000-000000000000,9188040d-6c67-4c5b-b112-36a304b66dad
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

To fully support embedded/iframe apps, be sure to wrap your login button with `azure_login_button`.

```python
import reflex as rx
from reflex_azure_auth import AzureAuthState, azure_login_button

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
                    azure_login_button(
                        rx.button("Log In with Microsoft"),
                    ),
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

### Customize the UI

The `register_auth_endpoints` function accepts 3 optional UI callables:

#### `loading_page`

This is the page displayed before and after redirecting to the Azure authorization endpoint.

The default implementation uses  `rx.cond(~rx.State.is_hydrated | ~AzureAuthState.userinfo, ...)`
to show a different message based on whether the user info was fetched or not.

#### `popup_login_page`

When the app is within an iframe, the normal redirect flow cannot be used, so
the authentication is handled within a popup window. This callable returns the
page displayed in the popup window before and after redirecting to the Azure
authorization endpoint.

#### `popup_logout_page`

When the app is within an iframe, the normal redirect flow cannot be used, so
the authentication is handled within a popup window. This callable returns the
page displayed in the popup window before redirecting to the Azure
logout endpoint.