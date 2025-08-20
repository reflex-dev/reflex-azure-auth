"""Configuration helpers for reflex_azure_auth.

This module provides small helpers to read Azure-related configuration from
environment variables used across the package.
"""

import os


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


def azure_issuer_uri() -> str:
    """Return the AZURE_ISSUER_URI environment variable or raise.

    Raises:
        RuntimeError: If the AZURE_ISSUER_URI environment variable is not set.
    """
    azure_issuer_uri = os.environ.get("AZURE_ISSUER_URI")
    if not azure_issuer_uri:
        raise RuntimeError("AZURE_ISSUER_URI environment variable is not set.")
    return azure_issuer_uri


def azure_valid_tenant_ids() -> list[str]:
    """Read the list of valid tenant_id from environment.

    Note: this list is only used when the issuer endpoint contains "common" or
    "organizations".

    Returns:
        A list of tenant id strings.
    """
    return os.environ.get("AZURE_VALID_TENANT_IDS", "").split(",")
