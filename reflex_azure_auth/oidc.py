"""OIDC helpers: metadata, JWKS, and JWT verification."""

import base64
import contextlib
import datetime
import hashlib
import json
from typing import List

import httpx
from authlib.jose import JsonWebKey, jwt

from .config import azure_issuer_uri, azure_valid_tenant_ids

# Microsoft account issuer id used for consumer accounts
MSA_ISSUER = "9188040d-6c67-4c5b-b112-36a304b66dad"

# Simple cached OIDC metadata + JWKS loader
_OIDC_CACHE: dict[str, dict] = {}


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


def _valid_issuers(issuer: str) -> List[str]:
    if "/common/" in issuer or "/organizations/" in issuer or "/{tenant_id}/" in issuer:
        valid_tenant_ids = azure_valid_tenant_ids()
        issuer_template = issuer.replace("/common/", "/{tenant_id}/").replace(
            "/organizations/", "/{tenant_id}/"
        )
        return [
            issuer_template.format(tenant_id=tenant_id)
            for tenant_id in valid_tenant_ids
            if tenant_id.strip()
        ]
    elif "/consumers/" in issuer:
        return [issuer.replace("/consumers/", f"/{MSA_ISSUER}/")]
    return [issuer]


async def azure_issuer_endpoint(service: str) -> str:
    """Fetch an endpoint URL (authorization/token/userinfo/etc) from OIDC metadata."""
    return (await _fetch_oidc_metadata(azure_issuer_uri()))[service]


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

    claims = jwt.decode(token, key_set)
    # validate claims manually per MS guidance
    aud = claims.get("aud")
    if audience and aud != audience and (isinstance(aud, list) and audience not in aud):
        raise RuntimeError(f"Invalid audience: {claims.get('aud')} != {audience}")
    if claims.get("iss") not in (valid_issuers := _valid_issuers(issuer)):
        raise RuntimeError(
            f"Invalid issuer: {claims.get('iss')} not in {valid_issuers}"
        )
    # expiration check
    exp = claims.get("exp")
    if exp is None or int(exp) < int(datetime.datetime.now(datetime.timezone.utc).timestamp()):
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
    return {}, {}


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
