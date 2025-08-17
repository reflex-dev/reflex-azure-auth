import datetime

import pytest

import reflex_azure_auth as raa


class DummyResp:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


@pytest.mark.asyncio
async def test_fetch_oidc_and_jwks(monkeypatch):
    md = {"jwks_uri": "https://example.com/jwks"}
    jwks = {"keys": []}

    async def fake_get(url, timeout=10):
        if url.endswith(".well-known/openid-configuration"):
            return DummyResp(md)
        if url == "https://example.com/jwks":
            return DummyResp(jwks)
        raise RuntimeError("unexpected url")

    class FakeClient:
        async def __aenter__(self):
            import pytest

            class DummyResp:
                def __init__(self, data):
                    self._data = data

                def json(self):
                    return self._data

            @pytest.mark.asyncio
            async def test_fetch_oidc_and_jwks(monkeypatch):
                issuer = "https://login.microsoftonline.com/common"
                md = {"jwks_uri": "https://example.com/jwks"}
                jwks = {"keys": []}

                async def fake_get(url, timeout=10):
                    if url.endswith(".well-known/openid-configuration"):
                        return DummyResp(md)
                    if url == "https://example.com/jwks":
                        return DummyResp(jwks)
                    raise RuntimeError("unexpected url")

                class FakeClient:
                    async def __aenter__(self):
                        return self

                    async def __aexit__(self, exc_type, exc, tb):
                        return False

                    async def get(self, url, timeout=10):
                        return await fake_get(url, timeout=timeout)

                monkeypatch.setattr(raa, "_OIDC_CACHE", {})
                monkeypatch.setattr(raa.httpx, "AsyncClient", lambda: FakeClient())

                got_md = await raa._fetch_oidc_metadata(issuer)
                assert got_md == md
                got_jwks = await raa._fetch_jwks(md["jwks_uri"])
                assert got_jwks == jwks

            @pytest.mark.asyncio
            async def test_verify_jwt_claim_checks(monkeypatch):
                # Monkeypatch network and jwt.decode to return controlled claims
                issuer = "https://login.microsoftonline.com/common"
                md = {"jwks_uri": "https://example.com/jwks"}
                jwks = {"keys": []}

                async def fake_fetch_oidc_metadata(i):
                    return md

                async def fake_fetch_jwks(j):
                    return jwks

                def fake_decode(token, key_set=None):
                    # return a token that is valid and not expired
                    return {
                        "iss": issuer,
                        "aud": "api://default",
                        "exp": int(
                            (
                                datetime.datetime.utcnow()
                                + datetime.timedelta(minutes=5)
                            ).timestamp()
                        ),
                    }

                monkeypatch.setattr(
                    raa, "_fetch_oidc_metadata", fake_fetch_oidc_metadata
                )
                monkeypatch.setattr(raa, "_fetch_jwks", fake_fetch_jwks)
                monkeypatch.setattr(
                    raa.jwt, "decode", lambda token, ks: fake_decode(token, ks)
                )

                claims = await raa.verify_jwt(
                    "dummy", audience="api://default", issuer=issuer
                )
                assert claims["aud"] == "api://default"
