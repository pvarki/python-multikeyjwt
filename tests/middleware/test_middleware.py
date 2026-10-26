"""Test the middleware"""

from typing import Any, Generator
import logging
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from fastapi.openapi.models import HTTPBearer as HTTPBearerModel

from multikeyjwt import Issuer, Verifier
from multikeyjwt.middleware import JWTBearer
from .app import APP
from ..conftest import DATA_PATH

LOGGER = logging.getLogger(__name__)

# pylint: disable=W0621


@pytest.fixture
def verifier_env(monkeypatch: Any) -> Generator[None, None, None]:
    """Configure the verifier via env"""
    monkeypatch.setenv("JWT_PUBKEY_PATH", str(DATA_PATH))
    monkeypatch.setenv("JWT_COOKIE_NAME", "auth_cookie")
    monkeypatch.setattr(Verifier, "_singleton", None)
    yield None


def test_hello(verifier_env: None) -> None:
    """Check the hello endpoint"""
    _ = verifier_env
    client = TestClient(APP)
    resp = client.get("/api/v1")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["message"] == "Hello World"


def test_unauth(verifier_env: None) -> None:
    """Check that unauth call to auth endpoint fails"""
    _ = verifier_env
    client = TestClient(APP)
    resp = client.get("/api/v1/check_auth")
    assert resp.status_code == 403


@pytest.mark.parametrize("authtype", ["header", "cookie"])
def test_auth_rr(issuer_rr: Issuer, verifier_env: None, authtype: str) -> None:
    """Check that valid jwt auth works"""
    _ = verifier_env
    client = TestClient(APP)
    token = issuer_rr.issue({"foo": "bar"})
    if authtype == "header":
        client.headers.update({"Authorization": f"Bearer {token}"})
    if authtype == "cookie":
        client.cookies.update({"auth_cookie": token})
    resp = client.get("/api/v1/check_auth")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["ok"]


@pytest.mark.parametrize("authtype", ["header", "cookie"])
def test_auth_cl(issuer_cl: Issuer, verifier_env: None, authtype: str) -> None:
    """Check that valid jwt auth works"""
    _ = verifier_env
    client = TestClient(APP)
    token = issuer_cl.issue({"foo": "bar"})
    if authtype == "header":
        client.headers.update({"Authorization": f"Bearer {token}"})
    if authtype == "cookie":
        client.cookies.update({"auth_cookie": token})
    resp = client.get("/api/v1/check_auth")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["ok"]


@pytest.mark.parametrize("authtype", ["header", "cookie"])
def test_invalid_auth(issuer_pc: Issuer, verifier_env: None, authtype: str) -> None:
    """Check that unauth call to auth endpoint fails"""
    _ = verifier_env
    client = TestClient(APP)
    token = issuer_pc.issue({"foo": "bar"})
    if authtype == "header":
        client.headers.update({"Authorization": f"Bearer {token}"})
    if authtype == "cookie":
        client.cookies.update({"auth_cookie": token})
    resp = client.get("/api/v1/check_auth")
    assert resp.status_code == 403


@pytest.mark.parametrize("cookie_kind", ["valid", "invalid", "expired", "wrong-audience"])
@pytest.mark.parametrize("optional", [False, True])
def test_header_wins(issuer_rr: Issuer, verifier_env: None, cookie_kind: str, optional: bool) -> None:
    """The returned subject proves which credential was selected."""
    _ = verifier_env
    client = TestClient(APP)
    cookie = issuer_rr.issue({"sub": "cookie", "aud": "service-a"})
    if cookie_kind == "invalid":
        cookie = "invalid-cookie"
    elif cookie_kind == "expired":
        expired = replace(issuer_rr, config=replace(issuer_rr.config, lifetime=-60))
        cookie = expired.issue({"aud": "service-a"})
    elif cookie_kind == "wrong-audience":
        cookie = issuer_rr.issue({"aud": "service-b"})
    client.cookies.set("auth_cookie", cookie)
    token = issuer_rr.issue({"sub": "header", "aud": "service-a"})
    path = "/api/v1/optional" if optional else "/api/v1/audience-a"
    response = client.get(path, headers={"Authorization": f"bearer {token}"})
    assert response.status_code == 200
    payload = response.json()["jwt"] if optional else response.json()
    assert payload["sub"] == "header"
    if optional:
        assert response.json()["state"] == payload


@pytest.mark.parametrize(
    "header_kind", ["absent", "empty", "missing-token", "basic", "invalid", "expired", "wrong-audience", "untrusted"]
)
@pytest.mark.parametrize("optional", [False, True])
@pytest.mark.usefixtures("verifier_env")
def test_header_failure_never_uses_cookie(
    issuer_rr: Issuer,
    issuer_pc: Issuer,
    header_kind: str,
    optional: bool,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A usable cookie cannot rescue any explicit bad header, even for optional auth."""
    client = TestClient(APP)
    token = issuer_rr.issue({"sub": "cookie", "aud": "service-a"})
    client.cookies.set("auth_cookie", token)
    expired = replace(issuer_rr, config=replace(issuer_rr.config, lifetime=-60))
    headers = {
        "empty": "",
        "missing-token": "Bearer",
        "basic": "Basic credentials",
        "invalid": "Bearer invalid-token",
        "wrong-audience": f"Bearer {issuer_rr.issue({'aud': 'service-b'})}",
        "untrusted": f"Bearer {issuer_pc.issue({'aud': 'service-a'})}",
        "expired": f"Bearer {expired.issue({'aud': 'service-a'})}",
    }
    path = "/api/v1/optional" if optional else "/api/v1/audience-a"
    response = client.get(path, headers={} if header_kind == "absent" else {"Authorization": headers[header_kind]})
    if header_kind == "absent":
        assert response.status_code == 200
        payload = response.json()["jwt"] if optional else response.json()
        assert payload["sub"] == "cookie"
        if optional:
            assert response.json()["state"] == payload
    elif optional:
        assert response.status_code == 200
        assert response.json() == {"jwt": None, "state": None}
    else:
        assert response.status_code == 403
    assert token not in caplog.text
    assert all(value.split(" ", 1)[-1] not in caplog.text for value in headers.values() if len(value) > 30)


@pytest.mark.parametrize("cookie_kind", ["absent", "invalid", "expired", "wrong-audience"])
@pytest.mark.parametrize("optional", [False, True])
def test_cookie_failures(issuer_rr: Issuer, verifier_env: None, cookie_kind: str, optional: bool) -> None:
    """Cookie-only and unauthenticated failures respect auto_error and clear state."""
    _ = verifier_env
    client = TestClient(APP)
    cookies = {
        "invalid": "invalid-cookie",
        "expired": replace(issuer_rr, config=replace(issuer_rr.config, lifetime=-60)).issue({"aud": "service-a"}),
        "wrong-audience": issuer_rr.issue({"aud": "service-b"}),
    }
    if cookie_kind != "absent":
        client.cookies.set("auth_cookie", cookies[cookie_kind])
    response = client.get("/api/v1/optional" if optional else "/api/v1/audience-a")
    assert response.status_code == (200 if optional else 403)
    if optional:
        assert response.json() == {"jwt": None, "state": None}


def test_audience_isolation(issuer_rr: Issuer, verifier_env: None) -> None:
    """Interleaved dependencies cannot change the singleton's verification policy."""
    _ = verifier_env
    client = TestClient(APP)
    for audience in ("service-a", "service-b", "service-a"):
        client.headers["Authorization"] = f"Bearer {issuer_rr.issue({'aud': audience})}"
        for route in ("a", "b"):
            response = client.get(f"/api/v1/audience-{route}")
            assert response.status_code == (200 if audience == f"service-{route}" else 403)
    client.headers["Authorization"] = f"Bearer {issuer_rr.issue({'sub': 'legacy'})}"
    assert client.get("/api/v1/check_auth").json()["sub"] == "legacy"


@pytest.mark.parametrize("audience", ["", [], ["service-a", 1]])
def test_invalid_config(audience: Any) -> None:
    """Fail configuration at dependency construction, without loading the verifier."""
    with pytest.raises(ValueError):
        JWTBearer(audience=audience)


def test_constructor_compatibility() -> None:
    """Keep HTTPBearer options and defer key loading until a request arrives."""
    dependency = JWTBearer(
        audience=("service-a", "service-b"),
        bearerFormat="JWT",
        scheme_name="services",
        description="Service authentication",
        auto_error=False,
    )
    assert dependency.scheme_name == "services"
    assert isinstance(dependency.model, HTTPBearerModel)
    assert dependency.model.bearerFormat == "JWT"
    assert dependency.model.description == "Service authentication"
    assert not dependency.auto_error


@pytest.mark.parametrize("cookie_name", ["", None])
def test_cookie_disabled(
    issuer_rr: Issuer, verifier_env: None, monkeypatch: pytest.MonkeyPatch, cookie_name: Any
) -> None:
    """An unset cookie name does not accidentally use a browser credential."""
    _ = verifier_env
    if cookie_name is None:
        monkeypatch.delenv("JWT_COOKIE_NAME")
    else:
        monkeypatch.setenv("JWT_COOKIE_NAME", cookie_name)
    client = TestClient(APP)
    client.cookies.set("auth_cookie", issuer_rr.issue({"sub": "cookie"}))
    assert client.get("/api/v1/check_auth").status_code == 403
