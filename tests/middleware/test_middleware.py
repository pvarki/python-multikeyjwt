"""Test the middleware"""
from typing import Any, Generator
import logging

import pytest
from fastapi.testclient import TestClient

from multikeyjwt import Issuer
from .app import APP
from ..conftest import DATA_PATH

LOGGER = logging.getLogger(__name__)

# pylint: disable=W0621


@pytest.fixture
def verifier_env(monkeypatch: Any) -> Generator[None, None, None]:
    """Configure the verifier via env"""
    monkeypatch.setenv("JWT_PUBKEY_PATH", str(DATA_PATH))
    monkeypatch.setenv("JWT_COOKIE_NAME", "auth_cookie")
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
    resp = client.get("/api/v1/check_auth")
    token = issuer_pc.issue({"foo": "bar"})
    if authtype == "header":
        client.headers.update({"Authorization": f"Bearer {token}"})
    if authtype == "cookie":
        client.cookies.update({"auth_cookie": token})
    assert resp.status_code == 403
