"""Test key issuing and verification"""

import logging
from dataclasses import replace
from typing import Any

import jwt as pyJWT  # too easy to accidentally override the module
import pytest

from multikeyjwt import Issuer, Verifier
from .conftest import DATA_PATH

LOGGER = logging.getLogger(__name__)


def test_rr_issued(issuer_rr: Issuer, verifier: Verifier) -> None:
    """Test that we can issue and verify rr-signed JWTs"""
    token = issuer_rr.issue({"userid": "I am groot"})
    decoded = verifier.decode(token)
    assert decoded["userid"] == "I am groot"


def test_cl_issued(issuer_cl: Issuer, verifier: Verifier) -> None:
    """Test that we can issue and verify cl-signed JWTs"""
    token = issuer_cl.issue({"racket": "Raccoon"})
    decoded = verifier.decode(token)
    assert decoded["racket"] == "Raccoon"


def test_es_issued(issuer_es: Issuer, verifier: Verifier) -> None:
    """Test that we can issue and verify ES256 JWTs"""
    token = issuer_es.issue({"baratna": "best"})
    decoded = verifier.decode(token)
    assert decoded["baratna"] == "best"


@pytest.mark.parametrize("issuer_name", ["issuer_rr", "issuer_es"])
@pytest.mark.parametrize(
    "kwargs,expected_lifetime",
    [
        ({}, 3600),
        ({"lifetime": None}, 3600),
        ({"lifetime": 60}, 60),
        ({"lifetime": 7200}, 7200),
        ({"lifetime": 0}, 0),
        ({"lifetime": -60}, -60),
    ],
)
def test_issue_lifetime(
    request: pytest.FixtureRequest,
    verifier: Verifier,
    issuer_name: str,
    kwargs: dict[str, Any],
    expected_lifetime: int,
) -> None:
    """Per-token lifetimes override the configured default without changing it."""
    original: Issuer = request.getfixturevalue(issuer_name)
    issuer = replace(original, config=replace(original.config, lifetime=3600))
    token = issuer.issue({"sub": "lifetime-test"}, **kwargs)
    decoded = pyJWT.decode(token, options={"verify_signature": False})
    assert decoded["exp"] - decoded["iat"] == expected_lifetime
    assert decoded["nbf"] == decoded["iat"]
    if expected_lifetime <= 0:
        with pytest.raises(pyJWT.ExpiredSignatureError):
            verifier.decode(token)
    else:
        assert verifier.decode(token)["sub"] == "lifetime-test"
    assert issuer.config.lifetime == 3600
    default = verifier.decode(issuer.issue({"sub": "default-lifetime"}))
    assert default["exp"] - default["iat"] == 3600


def test_pc_issued(issuer_pc: Issuer, verifier: Verifier) -> None:
    """Test that we can issue but not verify cl-signed JWTs"""
    token = issuer_pc.issue({"boss": "mang"})
    with pytest.raises(pyJWT.exceptions.InvalidSignatureError):
        verifier.decode(token)


def test_load_key(issuer_pc: Issuer) -> None:
    """test verifier key load load after init"""
    verifier = Verifier(pubkeypath=DATA_PATH)
    token = issuer_pc.issue({"foo": "bar"})
    with pytest.raises(pyJWT.exceptions.InvalidSignatureError):
        verifier.decode(token)
    verifier.load_key(DATA_PATH / "pc_jwtRS256.p_b")
    decoded = verifier.decode(token)
    assert decoded["foo"] == "bar"


def test_load_key_file_uri(issuer_pc: Issuer) -> None:
    """test verifier key load load after init"""
    verifier = Verifier(pubkeypath=DATA_PATH)
    token = issuer_pc.issue({"foo": "bar"})
    with pytest.raises(pyJWT.exceptions.InvalidSignatureError):
        verifier.decode(token)
    keypath = DATA_PATH / "pc_jwtRS256.p_b"
    verifier.load_key_from_url(f"file://{keypath}")
    decoded = verifier.decode(token)
    assert decoded["foo"] == "bar"


def test_load_edkey() -> None:
    """test verifier does not load ED25519 key"""
    verifier = Verifier(pubkeypath=DATA_PATH / "ed25519.pub")
    assert not verifier.pubkeys


@pytest.mark.parametrize("issuer_name", ["issuer_rr", "issuer_es"])
@pytest.mark.parametrize(
    "claims",
    [
        {},
        {"iss": "custom-issuer"},
        {"aud": "custom-audience"},
        {"iss": "custom-issuer", "aud": "custom-audience"},
        {"aud": ["service-a", "service-b"]},
        {"aud": None},
        {"iss": "", "aud": ""},
        {"aud": []},
    ],
)
def test_issue_claim_overrides(request: pytest.FixtureRequest, issuer_name: str, claims: dict[str, Any]) -> None:
    """Explicit claims take precedence, including falsey values, without changing defaults."""
    original: Issuer = request.getfixturevalue(issuer_name)
    config = replace(original.config, issuer="configured-issuer", audience="configured-audience")
    issuer = replace(original, config=config)
    defaults = {"iss": config.issuer, "aud": config.audience}
    expected = {**defaults, **claims}
    token = issuer.issue(claims.copy())
    decoded = pyJWT.decode(token, options={"verify_signature": False})
    assert {"iss": decoded["iss"], "aud": decoded["aud"]} == expected
    assert {"iss": config.issuer, "aud": config.audience} == defaults
    subsequent = pyJWT.decode(issuer.issue({}), options={"verify_signature": False})
    assert {"iss": subsequent["iss"], "aud": subsequent["aud"]} == defaults


@pytest.mark.parametrize("issuer_name", ["issuer_rr", "issuer_es"])
@pytest.mark.parametrize(
    "claim,expected",
    [("service-a", "service-a"), (["service-b", "service-a"], "service-a"), ("service-b", ("service-a", "service-b"))],
)
def test_audience(
    request: pytest.FixtureRequest, verifier: Verifier, issuer_name: str, claim: Any, expected: Any
) -> None:
    """Verify audiences with both key types without changing subsequent calls."""
    issuer: Issuer = request.getfixturevalue(issuer_name)
    token = issuer.issue({"aud": claim})
    assert verifier.decode(token, audience=expected)["aud"] == claim
    with pytest.raises(pyJWT.InvalidAudienceError):
        verifier.decode(token)
    assert verifier.decode(issuer.issue({"sub": "legacy"}))["sub"] == "legacy"


@pytest.mark.parametrize("issuer_name", ["issuer_rr", "issuer_es"])
@pytest.mark.parametrize("claims", [{}, {"aud": "service-b"}, {"aud": ""}, {"aud": []}, {"aud": 123}, {"aud": [123]}])
def test_wrong_audience(
    request: pytest.FixtureRequest, verifier: Verifier, issuer_name: str, claims: dict[str, Any]
) -> None:
    """Missing, mismatched and malformed audiences must fail after signature verification."""
    issuer: Issuer = request.getfixturevalue(issuer_name)
    with pytest.raises((pyJWT.InvalidAudienceError, pyJWT.MissingRequiredClaimError)):
        verifier.decode(issuer.issue(claims.copy()), audience="service-a")


@pytest.mark.parametrize("audience", ["", [], (), [""], ["service-a", 1], 123, b"service-a"])
def test_invalid_audience_config(verifier: Verifier, audience: Any) -> None:
    """Invalid expectations are configuration errors, not permission to skip verification."""
    with pytest.raises(ValueError):
        verifier.decode("not-a-token", audience=audience)


def test_audience_keeps_security_checks(issuer_rr: Issuer, issuer_pc: Issuer, verifier: Verifier) -> None:
    """An audience match cannot bypass signature, algorithm or expiration checks."""
    with pytest.raises(pyJWT.InvalidSignatureError):
        verifier.decode(issuer_pc.issue({"aud": "service-a"}), audience="service-a")
    with pytest.raises(pyJWT.InvalidAlgorithmError):
        verifier.decode(
            pyJWT.encode({"aud": "service-a"}, "test-secret-for-rejected-hs256-key", algorithm="HS256"),
            audience="service-a",
        )
    expired = replace(issuer_rr, config=replace(issuer_rr.config, lifetime=-60))
    with pytest.raises(pyJWT.ExpiredSignatureError):
        verifier.decode(expired.issue({"aud": "service-a"}), audience="service-a")


def test_future_nbf(issuer_rr: Issuer, verifier: Verifier, monkeypatch: pytest.MonkeyPatch) -> None:
    """A matching audience cannot make a future token valid."""
    import pendulum  # pylint: disable=import-outside-toplevel

    future = pendulum.now("UTC").add(minutes=1)
    monkeypatch.setattr("multikeyjwt.jwt.issuer.pendulum.now", lambda _timezone: future)
    with pytest.raises(pyJWT.ImmatureSignatureError):
        verifier.decode(issuer_rr.issue({"aud": "service-a"}), audience="service-a")


@pytest.mark.parametrize("issuer_name", ["issuer_rr", "issuer_es"])
def test_audience_after_wrong_key(request: pytest.FixtureRequest, issuer_name: str) -> None:
    """An earlier signature/algorithm mismatch must not prevent trying the right key."""
    issuer: Issuer = request.getfixturevalue(issuer_name)
    verifier = Verifier(pubkeypath=DATA_PATH / "pc_jwtRS256.p_b")
    verifier.load_key(issuer.privkeypath.with_suffix(".pub"))
    assert verifier.decode(issuer.issue({"aud": "service-a"}), audience="service-a")["aud"] == "service-a"
