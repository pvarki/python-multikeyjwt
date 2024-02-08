"""Test key issuing and verification"""
import logging

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
