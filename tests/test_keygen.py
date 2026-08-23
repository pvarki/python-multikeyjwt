"""Test the key generation helper"""

import logging
from pathlib import Path
import uuid

import pytest

from multikeyjwt import Issuer, Verifier
from multikeyjwt.config import Secret
from multikeyjwt.keygen import generate_keypair

LOGGER = logging.getLogger(__name__)

KTYPES = ("RSA", "SECP256R1")


@pytest.mark.parametrize("ktype", KTYPES)
def test_keygen(nice_tmpdir: str, ktype: str) -> None:
    """Test we can generate workable keys"""
    keypath = Path(nice_tmpdir) / Path("gentest.key")
    password = str(uuid.uuid4())
    # use smaller keys in tests for speed
    genkey, genpub = generate_keypair(keypath, password, ktype=ktype, ksize=1024)

    issuer = Issuer(privkeypath=genkey, keypasswd=Secret(password))
    verifier = Verifier(pubkeypath=genpub)

    token = issuer.issue({"sub": "genkeytest"})
    parsed = verifier.decode(token)
    assert parsed["sub"] == "genkeytest"


@pytest.mark.parametrize("ktype", KTYPES)
def test_keygen_nopassword(nice_tmpdir: str, ktype: str) -> None:
    """Test we can generate workable keys"""
    keypath = Path(nice_tmpdir) / Path("nopwtest.key")
    # use smaller keys in tests for speed
    genkey, genpub = generate_keypair(keypath, None, ktype=ktype, ksize=1024)

    issuer = Issuer(privkeypath=genkey)
    verifier = Verifier(pubkeypath=genpub)

    token = issuer.issue({"sub": "genkeytest"})
    parsed = verifier.decode(token)
    assert parsed["sub"] == "genkeytest"
