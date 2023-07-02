"""Test the key generation helper"""
import logging
from pathlib import Path
import uuid


from multikeyjwt import Issuer, Verifier
from multikeyjwt.config import Secret
from multikeyjwt.keygen import generate_keypair

LOGGER = logging.getLogger(__name__)


def test_keygen(nice_tmpdir: str) -> None:
    """Test we can generate workable keys"""
    keypath = Path(nice_tmpdir) / Path("gentest.key")
    password = str(uuid.uuid4())
    genkey, genpub = generate_keypair(keypath, password)

    issuer = Issuer(privkeypath=genkey, keypasswd=Secret(password))
    verifier = Verifier(pubkeypath=genpub)

    token = issuer.issue({"sub": "genkeytest"})
    parsed = verifier.decode(token)
    assert parsed["sub"] == "genkeytest"


def test_keygen_nopassword(nice_tmpdir: str) -> None:
    """Test we can generate workable keys"""
    keypath = Path(nice_tmpdir) / Path("nopwtest.key")
    genkey, genpub = generate_keypair(keypath, None)

    issuer = Issuer(privkeypath=genkey, keypasswd=None)
    verifier = Verifier(pubkeypath=genpub)

    token = issuer.issue({"sub": "genkeytest"})
    parsed = verifier.decode(token)
    assert parsed["sub"] == "genkeytest"
