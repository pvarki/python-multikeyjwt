"""Verifier for JWTs, using multiple public keys"""
from typing import Optional, Any, Dict, MutableSequence
from dataclasses import dataclass, field
from pathlib import Path
import functools
import logging

import jwt as pyJWT  # too easy to accidentally override the module
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.backends import default_backend


from .common import JWTVerifierConfig
from ..config import ENVCONFIG

LOGGER = logging.getLogger(__name__)


@dataclass
class Verifier:
    """Helper/handler JWT verification"""

    config: JWTVerifierConfig = field(default_factory=JWTVerifierConfig)

    pubkeypath: Path = field(default_factory=functools.partial(ENVCONFIG, "JWT_PUBKEY_PATH", cast=Path))

    # Non-init public props
    pubkeys: MutableSequence[PublicKeyTypes] = field(init=False)

    def __post_init__(self) -> None:
        """Read the keys"""
        if not self.pubkeypath.exists():
            raise ValueError(f"{self.pubkeypath} does not exist")
        if self.pubkeypath.is_dir():
            self.pubkeys = []
            for fpth in self.pubkeypath.iterdir():
                if not fpth.is_file():
                    continue
                if not fpth.name.endswith(".pub"):
                    continue
                LOGGER.debug("Loading key {}".format(fpth))
                with fpth.open("rb") as fpntr:
                    self.pubkeys.append(serialization.load_pem_public_key(fpntr.read(), backend=default_backend()))
        else:
            LOGGER.info("Loading key {}".format(self.pubkeypath))
            with self.pubkeypath.open("rb") as fpntr:
                self.pubkeys = [serialization.load_pem_public_key(fpntr.read(), backend=default_backend())]

    def decode(self, token: str) -> Dict[str, Any]:
        """Decode the token"""
        last_exception = Exception("This should not be raised")
        for pubkey in self.pubkeys:
            try:
                return pyJWT.decode(jwt=token, key=pubkey, algorithms=[self.config.algorithm])  # type: ignore
            except pyJWT.InvalidSignatureError as exc:
                last_exception = exc
                continue
        raise last_exception

    @classmethod
    def singleton(cls, **kwargs: Any) -> "Verifier":
        """Get a singleton"""
        global VERIFIER_SINGLETON  # pylint: disable=W0603
        if VERIFIER_SINGLETON is None:
            VERIFIER_SINGLETON = Verifier(**kwargs)
        assert VERIFIER_SINGLETON is not None
        return VERIFIER_SINGLETON


VERIFIER_SINGLETON: Optional[Verifier] = None
