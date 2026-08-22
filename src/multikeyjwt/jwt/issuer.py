"""Creator/signer aka issuer for JWTs"""

from typing import Optional, Any, Dict, cast, ClassVar
from dataclasses import dataclass, field
from pathlib import Path
import functools

import pendulum
from libadvian.binpackers import ensure_utf8
import jwt as pyJWT  # too easy to accidentally override the module
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.backends import default_backend


from .common import JWTIssuerConfig
from ..config import ENVCONFIG, Secret


@dataclass
class Issuer:
    """Helper/handler JWT issuing"""

    config: JWTIssuerConfig = field(default_factory=JWTIssuerConfig)
    privkeypath: Path = field(default_factory=functools.partial(ENVCONFIG, "JWT_PRIVKEY_PATH", cast=Path))
    keypasswd: Optional[Secret] = field(
        default_factory=functools.partial(ENVCONFIG, "JWT_PRIVKEY_PASS", cast=Secret, default=None)
    )

    # Private props
    _privkey: RSAPrivateKey = field(init=False, repr=False)
    _singleton: ClassVar[Optional["Issuer"]] = None

    def __post_init__(self) -> None:
        """Read the keys"""
        if self.privkeypath and self.privkeypath.exists():
            with self.privkeypath.open("rb") as fpntr:
                passphrase: Optional[bytes] = None
                if self.keypasswd:
                    passphrase = ensure_utf8(str(self.keypasswd))
                key = serialization.load_pem_private_key(fpntr.read(), password=passphrase, backend=default_backend())
                if not isinstance(key, RSAPrivateKey):
                    raise ValueError("{} is not RSAPrivateKey".format(self.privkeypath))
                self._privkey = key
        else:
            raise ValueError("No private key, cannot issue")

    def issue(self, claims: Dict[str, Any]) -> str:
        """Issue JWT with claims, sets some basic defaults"""
        now = pendulum.now("UTC")
        claims["nbf"] = now
        claims["iat"] = now
        claims["exp"] = now + pendulum.duration(seconds=self.config.lifetime)
        if self.config.issuer:
            claims["iss"] = self.config.issuer
        if self.config.audience:
            claims["aud"] = self.config.audience
        return pyJWT.encode(payload=claims, key=cast(Any, self._privkey), algorithm=self.config.algorithm)

    @classmethod
    def singleton(cls, **kwargs: Any) -> "Issuer":
        """Get a singleton"""
        if Issuer._singleton is None:
            Issuer._singleton = Issuer(**kwargs)
        assert Issuer._singleton is not None
        return Issuer._singleton
