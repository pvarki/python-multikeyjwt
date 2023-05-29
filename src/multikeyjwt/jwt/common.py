"""Common config etc classes"""
from typing import Optional
import functools
from dataclasses import dataclass, field

from ..config import ENVCONFIG

JWT_DEFAULT_LIFETIME = 60 * 60 * 2  # 2 hours in seconds


@dataclass
class JWTVerifierConfig:
    """Config options for jwt decode"""

    algorithm: str = field(default_factory=functools.partial(ENVCONFIG, "JWT_ALGORITHM", default="RS256"))


@dataclass
class JWTIssuerConfig(JWTVerifierConfig):
    """Config options for jwt encode"""

    lifetime: int = field(
        default_factory=functools.partial(ENVCONFIG, "JWT_LIFETIME", cast=int, default=JWT_DEFAULT_LIFETIME)
    )
    issuer: Optional[str] = field(default_factory=functools.partial(ENVCONFIG, "JWT_ISSUER", default=None))
    audience: Optional[str] = field(default_factory=functools.partial(ENVCONFIG, "JWT_AUDIENCE", default=None))
