""" Verify JWTs with multiple public keys, FastAPI middleware for auth """
__version__ = "1.3.0"  # NOTE Use `bump2version --config-file patch` to bump versions correctly

from .jwt.issuer import Issuer
from .jwt.verifier import Verifier


__all__ = ["Issuer", "Verifier"]
