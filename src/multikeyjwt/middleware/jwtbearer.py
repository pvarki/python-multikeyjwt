"""FastAPI auth middleware for JWT bearer auth"""
from typing import Optional, Any, Mapping
import logging

from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


from ..config import ENVCONFIG
from ..jwt.verifier import Verifier


LOGGER = logging.getLogger(__name__)
JWTPayload = Mapping[str, Any]


class JWTBearer(HTTPBearer):  # pylint: disable=R0903
    """Check JWT bearer tokens"""

    async def __call__(self, request: Request) -> Optional[JWTPayload]:  # type: ignore[override]
        jwt_b64: Optional[str] = None
        payload: Optional[Mapping[str, Any]] = None
        if cookie_name := ENVCONFIG("JWT_COOKIE_NAME"):
            if cookie := request.cookies.get(cookie_name):
                jwt_b64 = cookie
        if not jwt_b64:
            credentials: Optional[HTTPAuthorizationCredentials] = await super().__call__(request)
            if not credentials:
                # auto-error will have raised already if no auth header
                return None
            if credentials.scheme != "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            jwt_b64 = credentials.credentials
        if not jwt_b64 and self.auto_error:
            raise HTTPException(status_code=403, detail="Not authenticated")
        try:
            payload = Verifier.singleton().decode(jwt_b64)
        except Exception as exc:  # pylint: disable=W0703
            LOGGER.exception("Got problem {} decoding {}".format(exc, jwt_b64))
        if not payload and self.auto_error:
            raise HTTPException(status_code=403, detail="Invalid or expired token.")
        # Inject into request state to avoid Repeating Myself
        request.state.jwt = payload
        return payload
