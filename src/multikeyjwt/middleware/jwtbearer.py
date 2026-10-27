"""FastAPI auth middleware for JWT bearer auth"""

from typing import Optional, Any, Mapping, Sequence
import logging

from jwt import InvalidTokenError
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


from ..config import ENVCONFIG
from ..jwt.verifier import Verifier, validate_audience


LOGGER = logging.getLogger(__name__)
JWTPayload = Mapping[str, Any]


class JWTBearer(HTTPBearer):  # pylint: disable=R0903
    """Check JWT bearer tokens"""

    def __init__(
        self,
        *,
        audience: str | Sequence[str] | None = None,
        bearerFormat: Optional[str] = None,  # pylint: disable=invalid-name
        scheme_name: Optional[str] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ) -> None:
        validate_audience(audience)
        super().__init__(
            bearerFormat=bearerFormat, scheme_name=scheme_name, description=description, auto_error=auto_error
        )
        self.audience = audience

    async def __call__(self, request: Request) -> Optional[JWTPayload]:  # type: ignore[override]
        request.state.jwt = None
        jwt_b64: Optional[str] = None
        payload: Optional[Mapping[str, Any]] = None
        if "authorization" in request.headers:
            try:
                credentials: Optional[HTTPAuthorizationCredentials] = await super().__call__(request)
            except HTTPException as parent_error:
                credentials = None
                if parent_error.status_code not in (401, 403):
                    raise parent_error
            if credentials:
                jwt_b64 = credentials.credentials
        elif cookie_name := ENVCONFIG("JWT_COOKIE_NAME"):
            jwt_b64 = request.cookies.get(cookie_name)
        if jwt_b64:
            try:
                payload = Verifier.singleton().decode(jwt_b64, audience=self.audience)
            except InvalidTokenError as exc:
                LOGGER.info("JWT verification failed: %s", type(exc).__name__)
        if not payload and self.auto_error:
            raise HTTPException(status_code=403, detail="Invalid or expired token.")
        # Inject into request state to avoid Repeating Myself
        request.state.jwt = payload
        return payload
