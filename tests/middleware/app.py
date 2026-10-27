"""Quick and dirty fastapi test app"""

from typing import Mapping, Any, Optional
import logging

from fastapi import FastAPI, Depends, Request

from multikeyjwt.middleware import JWTPayload, JWTBearer

LOGGER = logging.getLogger(__name__)
APP = FastAPI(docs_url="/middleware/docs", openapi_url="/middleware/openapi.json")


@APP.get("/api/v1/check_auth")
async def check_auth(jwt: JWTPayload = Depends(JWTBearer(auto_error=True))) -> Mapping[str, Any]:
    """Check auth"""
    _ = jwt  # auto-error will raise early if not valid
    return {"ok": True, "sub": jwt.get("sub")}


@APP.get("/api/v1/audience-a")
async def check_audience_a(jwt: JWTPayload = Depends(JWTBearer(audience="service-a"))) -> JWTPayload:
    """Expose the verified identity for audience and precedence assertions."""
    return jwt


@APP.get("/api/v1/audience-b")
async def check_audience_b(jwt: JWTPayload = Depends(JWTBearer(audience="service-b"))) -> JWTPayload:
    """Share trusted keys with the other route without sharing its audience policy."""
    return jwt


async def stale_state(request: Request) -> None:
    """Seed state to prove optional authentication clears any prior identity."""
    request.state.jwt = {"sub": "stale"}


@APP.get("/api/v1/optional", dependencies=[Depends(stale_state)])
async def optional_auth(
    request: Request, jwt: Optional[JWTPayload] = Depends(JWTBearer(audience="service-a", auto_error=False))
) -> Mapping[str, Any]:
    """Return the dependency and state results for optional authentication."""
    return {"jwt": jwt, "state": request.state.jwt}


@APP.get("/api/v1")
async def hello() -> Mapping[str, str]:
    """Say hello"""
    return {"message": "Hello World"}
