"""Quick and dirty fastapi test app"""
from typing import Mapping
import logging

from fastapi import FastAPI, Depends

from multikeyjwt.middleware.jwtbearer import JWTPayload, JWTBearer

LOGGER = logging.getLogger(__name__)
APP = FastAPI(docs_url="/middleware/docs", openapi_url="/middleware/openapi.json")


@APP.get("/api/v1/check_auth")
async def check_auth(jwt: JWTPayload = Depends(JWTBearer(auto_error=True))) -> Mapping[str, bool]:
    """Check auth"""
    _ = jwt  # auto-error will raise early if not valid
    return {"ok": True}


@APP.get("/api/v1")
async def hello() -> Mapping[str, str]:
    """Say hello"""
    return {"message": "Hello World"}
