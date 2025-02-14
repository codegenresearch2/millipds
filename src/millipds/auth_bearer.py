import logging
import time

import jwt
from aiohttp import web

from .app_util import *

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

MAX_TOKEN_EXPIRATION = 60 * 60 * 24  # 24 hours

def authenticated(handler):
    async def authentication_handler(request: web.Request, *args, **kwargs):
        # extract the auth token
        auth = request.headers.get("Authorization")
        if auth is None:
            raise web.HTTPUnauthorized(text="Authentication required.")
        if not auth.startswith("Bearer "):
            raise web.HTTPUnauthorized(text="Invalid authentication type.")
        token = auth.removeprefix("Bearer ")

        # validate it
        db = get_db(request)
        try:
            payload: dict = jwt.decode(
                jwt=token,
                key=db.config["jwt_access_secret"],
                algorithms=["HS256"],
                audience=db.config["pds_did"],
                options={
                    "require": ["exp", "iat", "scope"],
                    "verify_exp": True,
                    "verify_iat": True,
                    "strict_aud": True,
                },
            )
        except jwt.exceptions.PyJWTError:
            raise web.HTTPUnauthorized(text="Invalid token.")

        # Check if the token has expired
        if payload.get("exp") < int(time.time()):
            raise web.HTTPUnauthorized(text="Token has expired.")

        # Enforce maximum token expiration time
        if payload.get("exp") - payload.get("iat") > MAX_TOKEN_EXPIRATION:
            raise web.HTTPUnauthorized(text="Token expiration time exceeds limit.")

        # if we reached this far, the payload must've been signed by us\n        if payload.get("scope") != "com.atproto.access":\n            raise web.HTTPUnauthorized(text="Invalid token scope.")\n\n        subject: str = payload.get("sub", "")\n        if not subject.startswith("did:"):\n            raise web.HTTPUnauthorized(text="Invalid token: invalid subject.")\n        request["authed_did"] = subject\n        return await handler(request, *args, **kwargs)\n\n    return authentication_handler\n\n# Add tests for new functionality\ndef test_authenticated_decorator():\n    # Test cases for valid and invalid tokens\n    # ...\n\n# Run tests\ntest_authenticated_decorator()