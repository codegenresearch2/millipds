import logging

import jwt
from aiohttp import web

from .app_util import *

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()


def authenticated(handler):
    async def authentication_handler(request: web.Request, *args, **kwargs):
        # Extract the auth token
        auth = request.headers.get("Authorization")
        if auth is None:
            raise web.HTTPUnauthorized(
                text="authentication required (this may be a bug, I'm erring on the side of caution for now)"
            )
        if not auth.startswith("Bearer "):
            raise web.HTTPUnauthorized(text="invalid auth type")
        token = auth.removeprefix("Bearer ")

        # Validate it with enhanced expiration handling
        db = get_db(request)
        try:
            payload: dict = jwt.decode(
                jwt=token,
                key=db.config["jwt_access_secret"],
                algorithms=["HS256"],
                audience=db.config["pds_did"],
                options={
                    "require": ["exp", "iat", "scope"],  # consider iat?
                    "verify_exp": True,
                    "verify_iat": True,
                    "strict_aud": True,  # may be unnecessary
                },
            )
        except jwt.exceptions.PyJWTError:
            raise web.HTTPUnauthorized(text="invalid jwt")

        # Ensure token hasn't expired\n        current_time = int(time.time())\n        if payload.get("exp") <= current_time:\n            raise web.HTTPUnauthorized(text="token has expired")\n\n        # Verify the scope\n        if payload.get("scope") != "com.atproto.access":\n            raise web.HTTPUnauthorized(text="invalid jwt scope")\n\n        # Set the authenticated DID in the request\n        subject: str = payload.get("sub", "")\n        if not subject.startswith("did:"):\n            raise web.HTTPUnauthorized(text="invalid jwt: invalid subject")\n        request["authed_did"] = subject\n        return await handler(request, *args, **kwargs)\n\n    return authentication_handler