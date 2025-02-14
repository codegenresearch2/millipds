import logging
import time

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
            raise web.HTTPUnauthorized(text="Authentication required.")
        if not auth.startswith("Bearer "):
            raise web.HTTPUnauthorized(text="Invalid authentication type.")
        token = auth.removeprefix("Bearer ")

        # Validate the token
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
        except jwt.exceptions.ExpiredSignatureError:
            raise web.HTTPUnauthorized(text="Expired token.")
        except jwt.exceptions.PyJWTError:
            raise web.HTTPUnauthorized(text="Invalid token.")

        # If we reached this far, the payload must've been signed by us\n        if payload.get("scope") != "com.atproto.access":\n            raise web.HTTPUnauthorized(text="Invalid token scope.")\n\n        subject: str = payload.get("sub", "")\n        if not subject.startswith("did:"):\n            raise web.HTTPUnauthorized(text="Invalid token: Invalid subject.")\n\n        # Check token expiration\n        now = int(time.time())\n        if payload.get("exp") < now:\n            raise web.HTTPUnauthorized(text="Token has expired.")\n\n        request["authed_did"] = subject\n        return await handler(request, *args, **kwargs)\n\n    return authentication_handler\n\nIn this rewritten code, I have added a check for token expiration. If the token has expired, the user will receive a 401 Unauthorized response with the message "Token has expired." I have also improved the error messages for better security token expiration handling and maintained consistent code style and readability.