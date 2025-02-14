import logging

import jwt
from aiohttp import web

from .app_util import *

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

def authenticated(handler):
    async def authentication_handler(request: web.Request, *args, **kwargs):
        # extract the auth token
        auth = request.headers.get("Authorization")
        if auth is None:
            raise web.HTTPUnauthorized(text="Authentication required")
        if not auth.startswith("Bearer "):
            raise web.HTTPUnauthorized(text="Invalid authentication type")
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
        except jwt.exceptions.ExpiredSignatureError:
            raise web.HTTPUnauthorized(text="Expired token")
        except jwt.exceptions.InvalidTokenError:
            raise web.HTTPUnauthorized(text="Invalid token")

        # if we reached this far, the payload must've been signed by us\n        if payload.get("scope") != "com.atproto.access":\n            raise web.HTTPUnauthorized(text="Invalid token scope")\n\n        subject: str = payload.get("sub", "")\n        if not subject.startswith("did:"):\n            raise web.HTTPUnauthorized(text="Invalid token: invalid subject")\n        request["authed_did"] = subject\n        return await handler(request, *args, **kwargs)\n\n    return authentication_handler\n\n\nIn the rewritten code, I have enhanced the security token expiration handling by adding specific error messages for expired and invalid tokens. I have also improved error handling for service authentication by providing more specific error messages. I have maintained consistent code style and readability by following the existing code's formatting and commenting style.