import logging
import time

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
            raise web.HTTPUnauthorized(text="authentication required")
        if not auth.startswith("Bearer "):
            raise web.HTTPUnauthorized(text="invalid auth type")
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
        except jwt.exceptions.PyJWTError as e:
            raise web.HTTPUnauthorized(text=f"invalid jwt: {str(e)}")

        # if we reached this far, the payload must've been signed by us\n        if payload.get("scope") != "com.atproto.access":\n            raise web.HTTPUnauthorized(text="invalid jwt scope")\n\n        subject: str = payload.get("sub", "")\n        if not subject.startswith("did:"):\n            raise web.HTTPUnauthorized(text="invalid jwt: invalid subject")\n\n        # enforce expiration time limit\n        exp = payload.get("exp")\n        if exp is not None and exp < int(time.time()):\n            raise web.HTTPUnauthorized(text="expired jwt")\n\n        request["authed_did"] = subject\n        return await handler(request, *args, **kwargs)\n\n    return authentication_handler\n\n\nIn the rewritten code, I have added a check to validate the expiration time of the token. If the token has expired, a `web.HTTPUnauthorized` exception is raised with an appropriate error message. I have also added more strict validation of input parameters in the `jwt.decode` function.