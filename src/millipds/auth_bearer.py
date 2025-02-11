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
        except jwt.exceptions.PyJWTError:
            raise web.HTTPUnauthorized(text="Invalid token")

        # if we reached this far, the payload must've been signed by us
        if payload.get("scope") != "com.atproto.access":
            raise web.HTTPUnauthorized(text="Invalid token scope")

        subject: str = payload.get("sub", "")
        if not subject.startswith("did:"):
            raise web.HTTPUnauthorized(text="Invalid token: invalid subject")
        request["authed_did"] = subject
        return await handler(request, *args, **kwargs)

    return authentication_handler