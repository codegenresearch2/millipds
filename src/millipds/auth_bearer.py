import logging

import jwt
from aiohttp import web

from .app_util import *
from . import crypto  # Assuming the crypto module is available

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

def authenticated(handler):
    """
    Decorator for handling authentication using JWT tokens.

    This decorator supports both symmetric and asymmetric tokens.
    It extracts the token from the Authorization header, validates it,
    and sets the authenticated DID in the request object.

    Args:
        handler (callable): The route handler function.

    Returns:
        callable: The decorated route handler function.
    """
    async def authentication_handler(request: web.Request, *args, **kwargs):
        # Extract the auth token
        auth = request.headers.get("Authorization")
        if auth is None:
            raise web.HTTPUnauthorized(text="Authentication required")
        if not auth.startswith("Bearer "):
            raise web.HTTPUnauthorized(text="Invalid authentication type")
        token = auth.removeprefix("Bearer ")

        # Decode the token without verifying the signature
        unverified_payload = jwt.api_jwt.decode_complete(token, options={"verify_signature": False})
        alg = unverified_payload["header"].get("alg")

        # Validate the token
        db = get_db(request)
        try:
            if alg == "HS256":
                # Symmetric token
                payload: dict = jwt.decode(
                    jwt=token,
                    key=db.config["jwt_access_secret"],
                    algorithms=[alg],
                    audience=db.config["pds_did"],
                    options={
                        "require": ["exp", "iat", "scope"],
                        "verify_exp": True,
                        "verify_iat": True,
                        "strict_aud": True,
                    },
                )
            else:
                # Asymmetric token
                iss = unverified_payload.get("iss")
                if not iss:
                    raise web.HTTPUnauthorized(text="Invalid token: missing issuer")

                # Retrieve the signing key for the issuer
                signing_key = db.signing_key_pem_by_did(iss)

                # Extract and validate the lxm from the request path
                lxm = request.match_info.get("lxm")
                if not lxm:
                    raise web.HTTPUnauthorized(text="Invalid request: missing lxm")

                payload: dict = jwt.decode(
                    jwt=token,
                    key=signing_key,
                    algorithms=[alg],
                    audience=db.config["pds_did"],
                    options={
                        "require": ["exp", "iat", "scope", "lxm"],
                        "verify_exp": True,
                        "verify_iat": True,
                        "strict_aud": True,
                    },
                )

                if payload.get("lxm") != lxm:
                    raise web.HTTPUnauthorized(text="Invalid token: lxm mismatch")

        except jwt.exceptions.ExpiredSignatureError:
            raise web.HTTPUnauthorized(text="Expired token")
        except jwt.exceptions.PyJWTError as e:
            raise web.HTTPUnauthorized(text=f"Invalid token: {str(e)}")

        # If we reached this far, the payload must've been signed by us
        if payload.get("scope") != "com.atproto.access":
            raise web.HTTPUnauthorized(text="Invalid token scope")

        subject: str = payload.get("sub", "")
        if not subject.startswith("did:"):
            raise web.HTTPUnauthorized(text="Invalid token: invalid subject")
        request["authed_did"] = subject
        return await handler(request, *args, **kwargs)

    return authentication_handler