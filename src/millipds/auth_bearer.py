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

        # Check if the 'header' key exists in the payload
        if 'header' not in unverified_payload:
            raise web.HTTPUnauthorized(text="Invalid token: missing header")

        alg = unverified_payload["header"].get("alg")

        # Validate the token
        db = get_db(request)
        try:
            # Check if the database connection is established and the necessary tables exist
            db.con.execute("SELECT 1 FROM config LIMIT 1")
        except Exception as e:
            raise web.HTTPUnauthorized(text="Authentication not possible due to a database configuration issue")

        try:
            # Check if the required configuration values are present
            if not all(key in db.config for key in ["jwt_access_secret", "pds_did"]):
                raise web.HTTPUnauthorized(text="Authentication not possible due to a configuration issue")

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
                if not signing_key:
                    raise web.HTTPUnauthorized(text="Invalid token: signing key not found")

                # Extract and validate the lxm from the request path
                lxm = request.match_info.get("lxm")
                if not lxm:
                    raise web.HTTPUnauthorized(text="Invalid request: missing lxm")

                payload: dict = jwt.decode(
                    jwt=token,
                    key=signing_key,
                    algorithms=[crypto.jwt_signature_alg_for_pem(signing_key)],
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

        did = payload.get("sub", "")
        if not did.startswith("did:"):
            raise web.HTTPUnauthorized(text="Invalid token: invalid subject")
        request["authed_did"] = did
        return await handler(request, *args, **kwargs)

    return authentication_handler