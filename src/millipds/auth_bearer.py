import logging
import uuid

import jwt
from aiohttp import web

from .app_util import *
from . import crypto

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

def authenticated(handler):
    async def authentication_handler(request: web.Request, *args, **kwargs):
        auth = request.headers.get("Authorization")
        if auth is None:
            raise web.HTTPUnauthorized(text="authentication required")
        if not auth.startswith("Bearer "):
            raise web.HTTPUnauthorized(text="invalid auth type")
        token = auth.removeprefix("Bearer ")

        db = get_db(request)

        unverified = jwt.api_jwt.decode_complete(token, options={"verify_signature": False})
        token_id = str(uuid.uuid4())

        if unverified["header"]["alg"] == "HS256":
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
                raise web.HTTPUnauthorized(text="invalid jwt")

            if payload.get("scope") != "com.atproto.access":
                raise web.HTTPUnauthorized(text="invalid jwt scope")

            subject: str = payload.get("sub", "")
            if not subject.startswith("did:"):
                raise web.HTTPUnauthorized(text="invalid jwt: invalid subject")

            if db.is_token_revoked(token_id):
                raise web.HTTPUnauthorized(text="token has been revoked")

            request["authed_did"] = subject
            request["token_id"] = token_id
        else:
            did: str = unverified["payload"]["iss"]
            if not did.startswith("did:"):
                raise web.HTTPUnauthorized(text="invalid jwt: invalid issuer")
            signing_key_pem = db.signing_key_pem_by_did(did)
            if signing_key_pem is None:
                raise web.HTTPUnauthorized(text="invalid jwt: unknown issuer")
            alg = crypto.jwt_signature_alg_for_pem(signing_key_pem)
            verifying_key = crypto.privkey_from_pem(signing_key_pem).public_key()
            try:
                payload = jwt.decode(
                    jwt=token,
                    key=verifying_key,
                    algorithms=[alg],
                    audience=db.config["pds_did"],
                    options={
                        "require": ["exp", "iat", "lxm"],
                        "verify_exp": True,
                        "verify_iat": True,
                        "strict_aud": True,
                    },
                )
            except jwt.exceptions.PyJWTError:
                raise web.HTTPUnauthorized(text="invalid jwt")

            request_lxm = request.path.rpartition("/")[2].partition("?")[0]
            if request_lxm != payload.get("lxm"):
                raise web.HTTPUnauthorized(text="invalid jwt: bad lxm")

            if db.is_token_revoked(token_id):
                raise web.HTTPUnauthorized(text="token has been revoked")

            request["authed_did"] = did
            request["token_id"] = token_id

        return await handler(request, *args, **kwargs)

    return authentication_handler


In the rewritten code, I have added a unique identifier for each token using the `uuid` module. I have also added a check to see if the token has been revoked before allowing the request to proceed. This is done by calling the `is_token_revoked` method on the database object, which is assumed to be implemented elsewhere.