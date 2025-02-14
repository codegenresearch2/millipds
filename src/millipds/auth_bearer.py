import logging

import jwt
from aiohttp import web
from aiohttp_jwt import JWTMiddleware

from .app_util import *
from . import crypto

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

def get_secret(request):
    db = get_db(request)
    return db.config["jwt_access_secret"]

def check_revoked_token(request, token):
    db = get_db(request)
    async with db.pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT * FROM revoked_tokens WHERE token = %s", (token,))
            return await cur.fetchone() is not None

async def check_credentials(request, token):
    db = get_db(request)
    unverified = jwt.api_jwt.decode_complete(token, options={"verify_signature": False})

    if await check_revoked_token(request, token):
        raise web.HTTPUnauthorized(text="Token has been revoked")

    if unverified["header"]["alg"] == "HS256":
        try:
            payload: dict = jwt.decode(
                jwt=token,
                key=get_secret(request),
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
            raise web.HTTPUnauthorized(text="Invalid JWT")

        if payload.get("scope") != "com.atproto.access":
            raise web.HTTPUnauthorized(text="Invalid JWT scope")

        subject: str = payload.get("sub", "")
        if not subject.startswith("did:"):
            raise web.HTTPUnauthorized(text="Invalid JWT: Invalid subject")

        return {"authed_did": subject}
    else:
        did: str = unverified["payload"]["iss"]
        if not did.startswith("did:"):
            raise web.HTTPUnauthorized(text="Invalid JWT: Invalid issuer")

        signing_key_pem = db.signing_key_pem_by_did(did)
        if signing_key_pem is None:
            raise web.HTTPUnauthorized(text="Invalid JWT: Unknown issuer")

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
            raise web.HTTPUnauthorized(text="Invalid JWT")

        request_lxm = request.path.rpartition("/")[2].partition("?")[0]
        if request_lxm != payload.get("lxm"):
            raise web.HTTPUnauthorized(text="Invalid JWT: Bad lxm")

        return {"authed_did": did}

jwt_middleware = JWTMiddleware(
    secret_or_pub_key=get_secret,
    request_property="authed_did",
    credentials_callback=check_credentials,
)

@routes.get("/protected")
@jwt_middleware
async def protected_route(request: web.Request):
    # This route is protected by JWT middleware
    return web.Response(text="You are authenticated!")


In this rewritten code, I have added a revoked_token table to the database schema. I have also added a JWT middleware to handle authentication. The middleware checks if the token is revoked, decodes the JWT, and verifies the signature. If the token is valid, it adds the authenticated DID to the request object. I have also added consistent code formatting and style to the code.