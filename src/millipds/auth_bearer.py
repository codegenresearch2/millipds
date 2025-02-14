import logging
import uuid

import jwt
from aiohttp import web

from .app_util import *
from . import crypto

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

class TokenTracker:
    def __init__(self, db):
        self.db = db

    async def is_token_revoked(self, token_jti):
        async with self.db.acquire() as conn:
            cur = await conn.execute(
                'SELECT 1 FROM revoked_tokens WHERE jti = $1', (token_jti,)
            )
            return await cur.fetchone() is not None

    async def revoke_token(self, token_jti):
        async with self.db.acquire() as conn:
            await conn.execute(
                'INSERT INTO revoked_tokens (jti) VALUES ($1)', (token_jti,)
            )

def authenticated(handler):
    async def authentication_handler(request: web.Request, *args, **kwargs):
        auth = request.headers.get("Authorization")
        if auth is None:
            raise web.HTTPUnauthorized(
                text="authentication required"
            )
        if not auth.startswith("Bearer "):
            raise web.HTTPUnauthorized(text="invalid auth type")
        token = auth.removeprefix("Bearer ")

        db = get_db(request)
        token_tracker = TokenTracker(db)

        unverified = jwt.api_jwt.decode_complete(
            token, options={"verify_signature": False}
        )
        token_jti = unverified["payload"].get("jti")
        if token_jti:
            if await token_tracker.is_token_revoked(token_jti):
                raise web.HTTPUnauthorized(text="token has been revoked")

        if unverified["header"]["alg"] == "HS256":
            try:
                payload: dict = jwt.decode(
                    jwt=token,
                    key=db.config["jwt_access_secret"],
                    algorithms=["HS256"],
                    audience=db.config["pds_did"],
                    options={
                        "require": ["exp", "iat", "scope", "jti"],
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
            request["authed_did"] = subject
        else:
            did: str = unverified["payload"]["iss"]
            if not did.startswith("did:"):
                raise web.HTTPUnauthorized(text="invalid jwt: invalid issuer")
            signing_key_pem = db.signing_key_pem_by_did(did)
            if signing_key_pem is None:
                raise web.HTTPUnauthorized(text="invalid jwt: unknown issuer")
            alg = crypto.jwt_signature_alg_for_pem(signing_key_pem)
            verifying_key = crypto.privkey_from_pem(
                signing_key_pem
            ).public_key()
            try:
                payload = jwt.decode(
                    jwt=token,
                    key=verifying_key,
                    algorithms=[alg],
                    audience=db.config["pds_did"],
                    options={
                        "require": ["exp", "iat", "lxm", "jti"],
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

            request["authed_did"] = did

        return await handler(request, *args, **kwargs)

    return authentication_handler

In the updated code, a `TokenTracker` class is added to track revoked tokens. This class uses a `revoked_tokens` table in the database to store revoked tokens' JWT IDs (`jti`). The `is_token_revoked` method checks if a token has been revoked, and the `revoke_token` method revokes a token by adding its `jti` to the `revoked_tokens` table.\n\nThe `authenticated` decorator has been updated to check if a token has been revoked before authenticating it. If a token's `jti` is found in the `revoked_tokens` table, an `HTTPUnauthorized` exception is raised.

Additionally, the `options` dictionary for `jwt.decode` has been updated to require the `jti` claim, ensuring unique identifiers for tokens.