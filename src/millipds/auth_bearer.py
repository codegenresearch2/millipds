import logging
import jwt
from aiohttp import web
from .app_util import *
from . import crypto

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

def authenticated(handler):
    """\n    There are three types of auth:\n     - bearer token signed by symmetric secret (generated by us during the password login flow)\n     - "service" bearer token signed by (asymmetric) repo signing key, scoped to a specific lxm\n     - whatever I do for oauth (TODO)\n    """

    async def authentication_handler(request: web.Request, *args, **kwargs):
        # extract the auth token
        auth = request.headers.get("Authorization")
        if auth is None:
            raise web.HTTPUnauthorized(
                text="authentication required (this may be a bug, I'm erring on the side of caution for now)"
            )
        if not auth.startswith("Bearer "):
            raise web.HTTPUnauthorized(text="invalid auth type")
        token = auth.removeprefix("Bearer ")

        # validate it TODO: this needs rigorous testing, I'm not 100% sure I'm
        # verifying all the things that need verifying
        db = get_db(request)

        unverified = jwt.api_jwt.decode_complete(
            token, options={"verify_signature": False}
        )
        # logger.info(unverified)
        if unverified["header"]["alg"] == "HS256":  # symmetric secret
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

            # if we reached this far, the payload must've been signed by us\n            if payload.get("scope") != "com.atproto.access":\n                raise web.HTTPUnauthorized(text="invalid jwt scope")\n\n            subject: str = payload.get("sub", "")\n            if not subject.startswith("did:"):\n                raise web.HTTPUnauthorized(text="invalid jwt: invalid subject")\n            request["authed_did"] = subject\n            # Track revoked tokens for security\n            if is_token_revoked(subject, token):\n                raise web.HTTPUnauthorized(text="token revoked")\n        else:  # asymmetric service auth (scoped to a specific lxm)\n            did: str = unverified["payload"]["iss"]\n            if not did.startswith("did:"):\n                raise web.HTTPUnauthorized(text="invalid jwt: invalid issuer")\n            signing_key_pem = db.signing_key_pem_by_did(did)\n            if signing_key_pem is None:\n                raise web.HTTPUnauthorized(text="invalid jwt: unknown issuer")\n            alg = crypto.jwt_signature_alg_for_pem(signing_key_pem)\n            verifying_key = crypto.privkey_from_pem(\n                signing_key_pem\n            ).public_key()\n            try:\n                payload = jwt.decode(\n                    jwt=token,\n                    key=verifying_key,\n                    algorithms=[alg],\n                    audience=db.config["pds_did"],\n                    options={\n                        "require": ["exp", "iat", "lxm"],\n                        "verify_exp": True,\n                        "verify_iat": True,\n                        "strict_aud": True,  # may be unnecessary\n                    },\n                )\n            except jwt.exceptions.PyJWTError:\n                raise web.HTTPUnauthorized(text="invalid jwt")\n\n            request_lxm = request.path.rpartition("/")[2].partition("?")[0]\n            if request_lxm != payload.get("lxm"):\n                raise web.HTTPUnauthorized(text="invalid jwt: bad lxm")\n\n            # everything checks out\n            request["authed_did"] = did\n            # Track revoked tokens for security\n            if is_token_revoked(did, token):\n                raise web.HTTPUnauthorized(text="token revoked")\n\n        return await handler(request, *args, **kwargs)\n\n    return authentication_handler\n\n# Function to track revoked tokens\ndef is_token_revoked(did, token):\n    # Implement token revocation logic here\n    # This could involve checking a database table where revoked tokens are stored\n    revoked_tokens = get_revoked_tokens()  # Placeholder function to get revoked tokens\n    return token in revoked_tokens.get(did, [])\n\n# Placeholder function to get revoked tokens\ndef get_revoked_tokens():\n    # This should ideally query a database to get the list of revoked tokens\n    # For simplicity, we'll return a dictionary with dummy data
    return {
        "did:example:123": ["revoked_token_1", "revoked_token_2"],
        "did:example:456": ["revoked_token_3"]
    }