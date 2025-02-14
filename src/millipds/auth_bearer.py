import logging

import jwt
from aiohttp import web
from sqlalchemy import Column, String, DateTime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from .app_util import *
from . import crypto

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

Base = declarative_base()

class RevokedToken(Base):
    __tablename__ = 'revoked_tokens'

    token = Column(String, primary_key=True)
    expiration = Column(DateTime, nullable=False)

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

        # Check if the token is revoked
        db = get_db(request)
        Session = sessionmaker(bind=db.engine)
        session = Session()
        revoked_token = session.query(RevokedToken).filter_by(token=token).first()
        if revoked_token:
            raise web.HTTPUnauthorized(text="token has been revoked")

        # validate it
        unverified = jwt.api_jwt.decode_complete(
            token, options={"verify_signature": False}
        )
        if unverified["header"]["alg"] == "HS256":  # symmetric secret
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
            request["authed_did"] = subject
        else:  # asymmetric service auth (scoped to a specific lxm)
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

            request["authed_did"] = did

        return await handler(request, *args, **kwargs)

    return authentication_handler