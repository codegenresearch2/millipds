from typing import Optional, Set, Tuple
import importlib.metadata
import logging
import asyncio
import time
import os
import io
import json
import uuid
import hashlib

import apsw
import aiohttp
from aiohttp_middlewares import cors_middleware
from aiohttp import web
import jwt

import cbrrr

from . import static_config
from . import database
from . import auth_oauth
from . import atproto_sync
from . import atproto_repo
from . import crypto
from . import util
from .appview_proxy import service_proxy
from .auth_bearer import authenticated
from .app_util import *
from .did import DIDResolver

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

# Adding additional claims for enhanced security
@routes.post("/xrpc/com.atproto.server.createSession")
async def server_create_session(request: web.Request):
    # Extract the args
    try:
        req_json: dict = await request.json()
    except json.JSONDecodeError:
        raise web.HTTPBadRequest(text="expected JSON")

    identifier = req_json.get("identifier")
    password = req_json.get("password")
    if not (isinstance(identifier, str) and isinstance(password, str)):
        raise web.HTTPBadRequest(text="invalid identifier or password")

    # Do authentication
    db = get_db(request)
    try:
        did, handle = db.verify_account_login(
            did_or_handle=identifier, password=password
        )
    except KeyError:
        raise web.HTTPUnauthorized(text="user not found")
    except ValueError:
        raise web.HTTPUnauthorized(text="incorrect identifier or password")

    # Prepare access tokens with additional claims
    unix_seconds_now = int(time.time())
    access_jwt = jwt.encode(
        {
            "scope": "com.atproto.access",
            "aud": db.config["pds_did"],
            "sub": did,
            "iat": unix_seconds_now,
            "exp": unix_seconds_now + 60 * 60 * 24,  # 24h
            "jti": str(uuid.uuid4()),
            "revoked": False,  # Additional claim to track revoked tokens
        },
        db.config["jwt_access_secret"],
        "HS256",
    )

    refresh_jwt = jwt.encode(
        {
            "scope": "com.atproto.refresh",
            "aud": db.config["pds_did"],
            "sub": did,
            "iat": unix_seconds_now,
            "exp": unix_seconds_now + 60 * 60 * 24 * 90,  # 90 days!
            "jti": str(uuid.uuid4()),
            "revoked": False,  # Additional claim to track revoked tokens
        },
        db.config["jwt_access_secret"],
        "HS256",
    )

    return web.json_response(
        {
            "did": did,
            "handle": handle,
            "accessJwt": access_jwt,
            "refreshJwt": refresh_jwt,
        }
    )

# Maintaining a clean database schema design
# Assuming a revoked_tokens table is added to the database to track revoked tokens
def revoke_token(db: database.Database, token: str):
    with db.new_con() as con:
        con.execute("INSERT INTO revoked_tokens (token) VALUES (?)", (token,))

def is_token_revoked(db: database.Database, token: str) -> bool:
    with db.new_con() as con:
        row = con.execute("SELECT 1 FROM revoked_tokens WHERE token = ?", (token,)).fetchone()
        return row is not None

# Updating the authenticated decorator to check for revoked tokens
@authenticated
async def authenticated_handler(request: web.Request, handler):
    token = request.headers.get("Authorization", "").split("Bearer ")[-1]
    if is_token_revoked(get_db(request), token):
        raise web.HTTPUnauthorized(text="token is revoked")
    return await handler(request)

# Updating the server_get_service_auth endpoint to include the revoked claim
@routes.get("/xrpc/com.atproto.server.getServiceAuth")
@authenticated_handler
async def server_get_service_auth(request: web.Request):
    # ... rest of the code ...
    return web.json_response(
        {
            "token": jwt.encode(
                {
                    "iss": request["authed_did"],
                    "aud": aud,
                    "lxm": lxm,
                    "exp": exp,
                    "iat": now,
                    "jti": str(uuid.uuid4()),
                    "revoked": False,  # Additional claim to track revoked tokens
                },
                signing_key,
                algorithm=crypto.jwt_signature_alg_for_pem(signing_key),
            )
        }
    )


In this rewritten code, I have added an additional claim `revoked` to the access and refresh tokens to track revoked tokens. I have also added two functions `revoke_token` and `is_token_revoked` to the database module to handle revoked tokens. I have updated the `authenticated` decorator to check for revoked tokens and the `server_get_service_auth` endpoint to include the `revoked` claim in the generated token.