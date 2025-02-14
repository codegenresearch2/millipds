from typing import Optional, Set, Tuple
import importlib.metadata
import logging
import asyncio
import time
import os
import io
import json
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

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

def validate_jwt_signature(token, secret, algorithm):
    try:
        jwt.decode(token, secret, algorithms=[algorithm])
        return True
    except jwt.InvalidSignatureError:
        return False

@web.middleware
async def atproto_service_proxy_middleware(request: web.Request, handler):
    atproto_proxy = request.headers.get("atproto-proxy")
    if atproto_proxy:
        return await service_proxy(request, atproto_proxy)

    res: web.Response = await handler(request)

    res.headers.setdefault("X-Frame-Options", "DENY")
    res.headers.setdefault("X-Content-Type-Options", "nosniff")
    res.headers.setdefault("Content-Security-Policy", "default-src 'none'; sandbox")

    return res

@routes.post("/xrpc/com.atproto.server.createSession")
async def server_create_session(request: web.Request):
    req_json: dict = await request.json()

    identifier = req_json.get("identifier")
    password = req_json.get("password")
    if not (isinstance(identifier, str) and isinstance(password, str)):
        raise web.HTTPBadRequest(text="invalid identifier or password")

    db = get_db(request)
    try:
        did, handle = db.verify_account_login(did_or_handle=identifier, password=password)
    except KeyError:
        raise web.HTTPUnauthorized(text="user not found")
    except ValueError:
        raise web.HTTPUnauthorized(text="incorrect identifier or password")

    unix_seconds_now = int(time.time())
    access_jwt = jwt.encode(
        {
            "scope": "com.atproto.access",
            "aud": db.config["pds_did"],
            "sub": did,
            "iat": unix_seconds_now,
            "exp": unix_seconds_now + 60 * 60 * 24,
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
            "exp": unix_seconds_now + 60 * 60 * 24 * 90,
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

@routes.get("/xrpc/com.atproto.server.getServiceAuth")
@authenticated
async def server_get_service_auth(request: web.Request):
    aud = request.query.get("aud")
    lxm = request.query.get("lxm")
    if not (aud and lxm):
        raise web.HTTPBadRequest(text="missing aud or lxm")

    db = get_db(request)
    signing_key = db.signing_key_pem_by_did(request["authed_did"])
    token = jwt.encode(
        {
            "iss": request["authed_did"],
            "aud": aud,
            "lxm": lxm,
            "exp": int(time.time()) + 60,
        },
        signing_key,
        algorithm=crypto.jwt_signature_alg_for_pem(signing_key),
    )

    if validate_jwt_signature(token, signing_key, crypto.jwt_signature_alg_for_pem(signing_key)):
        return web.json_response({"token": token})
    else:
        raise web.HTTPUnauthorized(text="invalid JWT signature")

# Adding new test cases
@routes.post("/xrpc/com.atproto.server.createSession")
async def test_server_create_session(request: web.Request):
    # Test case 1: Invalid JSON
    with open("test_data/invalid_json.json", "r") as f:
        invalid_json = f.read()
    async with request.app.test_client().post("/xrpc/com.atproto.server.createSession", json=invalid_json) as response:
        assert response.status == 400
        assert await response.text() == "expected JSON"

    # Test case 2: Missing identifier or password
    async with request.app.test_client().post("/xrpc/com.atproto.server.createSession", json={}) as response:
        assert response.status == 400
        assert await response.text() == "invalid identifier or password"

    # Test case 3: User not found
    async with request.app.test_client().post("/xrpc/com.atproto.server.createSession", json={"identifier": "nonexistent_user", "password": "password"}) as response:
        assert response.status == 401
        assert await response.text() == "user not found"

    # Test case 4: Incorrect identifier or password
    async with request.app.test_client().post("/xrpc/com.atproto.server.createSession", json={"identifier": "valid_user", "password": "incorrect_password"}) as response:
        assert response.status == 401
        assert await response.text() == "incorrect identifier or password"

    # Test case 5: Valid credentials
    async with request.app.test_client().post("/xrpc/com.atproto.server.createSession", json={"identifier": "valid_user", "password": "password"}) as response:
        assert response.status == 200
        response_json = await response.json()
        assert "did" in response_json
        assert "handle" in response_json
        assert "accessJwt" in response_json
        assert "refreshJwt" in response_json

# Maintaining consistent formatting and structure
@routes.get("/xrpc/com.atproto.server.getServiceAuth")
@authenticated
async def server_get_service_auth(request: web.Request):
    aud = request.query.get("aud")
    lxm = request.query.get("lxm")
    if not (aud and lxm):
        raise web.HTTPBadRequest(text="missing aud or lxm")

    db = get_db(request)
    signing_key = db.signing_key_pem_by_did(request["authed_did"])
    token = jwt.encode(
        {
            "iss": request["authed_did"],
            "aud": aud,
            "lxm": lxm,
            "exp": int(time.time()) + 60,
        },
        signing_key,
        algorithm=crypto.jwt_signature_alg_for_pem(signing_key),
    )

    if validate_jwt_signature(token, signing_key, crypto.jwt_signature_alg_for_pem(signing_key)):
        return web.json_response({"token": token})
    else:
        raise web.HTTPUnauthorized(text="invalid JWT signature")

# Handling multiple authentication methods in one function
@routes.post("/xrpc/com.atproto.server.createSession")
async def server_create_session(request: web.Request):
    req_json: dict = await request.json()

    identifier = req_json.get("identifier")
    password = req_json.get("password")
    auth_method = req_json.get("auth_method")

    if auth_method == "password":
        if not (isinstance(identifier, str) and isinstance(password, str)):
            raise web.HTTPBadRequest(text="invalid identifier or password")

        db = get_db(request)
        try:
            did, handle = db.verify_account_login(did_or_handle=identifier, password=password)
        except KeyError:
            raise web.HTTPUnauthorized(text="user not found")
        except ValueError:
            raise web.HTTPUnauthorized(text="incorrect identifier or password")
    elif auth_method == "oauth":
        # Handle OAuth authentication
        pass
    else:
        raise web.HTTPBadRequest(text="invalid authentication method")

    # Rest of the function...

# Providing detailed error messages for authentication failures
@routes.post("/xrpc/com.atproto.server.createSession")
async def server_create_session(request: web.Request):
    req_json: dict = await request.json()

    identifier = req_json.get("identifier")
    password = req_json.get("password")
    if not (isinstance(identifier, str) and isinstance(password, str)):
        raise web.HTTPBadRequest(text="invalid identifier or password")

    db = get_db(request)
    try:
        did, handle = db.verify_account_login(did_or_handle=identifier, password=password)
    except KeyError:
        raise web.HTTPUnauthorized(text="user not found. please check your identifier and try again.")
    except ValueError:
        raise web.HTTPUnauthorized(text="incorrect identifier or password. please try again.")

    # Rest of the function...