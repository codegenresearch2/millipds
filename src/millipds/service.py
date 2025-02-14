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

# Adding a new set to store revoked tokens
revoked_tokens = set()

@web.middleware
async def atproto_service_proxy_middleware(request: web.Request, handler):
    # Check if the token is revoked
    token = request.headers.get("Authorization")
    if token in revoked_tokens:
        raise web.HTTPUnauthorized(text="Token has been revoked")

    # Rest of the code...

@routes.post("/xrpc/com.atproto.server.createSession")
async def server_create_session(request: web.Request):
    # Extract the access token from the response
    response = await server_create_session_original(request)
    access_token = response.json().get("accessJwt")

    # Add the access token to the revoked tokens set
    revoked_tokens.add(access_token)

    return response

@routes.post("/xrpc/com.atproto.server.revokeSession")
@authenticated
async def server_revoke_session(request: web.Request):
    # Remove the token from the revoked tokens set
    token = request.headers.get("Authorization")
    revoked_tokens.discard(token)

    return web.Response()

# The rest of the code remains the same...