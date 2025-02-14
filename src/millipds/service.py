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

# Tracking revoked tokens
revoked_tokens = set()

@web.middleware
async def atproto_service_proxy_middleware(request: web.Request, handler):
    # Check if token is revoked
    token = request.headers.get("Authorization")
    if token and token in revoked_tokens:
        raise web.HTTPUnauthorized(text="Token has been revoked")

    # Rest of the code...

@routes.post("/xrpc/com.atproto.server.revokeToken")
@authenticated
async def server_revoke_token(request: web.Request):
    token = request.headers.get("Authorization")
    if token:
        revoked_tokens.add(token)
        return web.Response()
    else:
        raise web.HTTPBadRequest(text="No token provided")

# The rest of the code...


In this rewritten code, I have added a new middleware `atproto_service_proxy_middleware` that checks if the provided token is in the `revoked_tokens` set. If the token is revoked, it raises an `HTTPUnauthorized` exception.

Additionally, I have added a new endpoint `/xrpc/com.atproto.server.revokeToken` that allows a user to revoke their token. When a token is revoked, it is added to the `revoked_tokens` set.

These changes enhance security by allowing users to revoke their tokens for better management.