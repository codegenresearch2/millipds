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
from .did import DIDResolver

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

@web.middleware
async def atproto_service_proxy_middleware(request: web.Request, handler):
    atproto_proxy = request.headers.get("atproto-proxy")
    if atproto_proxy:
        try:
            did_resolver = get_did_resolver(request)
            service_did = await did_resolver.resolve_service(atproto_proxy)
            return await service_proxy(request, service_did)
        except Exception as e:
            logger.error(f"Failed to resolve service DID: {e}")
            raise web.HTTPBadGateway(text="Failed to resolve service DID")

    res: web.Response = await handler(request)

    res.headers.setdefault("X-Frame-Options", "DENY")
    res.headers.setdefault("X-Content-Type-Options", "nosniff")
    res.headers.setdefault("Content-Security-Policy", "default-src 'none'; sandbox")

    return res

# ... rest of the code ...

def construct_app(
	routes, db: database.Database, client: aiohttp.ClientSession
) -> web.Application:
    # ... rest of the code ...
    app[MILLIPDS_DID_RESOLVER] = DIDResolver(client)
    # ... rest of the code ...

async def run(
	db: database.Database,
	client: aiohttp.ClientSession,
	sock_path: Optional[str],
	host: str,
	port: int,
):
    # ... rest of the code ...
    if db.version != static_config.DATABASE_VERSION:
        logger.error("Database version mismatch. Please update your database schema.")
        raise RuntimeError("Database version mismatch")
    # ... rest of the code ...