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
from .app_util import (
    MILLIPDS_DB,
    MILLIPDS_AIOHTTP_CLIENT,
    MILLIPDS_FIREHOSE_QUEUES,
    MILLIPDS_FIREHOSE_QUEUES_LOCK,
    MILLIPDS_DID_RESOLVER,
    get_db,
    get_client,
    get_firehose_queues,
    get_firehose_queues_lock,
    get_did_resolver,
)
from .did import DIDResolver

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

# Adding DIDResolver to __all__
__all__ = [
    "MILLIPDS_DB",
    "MILLIPDS_AIOHTTP_CLIENT",
    "MILLIPDS_FIREHOSE_QUEUES",
    "MILLIPDS_FIREHOSE_QUEUES_LOCK",
    "MILLIPDS_DID_RESOLVER",
    "get_db",
    "get_client",
    "get_firehose_queues",
    "get_firehose_queues_lock",
    "get_did_resolver",
    "DIDResolver",
]

@web.middleware
async def atproto_service_proxy_middleware(request: web.Request, handler):
    # ... rest of the code ...

@routes.get("/")
async def hello(request: web.Request):
    # ... rest of the code ...

@routes.get("/.well-known/did.json")
async def well_known_did_web(request: web.Request):
    # ... rest of the code ...

@routes.get("/robots.txt")
async def robots_txt(request: web.Request):
    # ... rest of the code ...

@routes.get("/favicon.ico")
async def health(request: web.Request):
    # ... rest of the code ...

@routes.get("/xrpc/_health")
async def health(request: web.Request):
    # ... rest of the code ...

@routes.post("/xrpc/app.bsky.actor.putPreferences")
@authenticated
async def actor_put_preferences(request: web.Request):
    # ... rest of the code ...

@routes.get("/xrpc/app.bsky.actor.getPreferences")
@authenticated
async def actor_get_preferences(request: web.Request):
    # ... rest of the code ...

@routes.get("/xrpc/com.atproto.identity.resolveHandle")
async def identity_resolve_handle(request: web.Request):
    # ... rest of the code ...

@routes.get("/xrpc/com.atproto.server.describeServer")
async def server_describe_server(request: web.Request):
    # ... rest of the code ...

@routes.post("/xrpc/com.atproto.server.createSession")
async def server_create_session(request: web.Request):
    # ... rest of the code ...

@routes.get("/xrpc/com.atproto.server.getServiceAuth")
@authenticated
async def server_get_service_auth(request: web.Request):
    # ... rest of the code ...

@routes.post("/xrpc/com.atproto.identity.updateHandle")
@authenticated
async def identity_update_handle(request: web.Request):
    # ... rest of the code ...

@routes.get("/xrpc/com.atproto.server.getSession")
@authenticated
async def server_get_session(request: web.Request):
    # ... rest of the code ...

def construct_app(
    routes, db: database.Database, client: aiohttp.ClientSession
) -> web.Application:
    # ... rest of the code ...

async def run(
    db: database.Database,
    client: aiohttp.ClientSession,
    sock_path: Optional[str],
    host: str,
    port: int,
):
    # ... rest of the code ...