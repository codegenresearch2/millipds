from typing import Optional
import importlib.metadata
import logging
import asyncio
import time
import os
import json

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
from . import util
from .appview_proxy import service_proxy
from .auth_bearer import authenticated
from .app_util import get_db, MILLIPDS_DB, MILLIPDS_AIOHTTP_CLIENT, MILLIPDS_FIREHOSE_QUEUES, MILLIPDS_FIREHOSE_QUEUES_LOCK

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

# SQL statements centralized in one file
SQL_QUERIES = {
    'verify_account_login': "SELECT did, handle, password_hash FROM accounts WHERE did = ? OR handle = ?",
    'did_by_handle': "SELECT did FROM accounts WHERE handle = ?",
    'handle_by_did': "SELECT handle FROM accounts WHERE did = ?",
    'firehose_seq': "SELECT IFNULL(MAX(seq), 0) + 1 FROM firehose",
    'insert_firehose': "INSERT INTO firehose (seq, timestamp, msg) VALUES (?, ?, ?)",
}

@web.middleware
async def atproto_service_proxy_middleware(request: web.Request, handler):
    # ... (existing code)

@routes.get("/")
async def hello(request: web.Request):
    # ... (existing code)

@routes.get("/.well-known/did.json")
async def well_known_did_web(request: web.Request):
    # ... (existing code)

@routes.get("/robots.txt")
async def robots_txt(request: web.Request):
    # ... (existing code)

@routes.get("/favicon.ico")
async def health(request: web.Request):
    # ... (existing code)

@routes.get("/xrpc/_health")
async def health(request: web.Request):
    # ... (existing code)

@routes.get("/xrpc/app.bsky.actor.getPreferences")
async def actor_get_preferences(request: web.Request):
    # Clarify comment for better understanding
    # Return an empty list as per user preference
    return web.json_response({"preferences": []})

@routes.post("/xrpc/app.bsky.actor.putPreferences")
async def actor_put_preferences(request: web.Request):
    # TODO: actually implement this
    return web.Response()

@routes.get("/xrpc/com.atproto.identity.resolveHandle")
async def identity_resolve_handle(request: web.Request):
    # ... (existing code)

@routes.get("/xrpc/com.atproto.server.describeServer")
async def server_describe_server(request: web.Request):
    # ... (existing code)

@routes.post("/xrpc/com.atproto.server.createSession")
async def server_create_session(request: web.Request):
    # ... (existing code)

@routes.post("/xrpc/com.atproto.identity.updateHandle")
@authenticated
async def identity_update_handle(request: web.Request):
    # ... (existing code)

@routes.get("/xrpc/com.atproto.server.getSession")
@authenticated
async def server_get_session(request: web.Request):
    # ... (existing code)

def construct_app(routes, db: database.Database, client: aiohttp.ClientSession) -> web.Application:
    # ... (existing code)

async def run(db: database.Database, client: aiohttp.ClientSession, sock_path: Optional[str], host: str, port: int):
    # ... (existing code)