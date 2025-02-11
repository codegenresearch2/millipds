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
from . import util
from .appview_proxy import service_proxy
from .auth_bearer import authenticated
from .app_util import *

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

# Middleware for ATProto service proxying
@web.middleware
async def atproto_service_proxy_middleware(request: web.Request, handler):
    atproto_proxy = request.headers.get("atproto-proxy")
    if atproto_proxy:
        return await service_proxy(request, atproto_proxy)

    res: web.Response = await handler(request)

    # Add security headers to the response
    res.headers.setdefault("X-Frame-Options", "DENY")
    res.headers.setdefault("X-Content-Type-Options", "nosniff")
    res.headers.setdefault("Content-Security-Policy", "default-src 'none'; sandbox")

    return res

# Route for the homepage
@routes.get("/")
async def hello(request: web.Request):
    version = importlib.metadata.version("millipds")
    msg = f"""
                          ,dPYb, ,dPYb,
                          IP'`Yb IP'`Yb
                     gg   I8  8I I8  8I  gg
                     ""   I8  8' I8  8'  ""
  ,ggg,,ggg,,ggg,    gg   I8 dP  I8 dP   gg   gg,gggg,
 ,8" "8P" "8P" "8,   88   I8dP   I8dP    88   I8P"  "Yb
 I8   8I   8I   8I   88   I8P    I8P     88   I8'    ,8i
,dP   8I   8I   Yb,_,88,_,d8b,_ ,d8b,_ _,88,_,I8 _  ,d8'
8P'   8I   8I   `Y88P""Y88P'"Y888P'"Y888P""Y8PI8 YY88888PP"Y8888P"`Y8P' "YY8P8P
                                              I8
                                              I8
                                              I8
                                              I8
                                              I8
                                              I8

Hello! This is an ATProto PDS instance, running millipds v{version}

https://github.com/DavidBuchanan314/millipds
"""

    return web.Response(text=msg)

# Route for serving the server's did:web document
@routes.get("/.well-known/did.json")
async def well_known_did_web(request: web.Request):
    cfg = get_db(request).config
    return web.json_response(
        {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": cfg["pds_did"],
            "service": [
                {
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": cfg["pds_pfx"],
                }
            ],
        }
    )

# Route for serving robots.txt
@routes.get("/robots.txt")
async def robots_txt(request: web.Request):
    return web.Response(
        text="""
# this is an atproto pds. please crawl it.

User-Agent: *
Allow: /
"""
    )

# Route for serving favicon.ico
@routes.get("/favicon.ico")
async def health(request: web.Request):
    return web.Response(
        text="""
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
                <text x="50%" y="0.95em" font-size="90" text-anchor="middle">🌐</text>
            </svg>
        """,
        content_type="image/svg+xml",
        headers={"Cache-Control": "max-age=864000"},
    )

# Route for health check
@routes.get("/xrpc/_health")
async def health(request: web.Request):
    version = importlib.metadata.version("millipds")
    return web.json_response({"version": f"millipds v{version}"})

# Route for getting user preferences
@routes.get("/xrpc/app.bsky.actor.getPreferences")
async def actor_get_preferences(request: web.Request):
    # Return user preferences in JSON format
    return web.json_response({"preferences": []})

# Route for updating user preferences
@routes.post("/xrpc/app.bsky.actor.putPreferences")
async def actor_put_preferences(request: web.Request):
    # Extract the preferences from the request JSON
    req_json: dict = await request.json()
    preferences = req_json.get("preferences")

    # Update the user preferences in the database
    # TODO: Implement this

    return web.Response()

# Route for resolving a handle to a DID
@routes.get("/xrpc/com.atproto.identity.resolveHandle")
async def identity_resolve_handle(request: web.Request):
    handle = request.query.get("handle")
    if handle is None:
        raise web.HTTPBadRequest(text="Missing or invalid handle")

    did = get_db(request).did_by_handle(handle)
    if not did:
        raise web.HTTPNotFound(text="No user by that handle exists on this PDS")

    return web.json_response({"did": did})

# Route for describing the server
@routes.get("/xrpc/com.atproto.server.describeServer")
async def server_describe_server(request: web.Request):
    return web.json_response(
        {
            "did": get_db(request).config["pds_did"],
            "availableUserDomains": [],
        }
    )

# Route for creating a session
@routes.post("/xrpc/com.atproto.server.createSession")
async def server_create_session(request: web.Request):
    try:
        req_json: dict = await request.json()
    except json.JSONDecodeError:
        raise web.HTTPBadRequest(text="Expected JSON")

    identifier = req_json.get("identifier")
    password = req_json.get("password")
    if not (isinstance(identifier, str) and isinstance(password, str)):
        raise web.HTTPBadRequest(text="Invalid identifier or password")

    db = get_db(request)
    try:
        did, handle = db.verify_account_login(
            did_or_handle=identifier, password=password
        )
    except KeyError:
        raise web.HTTPUnauthorized(text="User not found")
    except ValueError:
        raise web.HTTPUnauthorized(text="Incorrect identifier or password")

    unix_seconds_now = int(time.time())
    access_jwt = jwt.encode(
        {
            "scope": "com.atproto.access",
            "aud": db.config["pds_did"],
            "sub": did,
            "iat": unix_seconds_now,
            "exp": unix_seconds_now + 60 * 60 * 24,  # 24h
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

# Route for updating a handle
@routes.post("/xrpc/com.atproto.identity.updateHandle")
@authenticated
async def identity_update_handle(request: web.Request):
    req_json: dict = await request.json()
    handle = req_json.get("handle")
    if handle is None:
        raise web.HTTPBadRequest(text="Missing or invalid handle")

    # TODO: Validate the handle and update the database

    # Generate firehose events for handle update
    with get_db(request).new_con() as con:
        firehose_seq = con.execute(
            "SELECT IFNULL(MAX(seq), 0) + 1 FROM firehose"
        ).fetchone()[0]
        firehose_bytes = cbrrr.encode_dag_cbor(
            {"t": "#identity", "op": 1}
        ) + cbrrr.encode_dag_cbor(
            {
                "seq": firehose_seq,
                "did": request["authed_did"],
                "time": util.iso_string_now(),
                "handle": handle,
            }
        )
        con.execute(
            "INSERT INTO firehose (seq, timestamp, msg) VALUES (?, ?, ?)",
            (
                firehose_seq,
                0,
                firehose_bytes,
            ),
        )
    await atproto_repo.firehose_broadcast(
        request, (firehose_seq, firehose_bytes)
    )

    # Generate firehose events for account update
    with get_db(request).new_con() as con:
        firehose_seq = con.execute(
            "SELECT IFNULL(MAX(seq), 0) + 1 FROM firehose"
        ).fetchone()[0]
        firehose_bytes = cbrrr.encode_dag_cbor(
            {"t": "#account", "op": 1}
        ) + cbrrr.encode_dag_cbor(
            {
                "seq": firehose_seq,
                "did": request["authed_did"],
                "time": util.iso_string_now(),
                "active": True,
            }
        )
        con.execute(
            "INSERT INTO firehose (seq, timestamp, msg) VALUES (?, ?, ?)",
            (
                firehose_seq,
                0,
                firehose_bytes,
            ),
        )
    await atproto_repo.firehose_broadcast(
        request, (firehose_seq, firehose_bytes)
    )

    return web.Response()

# Route for getting session information
@routes.get("/xrpc/com.atproto.server.getSession")
@authenticated
async def server_get_session(request: web.Request):
    return web.json_response(
        {
            "handle": get_db(request).handle_by_did(request["authed_did"]),
            "did": request["authed_did"],
            "email": "tfw_no@email.invalid",
            "emailConfirmed": True,
        }
    )

# Function to construct the web application
def construct_app(
    routes, db: database.Database, client: aiohttp.ClientSession
) -> web.Application:
    cors = cors_middleware(
        allow_all=True,
        expose_headers=["*"],
        allow_headers=["*"],
        allow_methods=["*"],
        allow_credentials=True,
        max_age=100_000_000,
    )

    client.headers.update(
        {"User-Agent": importlib.metadata.version("millipds")}
    )

    app = web.Application(middlewares=[cors, atproto_service_proxy_middleware])
    app[MILLIPDS_DB] = db
    app[MILLIPDS_AIOHTTP_CLIENT] = client
    app[MILLIPDS_FIREHOSE_QUEUES] = set()
    app[MILLIPDS_FIREHOSE_QUEUES_LOCK] = asyncio.Lock()
    app.add_routes(routes)
    app.add_routes(auth_oauth.routes)
    app.add_routes(atproto_sync.routes)
    app.add_routes(atproto_repo.routes)

    # Fallback service proxying for bsky appview routes
    app.add_routes(
        [
            web.get("/xrpc/app.bsky.{_:.*}", service_proxy),
            web.post("/xrpc/app.bsky.{_:.*}", service_proxy),
        ]
    )

    return app

# Function to run the web application
async def run(
    db: database.Database,
    client: aiohttp.ClientSession,
    sock_path: Optional[str],
    host: str,
    port: int,
):
    app = construct_app(routes, db, client)
    runner = web.AppRunner(app, access_log_format=static_config.HTTP_LOG_FMT)
    await runner.setup()

    if sock_path is None:
        logger.info(f"Listening on http://{host}:{port}")
        site = web.TCPSite(runner, host=host, port=port)
    else:
        logger.info(f"Listening on {sock_path}")
        site = web.UnixSite(runner, path=sock_path)

    await site.start()

    if sock_path:
        import grp

        try:
            sock_gid = grp.getgrnam(static_config.GROUPNAME).gr_gid
            os.chown(sock_path, os.geteuid(), sock_gid)
        except KeyError:
            logger.warning(
                f"Failed to set socket group - group {static_config.GROUPNAME!r} not found."
            )
        except PermissionError:
            logger.warning(
                f"Failed to set socket group - are you a member of the {static_config.GROUPNAME!r} group?"
            )

        os.chmod(sock_path, 0o770)

    while True:
        await asyncio.sleep(3600)  # Sleep forever