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
    msg = f"""\n                          ,dPYb, ,dPYb,\n                          IP'`Yb IP'`Yb\n                     gg   I8  8I I8  8I  gg\n                     ""   I8  8' I8  8'  ""\n  ,ggg,,ggg,,ggg,    gg   I8 dP  I8 dP   gg   gg,gggg,\n ,8" "8P" "8P" "8,   88   I8dP   I8dP    88   I8P"  "Yb\n I8   8I   8I   8I   88   I8P    I8P     88   I8'    ,8i\n,dP   8I   8I   Yb,_,88,_,d8b,_ ,d8b,_ _,88,_,I8 _  ,d8'\n8P'   8I   8I   `Y88P""Y88P'"Y888P'"Y888P""Y8PI8 YY88888PP"Y8888P"`Y8P' "YY8P8P\n                                              I8\n                                              I8\n                                              I8\n                                              I8\n                                              I8\n                                              I8\n\nHello! This is an ATProto PDS instance, running millipds v{version}\n\nhttps://github.com/DavidBuchanan314/millipds\n"""

    return web.Response(text=msg)

# Route for serving the server's did:web document\n@routes.get("/.well-known/did.json")\nasync def well_known_did_web(request: web.Request):\n    cfg = get_db(request).config\n    return web.json_response(\n        {\n            "@context": ["https://www.w3.org/ns/did/v1"],\n            "id": cfg["pds_did"],\n            "service": [\n                {\n                    "id": "#atproto_pds",\n                    "type": "AtprotoPersonalDataServer",\n                    "serviceEndpoint": cfg["pds_pfx"],\n                }\n            ],\n        }\n    )\n\n# Route for serving robots.txt\n@routes.get("/robots.txt")\nasync def robots_txt(request: web.Request):\n    return web.Response(\n        text="""\n# this is an atproto pds. please crawl it.\n\nUser-Agent: *\nAllow: /\n"""\n    )\n\n# Route for serving favicon.ico\n@routes.get("/favicon.ico")\nasync def health(request: web.Request):\n    return web.Response(\n        text="""\n            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">\n                <text x="50%" y="0.95em" font-size="90" text-anchor="middle">🌐</text>\n            </svg>\n        """,\n        content_type="image/svg+xml",\n        headers={"Cache-Control": "max-age=864000"},\n    )\n\n# Route for health check\n@routes.get("/xrpc/_health")\nasync def health(request: web.Request):\n    version = importlib.metadata.version("millipds")\n    return web.json_response({"version": f"millipds v{version}"})\n\n# Route for getting user preferences\n@routes.get("/xrpc/app.bsky.actor.getPreferences")\nasync def actor_get_preferences(request: web.Request):\n    # Return user preferences in JSON format\n    return web.json_response({"preferences": []})\n\n# Route for updating user preferences\n@routes.post("/xrpc/app.bsky.actor.putPreferences")\nasync def actor_put_preferences(request: web.Request):\n    # Update user preferences based on the JSON data in the request\n    # TODO: Implement this\n    return web.Response()\n\n# Route for resolving a handle to a DID\n@routes.get("/xrpc/com.atproto.identity.resolveHandle")\nasync def identity_resolve_handle(request: web.Request):\n    handle = request.query.get("handle")\n    if handle is None:\n        raise web.HTTPBadRequest(text="Missing or invalid handle")\n    did = get_db(request).did_by_handle(handle)\n    if not did:\n        raise web.HTTPNotFound(text="No user by that handle exists on this PDS")\n    return web.json_response({"did": did})\n\n# Route for describing the server\n@routes.get("/xrpc/com.atproto.server.describeServer")\nasync def server_describe_server(request: web.Request):\n    return web.json_response(\n        {\n            "did": get_db(request).config["pds_did"],\n            "availableUserDomains": [],\n        }\n    )\n\n# Route for creating a session\n@routes.post("/xrpc/com.atproto.server.createSession")\nasync def server_create_session(request: web.Request):\n    try:\n        req_json: dict = await request.json()\n    except json.JSONDecodeError:\n        raise web.HTTPBadRequest(text="Expected JSON")\n\n    identifier = req_json.get("identifier")\n    password = req_json.get("password")\n    if not (isinstance(identifier, str) and isinstance(password, str)):\n        raise web.HTTPBadRequest(text="Invalid identifier or password")\n\n    db = get_db(request)\n    try:\n        did, handle = db.verify_account_login(\n            did_or_handle=identifier, password=password\n        )\n    except KeyError:\n        raise web.HTTPUnauthorized(text="User not found")\n    except ValueError:\n        raise web.HTTPUnauthorized(text="Incorrect identifier or password")\n\n    unix_seconds_now = int(time.time())\n    access_jwt = jwt.encode(\n        {\n            "scope": "com.atproto.access",\n            "aud": db.config["pds_did"],\n            "sub": did,\n            "iat": unix_seconds_now,\n            "exp": unix_seconds_now + 60 * 60 * 24,  # 24h\n        },\n        db.config["jwt_access_secret"],\n        "HS256",\n    )\n\n    refresh_jwt = jwt.encode(\n        {\n            "scope": "com.atproto.refresh",\n            "aud": db.config["pds_did"],\n            "sub": did,\n            "iat": unix_seconds_now,\n            "exp": unix_seconds_now + 60 * 60 * 24 * 90,  # 90 days!\n        },\n        db.config["jwt_access_secret"],\n        "HS256",\n    )\n\n    return web.json_response(\n        {\n            "did": did,\n            "handle": handle,\n            "accessJwt": access_jwt,\n            "refreshJwt": refresh_jwt,\n        }\n    )\n\n# Route for updating a handle\n@routes.post("/xrpc/com.atproto.identity.updateHandle")\n@authenticated\nasync def identity_update_handle(request: web.Request):\n    req_json: dict = await request.json()\n    handle = req_json.get("handle")\n    if handle is None:\n        raise web.HTTPBadRequest(text="Missing or invalid handle")\n    # TODO: Validate the handle and update the database\n\n    with get_db(request).new_con() as con:\n        firehose_seq = con.execute(\n            "SELECT IFNULL(MAX(seq), 0) + 1 FROM firehose"\n        ).fetchone()[0]\n        firehose_bytes = cbrrr.encode_dag_cbor(\n            {"t": "#identity", "op": 1}\n        ) + cbrrr.encode_dag_cbor(\n            {\n                "seq": firehose_seq,\n                "did": request["authed_did"],\n                "time": util.iso_string_now(),\n                "handle": handle,\n            }\n        )\n        con.execute(\n            "INSERT INTO firehose (seq, timestamp, msg) VALUES (?, ?, ?)",\n            (\n                firehose_seq,\n                0,\n                firehose_bytes,\n            ),\n        )\n    await atproto_repo.firehose_broadcast(\n        request, (firehose_seq, firehose_bytes)\n    )\n\n    # Temporary hack: #account events shouldn't be generated here
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