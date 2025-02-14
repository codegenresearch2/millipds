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


@routes.get("/")
async def hello(request: web.Request):
    version = importlib.metadata.version("millipds")
    msg = f"""\n                          ,dPYb, ,dPYb,                           8I\n                          IP'`Yb IP'`Yb                           8I\n                     gg   I8  8I I8  8I  gg                       8I\n                     ""   I8  8' I8  8'  ""                       8I\n  ,ggg,,ggg,,ggg,    gg   I8 dP  I8 dP   gg   gg,gggg,      ,gggg,8I     ,gg,\n ,8" "8P" "8P" "8,   88   I8dP   I8dP    88   I8P"  "Yb    dP"  "Y8I   ,8'8,\n I8   8I   8I   8I   88   I8P    I8P     88   I8'    ,8i  i8'    ,8I  ,8'  Yb\n,dP   8I   8I   Yb,_,88,_,d8b,_ ,d8b,_ _,88,_,I8 _  ,d8' ,d8,   ,d8b,,8'_   8)\n8P'   8I   8I   `Y88P""Y88P'"Y888P'"Y888P""Y8PI8 YY88888PP"Y8888P"`Y8P' "YY8P8P\n                                              I8\n                                              I8\n                                              I8\n                                              I8\n                                              I8\n                                              I8\n\n\nHello! This is an ATProto PDS instance, running millipds v{version}\n\nhttps://github.com/DavidBuchanan314/millipds\n"""

    return web.Response(text=msg)


@routes.get("/.well-known/did.json")
async def well_known_did_web(request: web.Request):
    cfg = get_db(request).config
    return web.json_response(
        {
            "@context": [
                "https://www.w3.org/ns/did/v1",
            ],
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


@routes.get("/robots.txt")
async def robots_txt(request: web.Request):
    return web.Response(
        text="""\
# this is an atproto pds. please crawl it.\n\nUser-Agent: *\nAllow: /\n"""
    )


@routes.get("/favicon.ico")
async def health(request: web.Request):
    return web.Response(
        text="""\n            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">\n                <text x="50%" y="0.95em" font-size="90" text-anchor="middle">🌐</text>\n            </svg>\n        """,
        content_type="image/svg+xml",
        headers={"Cache-Control": "max-age=864000"},
    )


@routes.get("/xrpc/_health")
async def health(request: web.Request):
    version = importlib.metadata.version("millipds")
    return web.json_response({"version": f"millipds v{version}"})


@routes.post("/xrpc/app.bsky.actor.putPreferences")
@authenticated
async def actor_put_preferences(request: web.Request):
    prefs = await request.json()
    pref_bytes = json.dumps(
        prefs,
        ensure_ascii=False,
        separators=(",", ":"),
        check_circular=False,
    ).encode()
    db = get_db(request)
    db.con.execute(
        "UPDATE user SET prefs=? WHERE did=?",
        (pref_bytes, request["authed_did"]),
    )
    return web.Response()


@routes.get("/xrpc/app.bsky.actor.getPreferences")
@authenticated
async def actor_get_preferences(request: web.Request):
    db = get_db(request)
    row = db.con.execute(
        "SELECT prefs FROM user WHERE did=?", (request["authed_did"],)
    ).fetchone()

    assert row is not None

    prefs = json.loads(row[0])

    if not prefs:
        prefs = {"preferences": []}

    return web.json_response(prefs)


@routes.get("/xrpc/com.atproto.identity.resolveHandle")
async def identity_resolve_handle(request: web.Request):
    handle = request.query.get("handle")
    if handle is None:
        raise web.HTTPBadRequest(text="missing or invalid handle")

    did = get_db(request).did_by_handle(handle)
    if not did:
        return await service_proxy(request)

    return web.json_response({"did": did})


@routes.get("/xrpc/com.atproto.server.describeServer")
async def server_describe_server(request: web.Request):
    return web.json_response(
        {
            "did": get_db(request).config["pds_did"],
            "availableUserDomains": [],
        }
    )


@routes.post("/xrpc/com.atproto.server.createSession")
async def server_create_session(request: web.Request):
    try:
        req_json: dict = await request.json()
    except json.JSONDecodeError:
        raise web.HTTPBadRequest(text="expected JSON")

    identifier = req_json.get("identifier")
    password = req_json.get("password")
    if not (isinstance(identifier, str) and isinstance(password, str)):
        raise web.HTTPBadRequest(text="invalid identifier or password")

    db = get_db(request)
    try:
        did, handle = db.verify_account_login(
            did_or_handle=identifier, password=password
        )
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
    return web.json_response(
        {
            "token": jwt.encode(
                {
                    "iss": request["authed_did"],
                    "aud": aud,
                    "lxm": lxm,
                    "exp": int(time.time()) + 60,
                },
                signing_key,
                algorithm=crypto.jwt_signature_alg_for_pem(signing_key),
            )
        }
    )


@routes.post("/xrpc/com.atproto.identity.updateHandle")
@authenticated
async def identity_update_handle(request: web.Request):
    req_json: dict = await request.json()
    handle = req_json.get("handle")
    if handle is None:
        raise web.HTTPBadRequest(text="missing or invalid handle")

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

    app.add_routes(
        [
            web.get("/xrpc/app.bsky.{_:.*}", service_proxy),
            web.post("/xrpc/app.bsky.{_:.*}", service_proxy),
        ]
    )

    return app


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
        logger.info(f"listening on http://{host}:{port}")
        site = web.TCPSite(runner, host=host, port=port)
    else:
        logger.info(f"listening on {sock_path}")
        site = web.UnixSite(runner, path=sock_path)

    await site.start()

    if sock_path:
        try:
            sock_gid = grp.getgrnam(static_config.GROUPNAME).gr_gid
            os.chown(sock_path, os.geteuid(), sock_gid)
        except (KeyError, PermissionError):
            logger.warning(
                f"Failed to set socket group - group {static_config.GROUPNAME!r} not found."
                " or not a member of the group?"
            )
        os.chmod(sock_path, 0o770)

    while True:
        await asyncio.sleep(3600)