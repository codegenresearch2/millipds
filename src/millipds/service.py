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
    # https://atproto.com/specs/xrpc#service-proxying
    atproto_proxy = request.headers.get("atproto-proxy")
    if atproto_proxy:
        return await service_proxy(request, atproto_proxy)

    # else, normal response
    res: web.Response = await handler(request)

    # inject security headers (this should really be a separate middleware, but here works too)
    res.headers.setdefault("X-Frame-Options", "DENY")  # prevent clickjacking
    res.headers.setdefault(
        "X-Content-Type-Options", "nosniff"
    )  # prevent XSS (almost vestigial at this point, I think)
    res.headers.setdefault(
        "Content-Security-Policy", "default-src 'none'; sandbox"
    )  # prevent everything
    # NB: HSTS and other TLS-related headers not set, set them in nginx or wherever you terminate TLS

    return res


@routes.get("/")
async def hello(request: web.Request):
    version = importlib.metadata.version("millipds")
    msg = f"""\n                          ,dPYb, ,dPYb,                           8I\n                          IP'`Yb IP'`Yb                           8I\n                     gg   I8  8I I8  8I  gg                       8I\n                     ""   I8  8' I8  8'  ""                       8I\n  ,ggg,,ggg,,ggg,    gg   I8 dP  I8 dP   gg   gg,gggg,      ,gggg,8I     ,gg,\n ,8" "8P" "8P" "8,   88   I8dP   I8dP    88   I8P"  "Yb    dP"  "Y8I   ,8'8,\n I8   8I   8I   8I   88   I8P    I8P     88   I8'    ,8i  i8'    ,8I  ,8'  Yb\n,dP   8I   8I   Yb,_,88,_,d8b,_ ,d8b,_ _,88,_,I8 _  ,d8' ,d8,   ,d8b,,8'_   8)\n8P'   8I   8I   `Y88P""Y88P'"Y888P'"Y888P""Y8PI8 YY88888PP"Y8888P"`Y8P' "YY8P8P\n                                              I8\n                                              I8\n                                              I8\n                                              I8\n                                              I8\n                                              I8\n\n\nHello! This is an ATProto PDS instance, running millipds v{version}\n\nhttps://github.com/DavidBuchanan314/millipds\n"""

    return web.Response(text=msg)


@routes.get(
    "/.well-known/did.json"
)  # serve this server's did:web document (nb: reference PDS impl doesn't do this, hard to know the right thing to do)
async def well_known_did_web(request: web.Request):
    cfg = get_db(request).config
    return web.json_response(
        {
            "@context": [
                "https://www.w3.org/ns/did/v1",
            ],
            "id": cfg["pds_did"],
            "service": [
                {  # is this the right thing to do?
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


# browsers love to request this unprompted, so here's an answer for them\n@routes.get("/favicon.ico")\nasync def health(request: web.Request):\n    return web.Response(\n        text="""\n            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">\n                <text x="50%" y="0.95em" font-size="90" text-anchor="middle">🌐</text>\n            </svg>\n        """,\n        content_type="image/svg+xml",\n        headers={"Cache-Control": "max-age=864000"},\n    )\n\n\n# not a spec'd endpoint, but the reference impl has this too
@routes.get("/xrpc/_health")
async def health(request: web.Request):
    version = importlib.metadata.version("millipds")
    return web.json_response({"version": f"millipds v{version}"})


@routes.post("/xrpc/app.bsky.actor.putPreferences")
@authenticated
async def actor_put_preferences(request: web.Request):
    # NOTE: we don't try to pull out the specific "preferences" field\n    prefs = await request.json()\n    pref_bytes = json.dumps(\n        prefs,\n        ensure_ascii=False,  # more compact\n        separators=(",", ":"),  # likewise\n        check_circular=False,  # impossible, checking would be a waste\n    ).encode()\n    db = get_db(request)\n    db.con.execute(\n        "UPDATE user SET prefs=? WHERE did=?",\n        (pref_bytes, request["authed_did"]),\n    )\n    return web.Response()\n\n\n@routes.get("/xrpc/app.bsky.actor.getPreferences")\n@authenticated\nasync def actor_get_preferences(request: web.Request):\n    db = get_db(request)\n    row = db.con.execute(\n        "SELECT prefs FROM user WHERE did=?", (request["authed_did"],)\n    ).fetchone()\n\n    # should be impossible, otherwise we wouldn't be auth'd\n    assert row is not None\n\n    prefs = json.loads(row[0])\n\n    # TODO: in the future™ this will be unnecessary because we initialize it\n    # properly during account creation and/or I wrote a db migration script\n    if not prefs:\n        prefs = {"preferences": []}\n\n    return web.json_response(prefs)\n\n\n@routes.get("/xrpc/com.atproto.identity.resolveHandle")\nasync def identity_resolve_handle(request: web.Request):\n    handle = request.query.get("handle")\n    if handle is None:\n        raise web.HTTPBadRequest(text="missing or invalid handle")\n\n    did = get_db(request).did_by_handle(handle)\n    if not did:\n        # forward to appview (TODO: resolve it ourself?)\n        return await service_proxy(request)\n\n    # TODO: set cache control response headers?\n    return web.json_response({"did": did})\n\n\n@routes.get("/xrpc/com.atproto.server.describeServer")\nasync def server_describe_server(request: web.Request):\n    return web.json_response(\n        {\n            "did": get_db(request).config["pds_did"],\n            "availableUserDomains": [],\n        }\n    )\n\n\n@routes.post("/xrpc/com.atproto.server.createSession")\nasync def server_create_session(request: web.Request):\n    try:\n        req_json: dict = await request.json()\n    except json.JSONDecodeError:\n        raise web.HTTPBadRequest(text="expected JSON")\n\n    identifier = req_json.get("identifier")\n    password = req_json.get("password")\n    if not (isinstance(identifier, str) and isinstance(password, str)):\n        raise web.HTTPBadRequest(text="invalid identifier or password")\n\n    db = get_db(request)\n    try:\n        did, handle = db.verify_account_login(\n            did_or_handle=identifier, password=password\n        )\n    except KeyError:\n        raise web.HTTPUnauthorized(text="user not found")\n    except ValueError:\n        raise web.HTTPUnauthorized(text="incorrect identifier or password")\n\n    unix_seconds_now = int(time.time())\n    access_jwt = jwt.encode(\n        {\n            "scope": "com.atproto.access",\n            "aud": db.config["pds_did"],\n            "sub": did,\n            "iat": unix_seconds_now,\n            "exp": unix_seconds_now + 60 * 60 * 24,  # 24h\n        },\n        db.config["jwt_access_secret"],\n        "HS256",\n    )\n\n    refresh_jwt = jwt.encode(\n        {\n            "scope": "com.atproto.refresh",\n            "aud": db.config["pds_did"],\n            "sub": did,\n            "iat": unix_seconds_now,\n            "exp": unix_seconds_now + 60 * 60 * 24 * 90,  # 90 days!\n        },\n        db.config["jwt_access_secret"],\n        "HS256",\n    )\n\n    return web.json_response(\n        {\n            "did": did,\n            "handle": handle,\n            "accessJwt": access_jwt,\n            "refreshJwt": refresh_jwt,\n        }\n    )\n\n\n@routes.get("/xrpc/com.atproto.server.getServiceAuth")\n@authenticated\nasync def server_get_service_auth(request: web.Request):\n    aud = request.query.get("aud")\n    lxm = request.query.get("lxm")\n    if not (aud and lxm):\n        raise web.HTTPBadRequest(text="missing aud or lxm")\n    db = get_db(request)\n    signing_key = db.signing_key_pem_by_did(request["authed_did"])\n    return web.json_response(\n        {\n            "token": jwt.encode(\n                {\n                    "iss": request["authed_did"],\n                    "aud": aud,\n                    "lxm": lxm,\n                    "exp": int(time.time()) + 60,  # 60s\n                },\n                signing_key,\n                algorithm=crypto.jwt_signature_alg_for_pem(signing_key),\n            )\n        }\n    )\n\n\n@routes.post("/xrpc/com.atproto.identity.updateHandle")\n@authenticated\nasync def identity_update_handle(request: web.Request):\n    req_json: dict = await request.json()\n    handle = req_json.get("handle")\n    if handle is None:\n        raise web.HTTPBadRequest(text="missing or invalid handle")\n    db = get_db(request)\n    with db.new_con() as con:\n        firehose_seq = con.execute(\n            "SELECT IFNULL(MAX(seq), 0) + 1 FROM firehose"\n        ).fetchone()[0]\n        firehose_bytes = cbrrr.encode_dag_cbor(\n            {"t": "#identity", "op": 1}\n        ) + cbrrr.encode_dag_cbor(\n            {\n                "seq": firehose_seq,\n                "did": request["authed_did"],\n                "time": util.iso_string_now(),\n                "handle": handle,\n            }\n        )\n        con.execute(\n            "INSERT INTO firehose (seq, timestamp, msg) VALUES (?, ?, ?)",\n            (\n                firehose_seq,\n                0,\n                firehose_bytes,\n            ),\n        )\n    await atproto_repo.firehose_broadcast(\n        request, (firehose_seq, firehose_bytes)\n    )\n\n    firehose_seq = con.execute(\n        "SELECT IFNULL(MAX(seq), 0) + 1 FROM firehose"\n    ).fetchone()[0]\n    firehose_bytes = cbrrr.encode_dag_cbor(\n        {"t": "#account", "op": 1}\n    ) + cbrrr.encode_dag_cbor(\n        {\n            "seq": firehose_seq,\n            "did": request["authed_did"],\n            "time": util.iso_string_now(),\n            "active": True,\n        }\n    )\n    con.execute(\n        "INSERT INTO firehose (seq, timestamp, msg) VALUES (?, ?, ?)",\n        (\n            firehose_seq,\n            0,\n            firehose_bytes,\n        ),\n    )\n    await atproto_repo.firehose_broadcast(\n        request, (firehose_seq, firehose_bytes)\n    )\n\n    return web.Response()\n\n\n@routes.get("/xrpc/com.atproto.server.getSession")\n@authenticated\nasync def server_get_session(request: web.Request):\n    return web.json_response(\n        {\n            "handle": get_db(request).handle_by_did(request["authed_did"]),\n            "did": request["authed_did"],\n            "email": "tfw_no@email.invalid",\n            "emailConfirmed": True,\n        }\n    )\n\n\ndef construct_app(\n    routes, db: database.Database, client: aiohttp.ClientSession\n) -> web.Application:\n    cors = cors_middleware(\n        allow_all=True,\n        expose_headers=["*"],\n        allow_headers=["*"],\n        allow_methods=["*"],\n        allow_credentials=True,\n        max_age=100_000_000,\n    )\n\n    client.headers.update(\n        {"User-Agent": importlib.metadata.version("millipds")}\n    )\n\n    app = web.Application(middlewares=[cors, atproto_service_proxy_middleware])\n    app[MILLIPDS_DB] = db\n    app[MILLIPDS_AIOHTTP_CLIENT] = client\n    app[MILLIPDS_FIREHOSE_QUEUES] = set()\n    app[MILLIPDS_FIREHOSE_QUEUES_LOCK] = asyncio.Lock()\n    app.add_routes(routes)\n    app.add_routes(auth_oauth.routes)\n    app.add_routes(atproto_sync.routes)\n    app.add_routes(atproto_repo.routes)\n\n    app.add_routes(\n        [\n            web.get("/xrpc/app.bsky.{_:.*}", service_proxy),\n            web.post("/xrpc/app.bsky.{_:.*}", service_proxy),\n        ]\n    )\n\n    return app\n\n\nasync def run(\n    db: database.Database,\n    client: aiohttp.ClientSession,\n    sock_path: Optional[str],\n    host: str,\n    port: int,\n):\n    app = construct_app(routes, db, client)\n    runner = web.AppRunner(app, access_log_format=static_config.HTTP_LOG_FMT)\n    await runner.setup()\n\n    if sock_path is None:\n        logger.info(f"listening on http://{host}:{port}")\n        site = web.TCPSite(runner, host=host, port=port)\n    else:\n        logger.info(f"listening on {sock_path}")\n        site = web.UnixSite(runner, path=sock_path)\n\n    await site.start()\n\n    if sock_path:\n        import grp\n\n        try:\n            sock_gid = grp.getgrnam(static_config.GROUPNAME).gr_gid\n            os.chown(sock_path, os.geteuid(), sock_gid)\n        except KeyError:\n            logger.warning(\n                f"Failed to set socket group - group {static_config.GROUPNAME!r} not found."\n            )\n        except PermissionError:\n            logger.warning(\n                f"Failed to set socket group - are you a member of the {static_config.GROUPNAME!r} group?"\n            )\n\n        os.chmod(sock_path, 0o770)\n\n    while True:\n        await asyncio.sleep(3600)