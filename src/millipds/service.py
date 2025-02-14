import importlib.metadata
import logging
import asyncio
import time

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
        return await service_proxy(request, atproto_proxy)
    res: web.Response = await handler(request)
    res.headers.setdefault("X-Frame-Options", "DENY")
    res.headers.setdefault("X-Content-Type-Options", "nosniff")
    res.headers.setdefault("Content-Security-Policy", "default-src 'none'; sandbox")
    return res

@routes.get("/")
async def hello(request: web.Request):
    version = importlib.metadata.version("millipds")
    msg = f"Hello! This is an ATProto PDS instance, running millipds v{version}\n\nhttps://github.com/DavidBuchanan314/millipds"
    return web.Response(text=msg)

@routes.get("/.well-known/did.json")
async def well_known_did_web(request: web.Request):
    did = await get_did_resolver(request).resolve_did(get_db(request).config["pds_did"])
    return web.json_response(did)

@routes.get("/robots.txt")
async def robots_txt(request: web.Request):
    return web.Response(text="User-Agent: *\nAllow: /")

@routes.get("/favicon.ico")
async def favicon(request: web.Request):
    return web.Response(text="<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text x='50%' y='0.95em' font-size='90' text-anchor='middle'>🌐</text></svg>", content_type="image/svg+xml", headers={"Cache-Control": "max-age=864000"})

@routes.get("/xrpc/_health")
async def health(request: web.Request):
    version = importlib.metadata.version("millipds")
    return web.json_response({"version": f"millipds v{version}"})

@routes.post("/xrpc/app.bsky.actor.putPreferences")
@authenticated
async def actor_put_preferences(request: web.Request):
    prefs = await request.json()
    pref_bytes = util.compact_json(prefs)
    get_db(request).update_preferences(request["authed_did"], pref_bytes)
    return web.Response()

@routes.get("/xrpc/app.bsky.actor.getPreferences")
@authenticated
async def actor_get_preferences(request: web.Request):
    prefs = get_db(request).get_preferences(request["authed_did"])
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
    return web.json_response({"did": get_db(request).config["pds_did"], "availableUserDomains": []})

@routes.post("/xrpc/com.atproto.server.createSession")
async def server_create_session(request: web.Request):
    req_json: dict = await request.json()
    identifier = req_json.get("identifier")
    password = req_json.get("password")
    if not (isinstance(identifier, str) and isinstance(password, str)):
        raise web.HTTPBadRequest(text="invalid identifier or password")
    did, handle = get_db(request).verify_account_login(identifier, password)
    access_jwt, refresh_jwt = get_db(request).generate_jwt_tokens(did)
    return web.json_response({"did": did, "handle": handle, "accessJwt": access_jwt, "refreshJwt": refresh_jwt})

@routes.get("/xrpc/com.atproto.server.getServiceAuth")
@authenticated
async def server_get_service_auth(request: web.Request):
    aud = request.query.get("aud")
    lxm = request.query.get("lxm")
    now = int(time.time())
    exp = int(request.query.get("exp", now + 60))
    if not (aud and lxm):
        raise web.HTTPBadRequest(text="missing aud or lxm")
    if lxm == "com.atproto.server.getServiceAuth":
        raise web.HTTPBadRequest(text="can't generate auth tokens recursively!")
    max_exp = now + 60 * 30
    if exp > max_exp:
        logger.info(f"requested exp too far into the future, truncating to {max_exp}")
        exp = max_exp
    signing_key = get_db(request).signing_key_pem_by_did(request["authed_did"])
    return web.json_response({"token": jwt.encode({"iss": request["authed_did"], "aud": aud, "lxm": lxm, "exp": exp}, signing_key, algorithm=crypto.jwt_signature_alg_for_pem(signing_key))})

@routes.post("/xrpc/com.atproto.identity.updateHandle")
@authenticated
async def identity_update_handle(request: web.Request):
    req_json: dict = await request.json()
    handle = req_json.get("handle")
    if handle is None:
        raise web.HTTPBadRequest(text="missing or invalid handle")
    firehose_seq, firehose_bytes = get_db(request).update_handle(request["authed_did"], handle)
    await atproto_repo.firehose_broadcast(request, (firehose_seq, firehose_bytes))
    return web.Response()

@routes.get("/xrpc/com.atproto.server.getSession")
@authenticated
async def server_get_session(request: web.Request):
    handle = get_db(request).handle_by_did(request["authed_did"])
    return web.json_response({"handle": handle, "did": request["authed_did"], "email": "tfw_no@email.invalid", "emailConfirmed": True})

def construct_app(routes, db: database.Database, client: aiohttp.ClientSession, did_resolver: DIDResolver) -> web.Application:
    cors = cors_middleware(allow_all=True, expose_headers=["*"], allow_headers=["*"], allow_methods=["*"], allow_credentials=True, max_age=100_000_000)
    client.headers.update({"User-Agent": importlib.metadata.version("millipds")})
    app = web.Application(middlewares=[cors, atproto_service_proxy_middleware])
    app[MILLIPDS_DB] = db
    app[MILLIPDS_AIOHTTP_CLIENT] = client
    app[MILLIPDS_FIREHOSE_QUEUES] = set()
    app[MILLIPDS_FIREHOSE_QUEUES_LOCK] = asyncio.Lock()
    app[MILLIPDS_DID_RESOLVER] = did_resolver
    app.add_routes(routes)
    app.add_routes(auth_oauth.routes)
    app.add_routes(atproto_sync.routes)
    app.add_routes(atproto_repo.routes)
    app.add_routes([web.get("/xrpc/app.bsky.{_:.*}", service_proxy), web.post("/xrpc/app.bsky.{_:.*}", service_proxy)])
    return app

async def run(db: database.Database, client: aiohttp.ClientSession, sock_path: Optional[str], host: str, port: int):
    did_resolver = DIDResolver(client)
    app = construct_app(routes, db, client, did_resolver)
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
        import grp
        try:
            sock_gid = grp.getgrnam(static_config.GROUPNAME).gr_gid
            os.chown(sock_path, os.geteuid(), sock_gid)
        except KeyError:
            logger.warning(f"Failed to set socket group - group {static_config.GROUPNAME!r} not found.")
        except PermissionError:
            logger.warning(f"Failed to set socket group - are you a member of the {static_config.GROUPNAME!r} group?")
        os.chmod(sock_path, 0o770)
    while True:
        await asyncio.sleep(3600)

This rewritten code follows the rules provided. Dynamic DID resolution is achieved by introducing a DIDResolver class that can be used to resolve DIDs. Logging has been improved for better debugging and tracking. The code has been modularized for better maintainability.