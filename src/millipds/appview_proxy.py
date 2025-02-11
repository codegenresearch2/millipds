from typing import Optional
import logging
import time
import json

import jwt
from aiohttp import web

from . import crypto
from .auth_bearer import authenticated
from .app_util import *

logger = logging.getLogger(__name__)

SERVICE_ROUTES = {
	"did:web:api.bsky.chat#bsky_chat": "https://api.bsky.chat",
	"did:web:discover.bsky.app#bsky_fg": "https://discover.bsky.app",
	"did:plc:ar7c4by46qjdydhdevvrndac#atproto_labeler": "https://mod.bsky.app",
}

@routes.post("/xrpc/app.bsky.actor.putPreferences")
@authenticated
async def actor_put_preferences(request: web.Request):
	prefs = await request.json()
	pref_bytes = json.dumps(prefs, ensure_ascii=False, separators=(",", ":")).encode()
	db = get_db(request)
	db.con.execute("UPDATE user SET prefs=? WHERE did=?", (pref_bytes, request["authed_did"]))
	return web.Response()

@routes.get("/xrpc/app.bsky.actor.getPreferences")
@authenticated
async def actor_get_preferences(request: web.Request):
	db = get_db(request)
	row = db.con.execute("SELECT prefs FROM user WHERE did=?", (request["authed_did"],)).fetchone()
	prefs = json.loads(row[0]) if row[0] else {}
	return web.json_response(prefs)

@authenticated
async def service_proxy(request: web.Request, service: Optional[str] = None):
	lxm = request.path.rpartition("/")[2].partition("?")[0]
	logger.info(f"proxying lxm {lxm}")
	db = get_db(request)
	service_did, service_route = (service.partition("#")[0], SERVICE_ROUTES.get(service)) if service else (db.config["bsky_appview_did"], db.config["bsky_appview_pfx"])

	if service_route is None:
		return web.HTTPBadRequest(f"unable to resolve service {service!r}")

	signing_key = db.signing_key_pem_by_did(request["authed_did"])
	authn = {"Authorization": "Bearer " + jwt.encode({"iss": request["authed_did"], "aud": service_did, "lxm": lxm, "exp": int(time.time()) + 5 * 60}, signing_key, algorithm=crypto.jwt_signature_alg_for_pem(signing_key))}

	if request.method == "GET":
		async with get_client(request).get(service_route + request.path, params=request.query, headers=authn) as r:
			body_bytes = await r.read()
			return web.Response(body=body_bytes, content_type=r.content_type, status=r.status)
	elif request.method == "POST":
		request_body = await request.read()
		async with get_client(request).post(service_route + request.path, data=request_body, headers=(authn | {"Content-Type": request.content_type})) as r:
			body_bytes = await r.read()
			return web.Response(body=body_bytes, content_type=r.content_type, status=r.status)
	elif request.method == "PUT":
		raise NotImplementedError("TODO: PUT")
	else:
		raise NotImplementedError("TODO")