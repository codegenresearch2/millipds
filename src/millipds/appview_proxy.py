from typing import Optional
import logging
import time

import jwt
from aiohttp import web

from . import crypto
from .auth_bearer import authenticated
from .app_util import *

logger = logging.getLogger(__name__)


# TODO: this should be done via actual DID resolution, not hardcoded!
SERVICE_ROUTES = {
	"did:web:api.bsky.chat#bsky_chat": "https://api.bsky.chat",
	"did:web:discover.bsky.app#bsky_fg": "https://discover.bsky.app",
	"did:plc:ar7c4by46qjdydhdevvrndac#atproto_labeler": "https://mod.bsky.app",
}


@authenticated
async def service_proxy(request: web.Request, service: Optional[str] = None):
	"""
	If `service` is None, default to bsky appview (per details in db config)
	"""
	lxm = request.path.rpartition("/")[2].partition("?")[0]
	# TODO: verify valid lexicon method?
	logger.info(f"proxying lxm {lxm}")
	db = get_db(request)
	if service:
		service_did = service.partition("#")[0]
		service_route = SERVICE_ROUTES.get(service)
		if service_route is None:
			return web.HTTPBadRequest(f"unable to resolve service {service!r}")
	else:
		service_did = db.config["bsky_appview_did"]
		service_route = db.config["bsky_appview_pfx"]

	signing_key = db.signing_key_pem_by_did(request["authed_did"])
	authn = {
		"Authorization": "Bearer "
		+ jwt.encode(
			{
				"iss": request["authed_did"],
				"aud": service_did,
				"lxm": lxm,
				"exp": int(time.time()) + 5 * 60,  # 5 mins
			},
			signing_key,
			algorithm=crypto.jwt_signature_alg_for_pem(signing_key),
		)
	}  # TODO: cache this!
	if request.method == "GET":
		async with get_client(request).get(
			service_route + request.path, params=request.query, headers=authn
		) as r:
			body_bytes = await r.read()  # TODO: streaming?
			return web.Response(
				body=body_bytes, content_type=r.content_type, status=r.status
			)  # XXX: allowlist safe content types!
	elif request.method == "POST":
		request_body = await request.read()  # TODO: streaming?
		async with get_client(request).post(
			service_route + request.path,
			data=request_body,
			headers=(authn | {"Content-Type": request.content_type}),
		) as r:
			body_bytes = await r.read()  # TODO: streaming?
			return web.Response(
				body=body_bytes, content_type=r.content_type, status=r.status
			)  # XXX: allowlist safe content types!
	elif request.method == "PUT":
		raise NotImplementedError("TODO: PUT")
	else:
		raise NotImplementedError("TODO")

# Initialize user preferences during account creation
def initialize_user_preferences(db, did):
    preferences = {"preferences": []}
    prefs_bytes = json.dumps(preferences, ensure_ascii=False, separators=(',', ':')).encode()
    db.con.execute("INSERT INTO user_preferences (did, preferences) VALUES (?, ?)", (did, prefs_bytes))

@routes.post("/xrpc/app.bsky.actor.createAccount")
@authenticated
async def actor_create_account(request: web.Request):
    req_json = await request.json()
    did = req_json.get("did")
    password = req_json.get("password")
    handle = req_json.get("handle")
    
    if not (did and password and handle):
        raise web.HTTPBadRequest(text="missing or invalid parameters")
    
    db = get_db(request)
    try:
        db.create_account(did, handle, password)
        initialize_user_preferences(db, did)
    except Exception as e:
        raise web.HTTPInternalServerError(text=str(e))
    
    return web.Response()

@routes.put("/xrpc/app.bsky.actor.updatePreferences")
@authenticated
async def actor_update_preferences(request: web.Request):
    req_json = await request.json()
    preferences = req_json.get("preferences")
    
    if preferences is None:
        raise web.HTTPBadRequest(text="missing or invalid preferences")
    
    prefs_bytes = json.dumps(preferences, ensure_ascii=False, separators=(',', ':')).encode()
    db = get_db(request)
    db.con.execute("UPDATE user_preferences SET preferences=? WHERE did=?", (prefs_bytes, request["authed_did"]))
    
    return web.Response()

@routes.get("/xrpc/app.bsky.actor.getPreferences")
@authenticated
async def actor_get_preferences(request: web.Request):
    db = get_db(request)
    row = db.con.execute("SELECT preferences FROM user_preferences WHERE did=?", (request["authed_did"],)).fetchone()
    
    if row is None:
        raise web.HTTPNotFound(text="preferences not found")
    
    prefs = json.loads(row[0])
    
    return web.json_response(prefs)