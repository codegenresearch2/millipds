from typing import Set, Tuple
import logging
import uuid
import time

import jwt
from aiohttp import web

from .app_util import *
from . import util
from . import crypto

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()


def symmetric_token_auth(
	request: web.Request, authtype: str, token: str
) -> Tuple[str, Set[str]]:  # (subject, scopes)
	db = get_db(request)
	try:
		payload: dict = jwt.decode(
			jwt=token,
			key=db.config["jwt_access_secret"],
			algorithms=["HS256"],
			audience=db.config["pds_did"],
			options={
				"require": ["exp", "iat", "scope", "jti", "sub"],
				"verify_exp": True,
				"verify_iat": True,
				"strict_aud": True,  # may be unnecessary
			},
		)
	except jwt.exceptions.ExpiredSignatureError:
		# https://github.com/bluesky-social/atproto/discussions/3319
		# we need to signal this error in this specific format so the reference
		# client implementation will know what to do
		raise util.atproto_json_http_error(
			web.HTTPBadRequest, "ExpiredToken", "bad exp"
		)
	except jwt.exceptions.PyJWTError:
		raise web.HTTPUnauthorized(text="invalid jwt")

	revoked = db.con.execute(
		"SELECT COUNT(*) FROM revoked_token WHERE did=? AND jti=?",
		(payload["sub"], payload["jti"]),
	).fetchone()[0]

	if revoked:
		raise web.HTTPUnauthorized(text="revoked token")

	# if we reached this far, the payload must've been signed by us
	if not payload.get("scope"):
		raise web.HTTPUnauthorized(text="invalid jwt scope")

	if not payload.get("sub", "").startswith("did:"):
		raise web.HTTPUnauthorized(text="invalid jwt: invalid subject")

	# the tokens we issue via oauth will always have this field
	if jkt := payload.get("cnf", {}).get("jkt"):
		if authtype != "dpop":
			raise web.HTTPUnauthorized(text="dpop is required for this token")

		if jkt != request.get("verified_dpop_jkt"):
			raise web.HTTPUnauthorized(text="dpop binding failed")
	else:
		if authtype != "bearer":
			raise web.HTTPUnauthorized(text="unexpected auth token type")

	request["authed_did"] = payload["sub"]
	request["authed_scopes"] = set(payload["scope"].split(" "))

	# this info might be needed to revoke the token
	request["token_payload"] = payload


def auth_required(required_scopes: Set[str] = set(), revoke: bool = False):
	def decorator(handler):
		async def wrapper(request: web.Request, *args, **kwargs):
			if not request.get("authed_did"):
				raise web.HTTPUnauthorized(text=f"auth required")

			authed_scopes = request.get("authed_scopes", set())
			missing_scopes = required_scopes - authed_scopes
			if missing_scopes:
				raise web.HTTPUnauthorized(
					text=f"Required authorization scopes {required_scopes}, but you only have {authed_scopes} (missing {missing_scopes})"
				)

			if revoke:
				get_db(request).con.execute(
					"INSERT INTO revoked_token (did, jti, expires_at) VALUES (?, ?, ?)",
					(
						request["authed_did"],
						request["token_payload"]["jti"],
						request["token_payload"]["exp"],
					),
				)

			return await handler(request, *args, **kwargs)

		return wrapper

	return decorator


@web.middleware
async def auth_middleware(request: web.Request, handler):
	"""
	There are three types of auth:
	 - bearer token signed by symmetric secret (generated by us during the password login flow)
	 - "service" bearer token signed by (asymmetric) repo signing key, scoped to a specific lxm
	 - whatever I do for oauth (TODO)
	"""

	auth = request.headers.get("Authorization")
	if auth is None:
		# if there's no auth header, continue normally.
		# authenticated endpoints will detect the lack of request["authed_scopes"]/request["authed_did"]
		return await handler(request)

	authtype, _, token = auth.partition(" ")
	authtype = authtype.lower()
	if authtype not in ["bearer", "dpop"]:
		raise web.HTTPUnauthorized(text="invalid auth type")

	# validate it TODO: this needs rigorous testing, I'm not 100% sure I'm
	# verifying all the things that need verifying
	db = get_db(request)

	unverified = jwt.api_jwt.decode_complete(
		token, options={"verify_signature": False}
	)

	if unverified["header"]["alg"] == "HS256":  # symmetric secret
		symmetric_token_auth(request, authtype, token)
	else:  # asymmetric service auth (scoped to a specific lxm)
		did: str = unverified["payload"]["iss"]
		if not did.startswith("did:"):
			raise web.HTTPUnauthorized(text="invalid jwt: invalid issuer")
		signing_key_pem = db.signing_key_pem_by_did(did)
		if signing_key_pem is None:
			raise web.HTTPUnauthorized(text="invalid jwt: unknown issuer")
		alg = crypto.jwt_signature_alg_for_pem(signing_key_pem)
		verifying_key = crypto.privkey_from_pem(signing_key_pem).public_key()
		try:
			payload = jwt.decode(
				jwt=token,
				key=verifying_key,
				algorithms=[alg],
				audience=db.config["pds_did"],
				options={
					"require": ["exp", "iat", "lxm", "jti", "iss"],
					"verify_exp": True,
					"verify_iat": True,
					"strict_aud": True,  # may be unnecessary
				},
			)
		except jwt.exceptions.PyJWTError:
			raise web.HTTPUnauthorized(text="invalid jwt")

		revoked = db.con.execute(
			"SELECT COUNT(*) FROM revoked_token WHERE did=? AND jti=?",
			(payload["iss"], payload["jti"]),
		).fetchone()[0]

		if revoked:
			raise web.HTTPUnauthorized(text="revoked token")

		# note: request.path does not include the query string
		request_lxm = request.path.rpartition("/")[2]
		if request_lxm != payload.get("lxm"):
			raise web.HTTPUnauthorized(text="invalid jwt: bad lxm")

		# everything checks out
		request["authed_did"] = did
		request["authed_scopes"] = set(
			payload.get("scope", "atproto").split(" ")
		)

	return await handler(request)


# used for both service proxying, and getServiceAuth
def build_service_auth_token(
	request: web.Request, aud: str, lxm: str, duration: int
) -> str:
	if lxm.startswith("chat.bsky."):
		if "transition:chat.bsky" not in request["authed_scopes"]:
			raise web.HTTPUnauthorized(
				text=f"`transition:chat.bsky` scope required for lxm {lxm}"
			)

	now = int(time.time())
	signing_key = get_db(request).signing_key_pem_by_did(request["authed_did"])
	assert signing_key is not None
	return jwt.encode(
		{
			"iss": request["authed_did"],
			"aud": aud,
			"lxm": lxm,
			"exp": now + duration,
			"iat": now,
			"jti": str(uuid.uuid4()),
			"scope": " ".join(request.get("authed_scopes", {})),
		},
		signing_key,
		algorithm=crypto.jwt_signature_alg_for_pem(signing_key),
	)
