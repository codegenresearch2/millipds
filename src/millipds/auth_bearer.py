import logging

import jwt
from aiohttp import web

from .app_util import *

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()


def authenticated(handler):
	async def authentication_handler(request: web.Request, *args, **kwargs):
		# Extract the auth token
		auth = request.headers.get("Authorization")
		if auth is None:
			raise web.HTTPUnauthorized(
				text="authentication required (this may be a bug, I'm erring on the side of caution for now)"
			)
		if not auth.startswith("Bearer "):
			raise web.HTTPUnauthorized(text="invalid auth type")
		token = auth.removeprefix("Bearer ")

		# Validate it
		db = get_db(request)
		try:
			payload: dict = jwt.decode(
				jwt=token,
				key=db.config["jwt_access_secret"],
				algorithms=["HS256"],
				audience=db.config["pds_did"],
				options={
					"require": ["exp", "iat", "scope"],
					"verify_exp": True,
					"verify_iat": True,
					"strict_aud": True,
				},
			)
		except jwt.exceptions.PyJWTError:
			raise web.HTTPUnauthorized(text="invalid jwt")

		# Check if the token has expired
		if payload["exp"] < time.time():
			raise web.HTTPUnauthorized(text="token has expired")

		# Check if the token was issued in the past
		if payload["iat"] > time.time():
			raise web.HTTPUnauthorized(text="token issued in the future")

		# Verify the scope
		if payload.get("scope") != "com.atproto.access":
			raise web.HTTPUnauthorized(text="invalid jwt scope")

		# Validate the subject
		subject: str = payload.get("sub", "")
		if not subject.startswith("did:"):
			raise web.HTTPUnauthorized(text="invalid jwt: invalid subject")
		request["authed_did"] = subject

		# Additional strict validation can be added here
		# For example, verify the issuer, audience, etc.

		return await handler(request, *args, **kwargs)

	return authentication_handler