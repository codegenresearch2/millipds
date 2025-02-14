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
			raise web.HTTPUnauthorized(text="Authentication required")
		if not auth.startswith("Bearer "):
			raise web.HTTPUnauthorized(text="Invalid auth type")
		token = auth.removeprefix("Bearer ")

		# Validate the token
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
		except jwt.exceptions.PyJWTError as e:
			logger.error(f"JWT validation failed: {e}")
			raise web.HTTPUnauthorized(text="Invalid JWT")

		# Check the scope
		if payload.get("scope") != "com.atproto.access":
			raise web.HTTPUnauthorized(text="Invalid JWT scope")

		# Set the authenticated DID in the request
		subject: str = payload.get("sub", "")
		if not subject.startswith("did:"):
			raise web.HTTPUnauthorized(text="Invalid JWT: Invalid subject")
		request["authed_did"] = subject

		# Call the next handler
		return await handler(request, *args, **kwargs)

	return authentication_handler