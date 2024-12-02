import logging

import jwt
import cbrrr
import json

from aiohttp import web

from . import database

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

# example: https://shiitake.us-east.host.bsky.network/.well-known/oauth-protected-resource
@routes.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource(request: web.Request):
	cfg = get_db(request).config
	return web.json_response({
		"resource": cfg["pds_pfx"],
		"authorization_servers": [ cfg["pds_pfx"] ], # we are our own auth server
		"scopes_supported": [],
		"bearer_methods_supported": [ "header" ],
		"resource_documentation": "https://atproto.com"
	})


# example: https://bsky.social/.well-known/oauth-authorization-server
@routes.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server(request: web.Request):
	# XXX: most of these values are currently bogus!!! I copy pasted bsky's one
	# TODO: fill in alg_supported lists based on what pyjwt actually supports
	# perhaps via jwt.api_jws.get_default_algorithms().keys(), but we'd want to exclude the symmetric ones
	cfg = get_db(request).config
	pfx = cfg["pds_pfx"]
	return web.json_response({
		"issuer": pfx,
		"scopes_supported": ["atproto", "transition:generic", "transition:chat.bsky"],
		"subject_types_supported": ["public"],
		"response_types_supported": ["code"],
		"response_modes_supported": ["query", "fragment", "form_post"],
		"grant_types_supported": ["authorization_code", "refresh_token"],
		"code_challenge_methods_supported": ["S256"],
		"ui_locales_supported": ["en-US"],
		"display_values_supported": ["page", "popup", "touch"],
		"authorization_response_iss_parameter_supported": True,
		"request_object_signing_alg_values_supported": ["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512","none"],
		"request_object_encryption_alg_values_supported": [],
		"request_object_encryption_enc_values_supported": [],
		"request_parameter_supported": True,
		"request_uri_parameter_supported": True,
		"require_request_uri_registration": True,
		"jwks_uri": pfx + "/oauth/jwks",
		"authorization_endpoint": pfx + "/oauth/authorize",
		"token_endpoint": pfx + "/oauth/token",
		"token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
		"token_endpoint_auth_signing_alg_values_supported": ["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512"],
		"revocation_endpoint": pfx + "/oauth/revoke",
		"introspection_endpoint": pfx + "/oauth/introspect",
		"pushed_authorization_request_endpoint": pfx + "/oauth/par",
		"require_pushed_authorization_requests": True,
		"dpop_signing_alg_values_supported": ["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512"],
		"client_id_metadata_document_supported": True
	})

@routes.get("/oauth/authorize")
async def oauth_authorize(request: web.Request):
	# TODO: extract request_uri
	return web.Response(
		text="""\
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Authorize</title>
		<style>
			/*html, body {
				height: 100%
			}*/
			body {
				background-color: #333;
				color: #fff;
				font-family: system-ui, sans-serif;
				font-size: 16pt;
				margin: 2em 0;
			}

			.panel {
				background-color: #222;
				max-width: 420px;
				margin: auto;
				padding: 1.5em;
			}

			h1 {
				margin: 0;
				border-bottom: 0.1em solid #ff0048;
				line-height: 0.9;
			}

			form {
				margin-top: 1.5em;
			}

			input {
				width: 100%;
				box-sizing: border-box;
				padding: 0.5em 0.6em;
				font-size: 16pt;
				margin-bottom: 1em;
				margin-top: 0.5em;
				background-color: #1a1a1a;
				color: #fff;
				/*border: 0.1px solid #888;*/
				border-style: none;
				/*border-radius: 4px;*/
			}

			input[type="submit"] {
				/*margin-top: 1em;*/
				background-color: #ff0048;
				font-weight: bold;
				box-shadow: 2px 2px #000;
				margin-bottom: 0;
				/*border: 0.1px solid #fff;*/
			}

			input[type="submit"]:hover {
				background-color: #e10042;
			}

			input[type="submit"]:active {
				background-color: #c00038;
			}
		</style>
	</head>
	<body>
		<div class="panel">
			<h1>millipds</h1>
			<h3>put yer creds in the box.</h2>
			<form action="/oauth/login" method="POST">
				<div class="box">
					<label>handle: <input type="text" name="handle" value="todo.invalid" placeholder="bob.example.org"></label>
					<label>password: <input type="password" name="password" placeholder="password"></label>
				</div>
				<input type="submit" value="sign in">
			</form>
		</div>
	</body>
</html>""",
		content_type="text/html",
		headers={
			"Content-Security-Policy": "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'"
		}
	)

DPOP_NONCE = "placeholder_nonce_value" # this needs to get rotated! (does it matter that it's global?)

def dpop_protected(handler):
	async def dpop_handler(request: web.Request):
		dpop = request.headers.get("dpop")
		if dpop is None:
			raise web.HTTPBadRequest(
				text="missing dpop"
			)

		# we're not verifying yet, we just want to pull out the jwk from the header
		unverified = jwt.api_jwt.decode_complete(dpop, options={"verify_signature": False})
		jwk_data = unverified["header"]["jwk"]
		jwk = jwt.PyJWK.from_dict(jwk_data)
		decoded: dict = jwt.decode(dpop, key=jwk) # actual signature verification happens here

		logger.info(decoded)
		logger.info(request.url)

		# TODO: verify iat?, iss?

		if request.method != decoded["htm"]:
			return web.HTTPBadRequest(
				text="dpop: bad htm"
			)

		if str(request.url) != decoded["htu"]:
			logger.info(f"{request.url!r} != {decoded['htu']!r}")
			return web.HTTPBadRequest(
				text="dpop: bad htu (if your application is reverse-proxied, make sure the Host header is getting set properly)"
			)
		
		if decoded.get("nonce") != DPOP_NONCE:
			return web.HTTPBadRequest(
				body=json.dumps({
					"error": "use_dpop_nonce",
					"error_description": "Authorization server requires nonce in DPoP proof"
				}),
				headers={
					"DPoP-Nonce": DPOP_NONCE,
					"Content-Type": "application/json"
				} # if we don't put it here, the client will never see it
			)

		request["dpop_jwk"] = cbrrr.encode_dag_cbor(jwk_data) # for easy comparison in db etc.
		request["dpop_jti"] = decoded["jti"] # XXX: should replay prevention happen here?
		request["dpop_iss"] = decoded["iss"]

		res: web.Response = await handler(request)
		res.headers["DPoP-Nonce"] = DPOP_NONCE # TODO: make sure this always gets set even under error conditions?
		return res

	return dpop_handler


@routes.post("/oauth/par")
@dpop_protected
async def oauth_pushed_authorization_request(request: web.Request):
	data = await request.json() # TODO: doesn't rfc9126 say it's posted as form data?
	logging.info(data)

	assert(data["client_id"] == request["dpop_iss"]) # idk if this is required

	# we need to store the request somewhere, and associate it with the URI we return

	return web.json_response({
		"request_uri": "urn:ietf:params:oauth:request_uri:req-064ed63e9fbf10815fd5f402f4f3e92a", #XXX hardcoded test
		"expires_in": 299
	})


# these helpers are useful for conciseness and type hinting
# XXX: copy-pasted from service.py to avoid circular imports (should maybe put these in their own file)
def get_db(req: web.Request) -> database.Database:
	return req.app["MILLIPDS_DB"]
