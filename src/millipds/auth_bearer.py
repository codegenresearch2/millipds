import jwt\nimport logging\nfrom aiohttp import web\nfrom .app_util import *\nfrom .crypto import validate_token\n\nlogger = logging.getLogger(__name__)\"\n\nroutes = web.RouteTableDef()\n\nclass TokenExpired(Exception):\n    pass\n\nclass InvalidToken(Exception):\n    pass\n\nclass InsufficientScope(Exception):\n    pass\n\n\ndef authenticated(handler):\n    async def authentication_handler(request: web.Request):\n        auth = request.headers.get('Authorization')\n        if not auth:\n            raise web.HTTPUnauthorized(text='Authentication required')\n        if not auth.startswith('Bearer '):\n            raise web.HTTPUnauthorized(text='Invalid auth type')\n        token = auth.removeprefix('Bearer ')\n\n        try:\n            payload = validate_token(token)\n        except jwt.ExpiredSignatureError:\n            raise TokenExpired('Token has expired')\n        except jwt.InvalidTokenError:\n            raise InvalidToken('Invalid token')\n        except Exception as e:\n            raise web.HTTPUnauthorized(text=str(e))\n\n        if payload.get('scope') != 'com.atproto.access':\n            raise InsufficientScope('Insufficient scope')\n\n        request['authed_did'] = payload.get('sub')\n        return await handler(request)\n    return authentication_handler\n\n@routes.get('/.well-known/oauth-protected-resource')\nasync def oauth_protected_resource(request: web.Request):\n    cfg = get_db(request).config\n    return web.json_response({'resource': cfg['pds_pfx']})\n\n@routes.get('/.well-known/oauth-authorization-server')\nasync def oauth_authorization_server(request: web.Request):\n    cfg = get_db(request).config\n    pfx = cfg['pds_pfx']\n    return web.json_response({'issuer': pfx, 'scopes_supported': ['atproto'], 'subject_types_supported': ['public'], 'response_types_supported': ['code'], 'response_modes_supported': ['query', 'fragment', 'form_post'], 'grant_types_supported': ['authorization_code', 'refresh_token'], 'code_challenge_methods_supported': ['S256'], 'ui_locales_supported': ['en-US'], 'display_values_supported': ['page', 'popup', 'touch'], 'authorization_response_iss_parameter_supported': True, 'request_object_signing_alg_values_supported': ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES256K', 'ES384', 'ES512'], 'request_object_encryption_alg_values_supported': [], 'request_object_encryption_enc_values_supported': [], 'request_parameter_supported': True, 'request_uri_parameter_supported': True, 'require_request_uri_registration': True, 'jwks_uri': pfx + '/oauth/jwks', 'authorization_endpoint': pfx + '/oauth/authorize', 'token_endpoint': pfx + '/oauth/token', 'token_endpoint_auth_methods_supported': ['none', 'private_key_jwt'], 'token_endpoint_auth_signing_alg_values_supported': ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES256K', 'ES384', 'ES512'], 'revocation_endpoint': pfx + '/oauth/revoke', 'introspection_endpoint': pfx + '/oauth/introspect', 'pushed_authorization_request_endpoint': pfx + '/oauth/par', 'require_pushed_authorization_requests': True, 'dpop_signing_alg_values_supported': ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES256K', 'ES384', 'ES512'], 'client_id_metadata_document_supported': True})