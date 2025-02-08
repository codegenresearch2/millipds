import logging
import time
import jwt
from aiohttp import web

from .app_util import *

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()


def authenticated(handler):
    """
    Middleware function to authenticate requests based on JWT tokens.
    This function handles both symmetric and asymmetric token authentication.
    """
    async def authentication_handler(request: web.Request, *args, **kwargs):
        # Extract the auth token
        auth = request.headers.get('Authorization')
        if auth is None:
            raise web.HTTPUnauthorized(text='authentication required (this may be a bug, I'm erring on the side of caution for now)')
        if not auth.startswith('Bearer '):
            raise web.HTTPUnauthorized(text='invalid auth type')
        token = auth.removeprefix('Bearer ')

        # Validate the JWT token
        db = get_db(request)
        try:
            # Decode the token without verification to inspect the header
            decoded_token = jwt.api_jwt.decode_complete(token, options={'verify_signature': False})
            algorithm = decoded_token.get('alg', 'HS256')

            # Verify the token based on the algorithm
            if algorithm in ['HS256', 'HS384', 'HS512']:
                payload = jwt.decode(
                    token,
                    key=db.config['jwt_access_secret'],
                    algorithms=[algorithm],
                    audience=db.config['pds_did'],
                    options={
                        'require': ['exp', 'iat', 'scope'],
                        'verify_exp': True,
                        'verify_iat': True,
                        'strict_aud': True,
                    },
                )
            else:
                # For asymmetric algorithms, we need to verify the key
                jwk = await crypto.get_jwk_from_issuer(decoded_token['iss'])
                payload = jwt.decode(
                    token,
                    key=jwk,
                    algorithms=[algorithm],
                    audience=db.config['pds_did'],
                    options={
                        'require': ['exp', 'iat', 'scope'],
                        'verify_exp': True,
                        'verify_iat': True,
                        'strict_aud': True,
                    },
                )

        except jwt.exceptions.PyJWTError as e:
            raise web.HTTPUnauthorized(text=str(e))

        # Check if the token scope allows access
        if payload.get('scope') != 'com.atproto.access':
            raise web.HTTPUnauthorized(text='invalid jwt scope')

        # Set the authenticated DID in the request
        subject = payload.get('sub', '')
        if not subject.startswith('did:'):
            raise web.HTTPUnauthorized(text='invalid jwt: invalid subject')
        request['authed_did'] = subject
        return await handler(request, *args, **kwargs)

    return authentication_handler