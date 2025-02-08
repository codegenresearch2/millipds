import logging
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
        if not db.config.get('jwt_access_secret') or not db.config.get('pds_did'):
            raise web.HTTPUnauthorized(text='Configuration incomplete. Missing JWT access secret or PDS DID.')

        try:
            # Decode the token based on the algorithm
            decoded_token = jwt.decode(token, db.config['jwt_access_secret'], algorithms=['HS256', 'HS384', 'HS512'], audience=db.config['pds_did'], options={'require': ['exp', 'iat', 'scope'], 'verify_exp': True, 'verify_iat': True, 'strict_aud': True})
        except jwt.InvalidTokenError:
            raise web.HTTPUnauthorized(text='Invalid JWT token')

        # Check if the token scope allows access
        if decoded_token.get('scope') != 'com.atproto.access':
            raise web.HTTPUnauthorized(text='Invalid JWT scope')

        # Set the authenticated DID in the request
        subject = decoded_token.get('sub', '')
        if not subject.startswith('did:'):
            raise web.HTTPUnauthorized(text='Invalid JWT: invalid subject')
        request['authed_did'] = subject
        return await handler(request, *args, **kwargs)

    return authentication_handler