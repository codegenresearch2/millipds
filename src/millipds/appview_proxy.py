from typing import Optional
import logging
import time
import jwt
from aiohttp import web

from . import crypto
from .auth_bearer import authenticated
from .app_util import *

logger = logging.getLogger(__name__)

# Service Routes
SERVICE_ROUTES = {
    'did:web:api.bsky.chat#bsky_chat': 'https://api.bsky.chat',
    'did:web:discover.bsky.app#bsky_fg': 'https://discover.bsky.app',
    'did:plc:ar7c4by46qjdydhdevvrndac#atproto_labeler': 'https://mod.bsky.app',
}

@authenticated
async def service_proxy(request: web.Request, service: Optional[str] = None):
    '''
    Proxy requests to the specified service or default service based on the request.
    '''
    lxm = request.path.rpartition('/')[2].partition('?')[0]
    db = get_db(request)
    did_resolver = DIDResolver(get_client(request))

    if service:
        service_did = service.partition('#')[0]
        resolved_service = await did_resolver.resolve(service_did)
        if resolved_service is None:
            return web.HTTPInternalServerError(text='Unable to resolve service DID')
        service_route = SERVICE_ROUTES.get(service) or resolved_service
    else:
        service_did = db.config['bsky_appview_did']
        service_route = db.config['bsky_appview_pfx']

    signing_key = db.signing_key_pem_by_did(request['authed_did'])
    auth_headers = {
        'Authorization': 'Bearer ' +
        jwt.encode(
            {
                'iss': request['authed_did'],
                'aud': service_did,
                'lxm': lxm,
                'exp': int(time.time()) + 5 * 60,
            },
            signing_key,
            algorithm=crypto.jwt_signature_alg_for_pem(signing_key),
        )
    }

    async with get_client(request).get(
        service_route + request.path,
        params=request.query,
        headers=auth_headers,
    ) as r:
        body_bytes = await r.read()
        logger.info(f'Proxied lxm: {lxm}')  # Simplified logging
        return web.Response(
            body=body_bytes,
            content_type=r.content_type,
            status=r.status,
        )
    
    # TODO: Implement handling for POST and PUT requests
    # Add similar placeholders for methods that are not yet implemented
    # Consider adding error handling for different HTTP methods
    # Ensure to follow the gold code's consistent formatting and structure