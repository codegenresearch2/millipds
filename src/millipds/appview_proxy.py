from typing import Optional
import logging
import time

import jwt
from aiohttp import web

from . import crypto
from .auth_bearer import authenticated
from .app_util import *
from .did import DIDResolver

logger = logging.getLogger(__name__)

@authenticated
async def service_proxy(request: web.Request, service: Optional[str] = None):
    """
    If `service` is None, default to bsky appview (per details in db config)
    """
    lxm = request.path.rpartition("/")[2].partition("?")[0]
    logger.info(f"proxying lxm {lxm}")
    db = get_db(request)
    did_resolver = get_did_resolver(request)

    if service:
        service_did, _, fragment = service.partition("#")
        did_doc = await did_resolver.resolve_with_db_cache(service_did)
        if did_doc is None:
            raise web.HTTPBadRequest(text=f"unable to resolve service {service!r}")
        service_route = None
        for service_entry in did_doc.get("service", []):
            if service_entry.get("id") == fragment:
                service_route = service_entry.get("serviceEndpoint")
                break
        if service_route is None:
            raise web.HTTPBadRequest(text=f"unable to find service fragment {fragment!r} in DID document")
    else:
        service_did = db.config["bsky_appview_did"]
        service_route = db.config["bsky_appview_pfx"]

    signing_key = db.signing_key_pem_by_did(request["authed_did"])
    auth_headers = {
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
    }
    # TODO: cache this?

    if request.method == "GET":
        async with get_client(request).get(
            service_route + request.path,
            params=request.query,
            headers=auth_headers,
        ) as r:
            # TODO: allowlist safe content types!
            # TODO: streaming?
            body_bytes = await r.read()
            return web.Response(
                body=body_bytes, content_type=r.content_type, status=r.status
            )
    elif request.method == "POST":
        # TODO: streaming?
        request_body = await request.read()
        async with get_client(request).post(
            service_route + request.path,
            data=request_body,
            headers=(auth_headers | {"Content-Type": request.content_type}),
        ) as r:
            # TODO: allowlist safe content types!
            # TODO: streaming?
            body_bytes = await r.read()
            return web.Response(
                body=body_bytes, content_type=r.content_type, status=r.status
            )
    elif request.method == "PUT":
        raise NotImplementedError("TODO: PUT")
    else:
        raise NotImplementedError("TODO")