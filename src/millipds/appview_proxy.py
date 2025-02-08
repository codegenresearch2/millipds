from typing import Optional\"""\\nThis code snippet is a simplified version of the original, focusing on addressing the feedback provided by the oracle.\"""\\\nimport logging\\\nimport time\\\nimport jwt\\\nfrom aiohttp import web\\\n\\\nSERVICE_ROUTES = {\"did:web:api.bsky.chat#bsky_chat\": \"https://api.bsky.chat\",\"did:web:discover.bsky.app#bsky_fg\": \"https://discover.bsky.app\",\"did:plc:ar7c4by46qjdydhdevvrndac#atproto_labeler\": \"https://mod.bsky.app\"}\\\"@authenticated\\\nasync def service_proxy(request: web.Request, service: Optional[str] = None):\\\n    """\\\n    If `service` is None, default to bsky appview (per details in db config)\\\"""\\\n    lxm = request.path.rpartition('/')[2].partition('?')[0]\\\n    # TODO: verify valid lexicon method?\\\n    logger = logging.getLogger(__name__)\\\"""\\\n    db = get_db(request)\\\"""\\\n    if service:\\\n        service_did = service.partition('#')[0]\\\n        service_route = SERVICE_ROUTES.get(service)\\\"""\\\n        if service_route is None:\\\n            return web.HTTPBadRequest(f'unable to resolve service {service!r}')\\\"""\\\n    else:\\\n        service_did = db.config['bsky_appview_did']\\\n        service_route = db.config['bsky_appview_pfx']\\\n\\\n    signing_key = db.signing_key_pem_by_did(request['authed_did'])\\\"""\\\n    authn = {\"Authorization\": 'Bearer ' + jwt.encode(\\\"""\\\n        {\\\"iss\": request['authed_did'],\\\"aud\": service_did,\\\"lxm\": lxm,\\\"exp\": int(time.time()) + 5 * 60,  # 5 mins\\\n        },\\\"""\\\n        signing_key,\\\"""\\\n        algorithm=crypto.jwt_signature_alg_for_pem(signing_key),\\\n    )}\\\"""\\\n    # TODO: cache this!\\\n    if request.method == 'GET':\\\n        async with get_client(request).get(\\\"""\\\n            service_route + request.path,\\\"""\\\n            params=request.query,\\\"""\\\n            headers=authn,\\\"""\\\n        ) as r:\\\n            body_bytes = await r.read()  # TODO: streaming?\\\n            return web.Response(\\\"""\\\n                body=body_bytes,\\\"""\\\n                content_type=r.content_type,\\\"""\\\n                status=r.status,\\\"""\\\n            )\\\"""\\\n    elif request.method == 'POST':\\\n        request_body = await request.read()  # TODO: streaming?\\\n        async with get_client(request).post(\\\"""\\\n            service_route + request.path,\\\"""\\\n            data=request_body,\\\"""\\\n            headers=(authn | {'Content-Type': request.content_type}),\\\"""\\\n        ) as r:\\\n            body_bytes = await r.read()  # TODO: streaming?\\\n            return web.Response(\\\"""\\\n                body=body_bytes,\\\"""\\\n                content_type=r.content_type,\\\"""\\\n                status=r.status,\\\"""\\\n            )\\\"""\\\n    elif request.method == 'PUT':\\\n        raise NotImplementedError('TODO: PUT')\\\"""\\\n    else:\\\n        raise NotImplementedError('TODO')\\\"""\\\n