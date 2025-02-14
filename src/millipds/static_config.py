"""\nHardcoded configs (it is not expected that end-users need to edit this file)\n\n(some of this stuff might want to be broken out into a proper config file, eventually)\n"""

HTTP_LOG_FMT = (
	'%{X-Forwarded-For}i %t (%Tf) "%r" %s %b "%{Referer}i" "%{User-Agent}i"'
)

GROUPNAME = "millipds-sock"

MILLIPDS_DB_VERSION = (
	1  # this gets bumped if we make breaking changes to the db schema
)
ATPROTO_REPO_VERSION_3 = 3  # might get bumped if the atproto spec changes
CAR_VERSION_1 = 1

DATA_DIR = "./data"
MAIN_DB_PATH = DATA_DIR + "/millipds.sqlite3"
REPOS_DIR = DATA_DIR + "/repos"

# might want to tweak this upwards on a very active PDS
FIREHOSE_QUEUE_SIZE = 100

# NB: each firehose event can be up to ~1MB, but on average they're much smaller\n\nDID_CACHE_TTL = 60 * 60  # 1 hour\nDID_CACHE_ERROR_TTL = 60 * 5  # 5 mins\n\n# Integrate DIDResolver into application context\nasync def setup_did_resolver(app):\n    client = app[MILLIPDS_AIOHTTP_CLIENT]\n    did_resolver = DIDResolver(client, static_config.PLC_DIRECTORY_HOST)\n    app[MILLIPDS_DID_RESOLVER] = did_resolver\n\n# Improved error handling for service resolution\n@routes.get("/xrpc/com.atproto.identity.resolveHandle")\nasync def identity_resolve_handle(request: web.Request):\n    handle = request.query.get("handle")\n    if handle is None:\n        raise web.HTTPBadRequest(text="Missing or invalid handle")\n\n    did_resolver = get_did_resolver(request)\n    try:\n        did = await did_resolver.resolve_handle(handle)\n    except Exception as e:\n        raise web.HTTPInternalServerError(text=str(e))\n\n    if not did:\n        # Forward to appview (TODO: resolve it ourself?)\n        return await service_proxy(request)\n\n    # TODO: set cache control response headers?\n    return web.json_response({"did": did})