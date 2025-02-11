"""
Hardcoded configs (it is not expected that end-users need to edit this file)

(some of this stuff might want to be broken out into a proper config file, eventually)
"""

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

# NB: each firehose event can be up to ~1MB, but on average they're much smaller

DID_CACHE_TTL = 60 * 60  # 1 hour
DID_CACHE_ERROR_TTL = 60 * 5  # 5 mins

# Integrate DIDResolver into application context
async def setup_did_resolver(app):
    client = app[MILLIPDS_AIOHTTP_CLIENT]
    did_resolver = DIDResolver(client, static_config.PLC_DIRECTORY_HOST)
    app[MILLIPDS_DID_RESOLVER] = did_resolver

# Improve error handling for service resolution
@routes.get("/.well-known/did.json")
async def well_known_did_web(request: web.Request):
    did_resolver = get_did_resolver(request)
    cfg = get_db(request).config
    try:
        did_doc = await did_resolver.resolve_did(cfg["pds_did"])
        return web.json_response(did_doc)
    except Exception as e:
        logger.error(f"Failed to resolve DID: {e}")
        raise web.HTTPInternalServerError(text="Failed to resolve DID")