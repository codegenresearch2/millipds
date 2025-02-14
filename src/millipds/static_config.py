"""\nHardcoded configs (it is not expected that end-users need to edit this file)\n\n(some of this stuff might want to be broken out into a proper config file, eventually)\n"""

from typing import Optional
import importlib.metadata
import os

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

# NB: each firehose event can be up to ~1MB, but on average they're much smaller\n\nDID_CACHE_TTL = 60 * 60  # 1 hour\nDID_CACHE_ERROR_TTL = 60 * 5  # 5 mins\n\n# Initialize the DIDResolver with the application context\nDID_RESOLVER = DIDResolver(get_client(request), static_config.PLC_DIRECTORY_HOST)\napp[MILLIPDS_DID_RESOLVER] = DID_RESOLVER\n\n# Improved error handling for service resolution\ntry:\n    did = DID_RESOLVER.resolve(request.query.get("handle"))\n    if not did:\n        raise web.HTTPNotFound(text="DID not found")\nexcept Exception as e:\n    logger.error(f"DID resolution failed: {e}")\n    raise web.HTTPInternalServerError(text="DID resolution failed")\n\n# Dynamic DID resolution over hardcoded routes\nasync def identity_resolve_handle(request: web.Request):\n    handle = request.query.get("handle")\n    if handle is None:\n        raise web.HTTPBadRequest(text="missing or invalid handle")\n\n    try:\n        did = await DID_RESOLVER.resolve(handle)\n        if did:\n            return web.json_response({"did": did})\n        else:\n            raise web.HTTPNotFound(text="DID not found")\n    except Exception as e:\n        logger.error(f"DID resolution failed: {e}")\n        raise web.HTTPInternalServerError(text="DID resolution failed")