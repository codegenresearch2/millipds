"""\nHardcoded configs (it is not expected that end-users need to edit this file)\n\n(some of this stuff might want to be broken out into a proper config file, eventually)\n"""

from typing import Optional
import importlib.metadata

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

# NB: each firehose event can be up to ~1MB, but on average they're much smaller\n\nDID_CACHE_TTL = 60 * 60  # 1 hour\nDID_CACHE_ERROR_TTL = 60 * 5  # 5 mins\n\ndef get_did_resolver():\n    client = get_client(request)\n    return DIDResolver(client, PLC_DIRECTORY_HOST)\n\ndef resolve_did(did: str) -> Optional[str]:\n    try:\n        return get_did_resolver().resolve(did)\n    except Exception as e:\n        logger.error(f"Failed to resolve DID {did}: {e}")\n        return None