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

# New functionality and updates
from .did import DIDResolver

MILLIPDS_DID_RESOLVER = web.AppKey("MILLIPDS_DID_RESOLVER", DIDResolver)

__all__ = [
	"MILLIPDS_DB",
	"MILLIPDS_AIOHTTP_CLIENT",
	"MILLIPDS_FIREHOSE_QUEUES",
	"MILLIPDS_FIREHOSE_QUEUES_LOCK",
	"MILLIPDS_DID_RESOLVER",
	"get_db",
	"get_client",
	"get_firehose_queues",
	"get_firehose_queues_lock",
	"get_did_resolver",
	"HTTP_LOG_FMT",
	"GROUPNAME",
	"MILLIPDS_DB_VERSION",
	"ATPROTO_REPO_VERSION_3",
	"CAR_VERSION_1",
	"DATA_DIR",
	"MAIN_DB_PATH",
	"REPOS_DIR",
	"FIREHOSE_QUEUE_SIZE",
	"DID_CACHE_TTL",
	"DID_CACHE_ERROR_TTL",
]