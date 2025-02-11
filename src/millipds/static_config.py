"""
Hardcoded configs (it is not expected that end-users need to edit this file)

(some of this stuff might want to be broken out into a proper config file, eventually)
"""

from .app_util import MILLIPDS_DID_RESOLVER

HTTP_LOG_FMT = (
	'%{X-Forwarded-For}i %t (%Tf) "%r" %s %b "%{Referer}i" "%{User-Agent}i"'
)

GROUPNAME = "millipds-sock"

MILLIPDS_DB_VERSION = 1
ATPROTO_REPO_VERSION_3 = 3
CAR_VERSION_1 = 1

DATA_DIR = "./data"
MAIN_DB_PATH = DATA_DIR + "/millipds.sqlite3"
REPOS_DIR = DATA_DIR + "/repos"

FIREHOSE_QUEUE_SIZE = 100

DID_CACHE_TTL = 60 * 60
DID_CACHE_ERROR_TTL = 60 * 5

__all__ = [
	"MILLIPDS_DB_VERSION",
	"ATPROTO_REPO_VERSION_3",
	"CAR_VERSION_1",
	"DATA_DIR",
	"MAIN_DB_PATH",
	"REPOS_DIR",
	"FIREHOSE_QUEUE_SIZE",
	"DID_CACHE_TTL",
	"DID_CACHE_ERROR_TTL",
	"HTTP_LOG_FMT",
	"GROUPNAME",
	"MILLIPDS_DID_RESOLVER",
]


In the rewritten code, I have updated the `__all__` list to include the new items. I have also added `MILLIPDS_DID_RESOLVER` to the `__all__` list as per the user's preference. I have maintained the consistent naming conventions for helpers and kept the CORS configuration unchanged as per the user's preferences.