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

# NB: each firehose event can be up to ~1MB, but on average they're much smaller\n\nDID_CACHE_TTL = 60 * 60  # 1 hour\nDID_CACHE_ERROR_TTL = 60 * 5  # 5 mins\n\n# New functionality\nfrom .did import DIDResolver\n\n__all__ = [\n	"HTTP_LOG_FMT",\n	"GROUPNAME",\n	"MILLIPDS_DB_VERSION",\n	"ATPROTO_REPO_VERSION_3",\n	"CAR_VERSION_1",\n	"DATA_DIR",\n	"MAIN_DB_PATH",\n	"REPOS_DIR",\n	"FIREHOSE_QUEUE_SIZE",\n	"DID_CACHE_TTL",\n	"DID_CACHE_ERROR_TTL",\n	"DIDResolver",\n]\n\n# Include a DID resolver instance\ndid_resolver = DIDResolver()