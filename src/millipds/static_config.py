# Hardcoded configs (it is not expected that end-users need to edit this file)

# (some of this stuff might want to be broken out into a proper config file, eventually)

HTTP_LOG_FMT = (
    '%{X-Forwarded-For}i %t (%Tf) "%r" %s %b "%{Referer}i" "%{User-Agent}i'
)

GROUPNAME = "millipds-sock"

MILLIPDS_DB_VERSION = 2  # this gets bumped if we make breaking changes to the db schema

ATPROTO_REPO_VERSION_3 = 3  # might get bumped if the atproto spec changes
CAR_VERSION_1 = 1

DATA_DIR = "./data"
MAIN_DB_PATH = DATA_DIR + "/millipds.sqlite3"
REPOS_DIR = DATA_DIR + "/repos"

FIREHOSE_QUEUE_SIZE = 100  # might want to tweak this upwards on a very active PDS

DID_CACHE_TTL = 60 * 60  # 1 hour
DID_CACHE_ERROR_TTL = 60 * 5  # 5 mins

PLC_DIRECTORY_HOST = "https://plc.directory"  # Add the missing configuration variable