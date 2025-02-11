# Hardcoded configs (it is not expected that end-users need to edit this file)

# (some of this stuff might want to be broken out into a proper config file, eventually)

# Format for HTTP access logs
HTTP_LOG_FMT = (
    '%{X-Forwarded-For}i %t (%Tf) "%r" %s %b "%{Referer}i" "%{User-Agent}i"'
)

# Group name for the socket
GROUPNAME = "millipds-sock"

# Version of the database schema (gets bumped with breaking changes)
MILLIPDS_DB_VERSION = 2

# Version of the ATProto repository (might change if the ATProto spec changes)
ATPROTO_REPO_VERSION_3 = 3

# Version of the CAR file format
CAR_VERSION_1 = 1

# Directory for data storage
DATA_DIR = "./data"

# Path to the main database file
MAIN_DB_PATH = DATA_DIR + "/millipds.sqlite3"

# Directory for repository storage
REPOS_DIR = DATA_DIR + "/repos"

# Maximum size of the firehose queue (potentially increase for very active PDS instances)
FIREHOSE_QUEUE_SIZE = 100

# Time-to-live for DID cache in seconds
DID_CACHE_TTL = 60 * 60  # 1 hour

# Time-to-live for DID cache errors in seconds
DID_CACHE_ERROR_TTL = 60 * 5  # 5 minutes

# Host for the PLC directory
PLC_DIRECTORY_HOST = "https://plc.directory"