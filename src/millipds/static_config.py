# Logging format for HTTP requests
HTTP_LOG_FMT = (
    '%{X-Forwarded-For}i %t (%Tf) "%r" %s %b "%{Referer}i" "%{User-Agent}i'
)

# Group name for Unix socket permissions
GROUPNAME = "millipds-sock"

# Database version
MILLIPDS_DB_VERSION = 2  # This gets bumped if we make breaking changes to the db schema

# Version for ATProto repo
ATPROTO_REPO_VERSION_3 = 3  # Might get bumped if the atproto spec changes

# Version for CAR files
CAR_VERSION_1 = 1

# Directory for data storage
DATA_DIR = "./data"

# Path to the main database file
MAIN_DB_PATH = DATA_DIR + "/millipds.sqlite3"

# Directory for repository storage
REPOS_DIR = DATA_DIR + "/repos"

# Size of the firehose queue
FIREHOSE_QUEUE_SIZE = 100

# Time-to-live for DID cache entries
DID_CACHE_TTL = 60 * 60  # 1 hour

# Time-to-live for DID cache entries in case of error
DID_CACHE_ERROR_TTL = 60 * 5  # 5 mins

# Host for PLC directory
PLC_DIRECTORY_HOST = "https://plc.directory"