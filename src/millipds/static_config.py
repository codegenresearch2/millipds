Hardcoded configs (it is not expected that end-users need to edit this file)

# This file contains configuration settings for the application.
HTTP_LOG_FMT = '%{X-Forwarded-For}i %t (%Tf) "%r" %s %b "%{Referer}i" "%{User-Agent}i"'

GROUPNAME = "millipds-sock"

# Versioning for the database, increment this when there are breaking changes to the schema. Current version is 2.
MILLIPDS_DB_VERSION = 2

# Versioning for ATProto repo
ATPROTO_REPO_VERSION_3 = 3

# Version for CAR files
CAR_VERSION_1 = 1

# Directory paths
DATA_DIR = "./data"
MAIN_DB_PATH = DATA_DIR + "/millipds.sqlite3"
REPOS_DIR = DATA_DIR + "/repos"

# Queue size for firehose events
# Adjust this based on the application's activity level.
FIREHOSE_QUEUE_SIZE = 100

# Time-to-live for DID cache entries
# The time-to-live for normal cache entries.
DID_CACHE_TTL = 60 * 60

# The time-to-live for cache entries in case of error.
DID_CACHE_ERROR_TTL = 60 * 5

# Host for the PLC directory, if applicable
PLC_DIRECTORY_HOST = "https://plc.directory"