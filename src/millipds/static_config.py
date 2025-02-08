Hardcoded configs (it is not expected that end-users need to edit this file)

# This file contains configuration settings for the application.
HTTP_LOG_FMT = '%{X-Forwarded-For}i %t (%Tf) "%r" %s %b "%{Referer}i" "%{User-Agent}i"'

GROUPNAME = "millipds-sock"

# Versioning for the database, increment this when there are breaking changes to the schema.
# NB: This should be updated whenever the database schema is modified in a way that could affect existing data.
MILLIPDS_DB_VERSION = 2

# Versioning for ATProto repo
# NB: This should be updated whenever the ATProto specification is modified.
ATPROTO_REPO_VERSION_3 = 3

# Version for CAR files
# NB: This should be updated whenever the CAR file format is modified.
CAR_VERSION_1 = 1

# Directory paths
DATA_DIR = "./data"
MAIN_DB_PATH = DATA_DIR + "/millipds.sqlite3"
REPOS_DIR = DATA_DIR + "/repos"

# Queue size for firehose events
# NB: Adjust this based on the application's activity level.
FIREHOSE_QUEUE_SIZE = 100

# Time-to-live for DID cache entries
# The time-to-live for normal cache entries.
# NB: This should be adjusted based on the expected cache usage and performance.
DID_CACHE_TTL = 60 * 60

# The time-to-live for cache entries in case of error.
# NB: This should be shorter than DID_CACHE_TTL to ensure quick recovery from errors.
DID_CACHE_ERROR_TTL = 60 * 5

# Host for the PLC directory, if applicable
PLC_DIRECTORY_HOST = "https://plc.directory"