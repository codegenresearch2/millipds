Hardcoded configs (it is not expected that end-users need to edit this file)

# This is a descriptive comment, which should be prefixed with '#' for Python to recognize it as a comment
HTTP_LOG_FMT = '%{X-Forwarded-For}i %t (%Tf) "%r" %s %b "%{Referer}i" "%{User-Agent}i"'

GROUPNAME = "millipds-sock"

# Versioning for configurations
MILLIPDS_DB_VERSION = 1
ATPROTO_REPO_VERSION_3 = 3
CAR_VERSION_1 = 1

# Directory paths
DATA_DIR = "./data"
MAIN_DB_PATH = DATA_DIR + "/millipds.sqlite3"
REPOS_DIR = DATA_DIR + "/repos"

# Queue size for firehose events
FIREHOSE_QUEUE_SIZE = 100

# Time-to-live for DID cache entries
DID_CACHE_TTL = 60 * 60
DID_CACHE_ERROR_TTL = 60 * 5