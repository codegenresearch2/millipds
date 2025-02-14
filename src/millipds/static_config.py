Hardcoded configs (it is not expected that end-users need to edit this file)\n\n(some of this stuff might want to be broken out into a proper config file, eventually)\n\n# Updated HTTP log format\nHTTP_LOG_FMT = '%{X-Forwarded-For}i %t (%Tf) "%r" %s %b "%{Referer}i" "%{User-Agent}i"'\n\n# Groupname for socket\nGROUPNAME = "millipds-sock"\n\n# Database version\nMILLIPDS_DB_VERSION = 1  # this gets bumped if we make breaking changes to the db schema\n\n# ATPROTO repo version\nATPROTO_REPO_VERSION_3 = 3  # might get bumped if the atproto spec changes\n\n# Car version\nCAR_VERSION_1 = 1\n\n# Data directory\nDATA_DIR = "./data"\n\n# Main database path\nMAIN_DB_PATH = DATA_DIR + "/millipds.sqlite3"\n\n# Repositories directory\nREPOS_DIR = DATA_DIR + "/repos"\n\n# Firehose queue size\nFIREHOSE_QUEUE_SIZE = 100\n\n# DID cache TTL\nDID_CACHE_TTL = 60 * 60  # 1 hour\n\n# DID cache error TTL\nDID_CACHE_ERROR_TTL = 60 * 5  # 5 mins\n\n# New functionality: DIDResolver instance\nfrom .did import DIDResolver\n\n# Updated __all__ to include new items\n__all__ = [\n    "HTTP_LOG_FMT",\n    "GROUPNAME",\n    "MILLIPDS_DB_VERSION",\n    "ATPROTO_REPO_VERSION_3",\n    "CAR_VERSION_1",\n    "DATA_DIR",\n    "MAIN_DB_PATH",\n    "REPOS_DIR",\n    "FIREHOSE_QUEUE_SIZE",\n    "DID_CACHE_TTL",\n    "DID_CACHE_ERROR_TTL",\n    "DIDResolver"\n]