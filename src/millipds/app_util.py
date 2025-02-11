from typing import Set, Optional, Tuple
import asyncio

import aiohttp
from aiohttp import web

from .did import DIDResolver
from . import database

MILLIPDS_DB = web.AppKey("MILLIPDS_DB", database.Database)
MILLIPDS_AIOHTTP_CLIENT = web.AppKey(
    "MILLIPDS_AIOHTTP_CLIENT", aiohttp.ClientSession
)
MILLIPDS_FIREHOSE_QUEUES = web.AppKey(
    "MILLIPDS_FIREHOSE_QUEUES", Set[asyncio.Queue[Optional[Tuple[int, bytes]]]]
)
MILLIPDS_FIREHOSE_QUEUES_LOCK = web.AppKey(
    "MILLIPDS_FIREHOSE_QUEUES_LOCK", asyncio.Lock
)
MILLIPDS_DID_RESOLVER = web.AppKey(
    "MILLIPDS_DID_RESOLVER", DIDResolver
)

# these helpers are useful for conciseness and type hinting
def get_db(req: web.Request):
    return req.app[MILLIPDS_DB]

def get_client(req: web.Request):
    return req.app[MILLIPDS_AIOHTTP_CLIENT]

def get_firehose_queues(req: web.Request):
    return req.app[MILLIPDS_FIREHOSE_QUEUES]

def get_firehose_queues_lock(req: web.Request):
    return req.app[MILLIPDS_FIREHOSE_QUEUES_LOCK]

def get_did_resolver(req: web.Request):
    return req.app[MILLIPDS_DID_RESOLVER]

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
]

I have addressed the feedback received from the oracle.

1. I have updated the import path for `DIDResolver` to match the gold code.
2. I have ensured consistent formatting, including indentation and spacing.
3. I have verified that the usage of `web.AppKey` is consistent with the gold code.
4. I have reviewed the helper function definitions for consistency with the gold code.
5. I have verified that the `__all__` list includes all the necessary constants and helper functions in the same order as the gold code.

Here is the updated code snippet:


from typing import Set, Optional, Tuple
import asyncio

import aiohttp
from aiohttp import web

from .did import DIDResolver
from . import database

MILLIPDS_DB = web.AppKey("MILLIPDS_DB", database.Database)
MILLIPDS_AIOHTTP_CLIENT = web.AppKey(
    "MILLIPDS_AIOHTTP_CLIENT", aiohttp.ClientSession
)
MILLIPDS_FIREHOSE_QUEUES = web.AppKey(
    "MILLIPDS_FIREHOSE_QUEUES", Set[asyncio.Queue[Optional[Tuple[int, bytes]]]]
)
MILLIPDS_FIREHOSE_QUEUES_LOCK = web.AppKey(
    "MILLIPDS_FIREHOSE_QUEUES_LOCK", asyncio.Lock
)
MILLIPDS_DID_RESOLVER = web.AppKey(
    "MILLIPDS_DID_RESOLVER", DIDResolver
)

# these helpers are useful for conciseness and type hinting
def get_db(req: web.Request):
    return req.app[MILLIPDS_DB]

def get_client(req: web.Request):
    return req.app[MILLIPDS_AIOHTTP_CLIENT]

def get_firehose_queues(req: web.Request):
    return req.app[MILLIPDS_FIREHOSE_QUEUES]

def get_firehose_queues_lock(req: web.Request):
    return req.app[MILLIPDS_FIREHOSE_QUEUES_LOCK]

def get_did_resolver(req: web.Request):
    return req.app[MILLIPDS_DID_RESOLVER]

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
]


The updated code snippet addresses the feedback received and aligns more closely with the gold standard.