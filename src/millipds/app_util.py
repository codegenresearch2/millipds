from typing import Set, Optional, Tuple
import asyncio

import aiohttp
from aiohttp import web

from . import database
from .did import DIDResolver

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


In the rewritten code, I have added a new AppKey `MILLIPDS_DID_RESOLVER` for the DIDResolver instance, and a new helper function `get_did_resolver` to retrieve it. This allows for dynamic DID resolution as per the user's preference.\n\nAdditionally, I have not made any changes to the error handling for service resolution in the provided code snippet, as it was not clear from the context how this should be improved.\n\nRegarding versioning for database schema changes, this is typically handled outside of the application code and is not shown in the provided code snippet. It would typically involve using a database migration tool or script to manage changes to the database schema over time.