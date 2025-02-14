import aiohttp
import asyncio
from typing import Dict, Callable, Any, Awaitable, Optional
import re
import json
import time
import logging

from .app_util import get_db, get_client
from . import util
from . import static_config

logger = logging.getLogger(__name__)

DIDDoc = Dict[str, Any]

class DIDResolver:
    DID_LENGTH_LIMIT = 2048
    DIDDOC_LENGTH_LIMIT = 0x10000

    def __init__(self) -> None:
        self.hits = 0
        self.misses = 0

    async def resolve_with_db_cache(self, did: str) -> Optional[DIDDoc]:
        db = get_db()
        session = get_client()

        now = int(time.time())
        row = db.con.execute(
            "SELECT doc FROM did_cache WHERE did=? AND expires_at<?", (did, now)
        ).fetchone()

        if row is not None:
            self.hits += 1
            doc = row[0]
            return None if doc is None else json.loads(doc)

        self.misses += 1
        logger.info(
            f"DID cache miss for {did}. Total hits: {self.hits}, Total misses: {self.misses}"
        )
        try:
            doc = await self.resolve_uncached(session, did)
        except Exception as e:
            logger.exception(f"Error resolving DID {did}: {e}")
            doc = None

        now = int(time.time())
        expires_at = now + (
            static_config.DID_CACHE_ERROR_TTL
            if doc is None
            else static_config.DID_CACHE_TTL
        )

        db.con.execute(
            "INSERT OR REPLACE INTO did_cache (did, doc, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (
                did,
                None if doc is None else util.compact_json(doc),
                now,
                expires_at,
            ),
        )

        return doc

    async def resolve_uncached(self, session: aiohttp.ClientSession, did: str) -> DIDDoc:
        if len(did) > self.DID_LENGTH_LIMIT:
            raise ValueError("DID too long for atproto")
        scheme, method, *_ = did.split(":")
        if scheme != "did":
            raise ValueError("not a valid DID")
        resolver = self.get_resolver_for_method(method)
        if resolver is None:
            raise ValueError(f"Unsupported DID method: {method}")
        return await resolver(session, did)

    async def _get_json_with_limit(self, session: aiohttp.ClientSession, url: str, limit: int) -> DIDDoc:
        async with session.get(url) as r:
            r.raise_for_status()
            try:
                await r.content.readexactly(limit)
                raise ValueError("DID document too large")
            except asyncio.IncompleteReadError as e:
                return json.loads(e.partial)

    async def resolve_did_web(self, session: aiohttp.ClientSession, did: str) -> DIDDoc:
        if not re.match(r"^did:web:[a-z0-9\.\-]+$", did):
            raise ValueError("Invalid did:web")
        host = did.rpartition(":")[2]
        return await self._get_json_with_limit(
            session, f"https://{host}/.well-known/did.json", self.DIDDOC_LENGTH_LIMIT
        )

    async def resolve_did_plc(self, session: aiohttp.ClientSession, did: str) -> DIDDoc:
        if not re.match(r"^did:plc:[a-z2-7]+$", did):
            raise ValueError("Invalid did:plc")
        plc_directory_host = static_config.PLC_DIRECTORY_HOST
        return await self._get_json_with_limit(
            session, f"{plc_directory_host}/{did}", self.DIDDOC_LENGTH_LIMIT
        )

    def get_resolver_for_method(self, method: str) -> Callable[[aiohttp.ClientSession, str], Awaitable[DIDDoc]]:
        return {
            "web": self.resolve_did_web,
            "plc": self.resolve_did_plc,
        }.get(method)