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

"""\nSecurity considerations for DID resolution:\n\n- SSRF - not handled here!!! - caller must pass in an "SSRF safe" ClientSession\n- Overly long DID strings (handled here via a hard limit (2KiB))\n- Overly long DID document responses (handled here via a hard limit (64KiB))\n- Servers that are slow to respond (handled via timeouts configured in the ClientSession)\n- Non-canonically-encoded DIDs (handled here via strict regex - for now we don't support percent-encoding at all)\n\n"""

class DIDResolver:
    DID_LENGTH_LIMIT = 2048
    DIDDOC_LENGTH_LIMIT = 0x10000

    def __init__(self) -> None:
        self.hits = 0
        self.misses = 0
        self.did_methods: Dict[str, Callable[[str], Awaitable[DIDDoc]]] = {
            "web": self.resolve_did_web,
            "plc": self.resolve_did_plc,
        }

    async def resolve_with_db_cache(self, request: web.Request, did: str) -> Optional[DIDDoc]:
        db = get_db(request)
        session = get_client(request)

        # Try the db first
        now = int(time.time())
        row = db.con.execute(
            "SELECT doc FROM did_cache WHERE did=? AND expires_at<?", (did, now)
        ).fetchone()

        # Cache hit
        if row is not None:
            self.hits += 1
            doc = row[0]
            return None if doc is None else json.loads(doc)

        # Cache miss
        self.misses += 1
        logger.info(
            f"DID cache miss for {did}. Total hits: {self.hits}, Total misses: {self.misses}"
        )
        try:
            doc = await self.resolve_uncached(session, did)
        except Exception as e:
            logger.exception(f"Error resolving DID {did}: {e}")
            doc = None

        # Update "now" because resolution might've taken a while\n        now = int(time.time())\n        expires_at = now + (\n            static_config.DID_CACHE_ERROR_TTL\n            if doc is None\n            else static_config.DID_CACHE_TTL\n        )\n\n        # Update the cache (note: we cache failures too, but with a shorter TTL)\n        db.con.execute(\n            "INSERT OR REPLACE INTO did_cache (did, doc, created_at, expires_at) VALUES (?, ?, ?, ?)",\n            (\n                did,\n                None if doc is None else util.compact_json(doc),\n                now,\n                expires_at,\n            ),\n        )\n\n        return doc\n\n    async def resolve_uncached(self, session: aiohttp.ClientSession, did: str) -> DIDDoc:\n        if len(did) > self.DID_LENGTH_LIMIT:\n            raise ValueError("DID too long for atproto")\n        scheme, method, *_ = did.split(":")\n        if scheme != "did":\n            raise ValueError("not a valid DID")\n        resolver = self.did_methods.get(method)\n        if resolver is None:\n            raise ValueError(f"Unsupported DID method: {method}")\n        return await resolver(session, did)\n\n    async def _get_json_with_limit(self, session: aiohttp.ClientSession, url: str, limit: int) -> DIDDoc:\n        async with session.get(url) as r:\n            r.raise_for_status()\n            try:\n                await r.content.readexactly(limit)\n                raise ValueError("DID document too large")\n            except asyncio.IncompleteReadError as e:\n                # this is actually the happy path\n                return json.loads(e.partial)\n\n    async def resolve_did_web(self, session: aiohttp.ClientSession, did: str) -> DIDDoc:\n        if not re.match(r"^did:web:[a-z0-9\.\-]+$", did):\n            raise ValueError("Invalid did:web")\n        host = did.rpartition(":")[2]\n\n        return await self._get_json_with_limit(\n            session, f"https://{host}/.well-known/did.json", self.DIDDOC_LENGTH_LIMIT\n        )\n\n    async def resolve_did_plc(self, session: aiohttp.ClientSession, did: str) -> DIDDoc:\n        if not re.match(r"^did:plc:[a-z2-7]+$", did):  # base32-sortable\n            raise ValueError("Invalid did:plc")\n\n        return await self._get_json_with_limit(\n            session, f"{static_config.PLC_DIRECTORY_HOST}/{did}", self.DIDDOC_LENGTH_LIMIT\n        )