import aiohttp
import asyncio
from typing import Dict, Callable, Any, Awaitable, Optional
import re
import json
import time
import logging

from .database import Database
from . import util
from . import static_config

logger = logging.getLogger(__name__)

DIDDoc = Dict[str, Any]

"""\nSecurity considerations for DID resolution:\n\n- SSRF - not handled here!!! - caller must pass in an "SSRF safe" ClientSession\n- Overly long DID strings (handled here via a hard limit (2KiB))\n- Overly long DID document responses (handled here via a hard limit (64KiB))\n- Servers that are slow to respond (handled via timeouts configured in the ClientSession)\n- Non-canonically-encoded DIDs (handled here via strict regex - for now we don't support percent-encoding at all)\n\n"""


class DIDResolver:
	DID_LENGTH_LIMIT = 2048
	DIDDOC_LENGTH_LIMIT = 0x10000

	def __init__(
		self,
		session: aiohttp.ClientSession,
		plc_directory_host: str = "https://plc.directory",
	) -> None:
		self.session: aiohttp.ClientSession = session
		self.plc_directory_host: str = plc_directory_host
		self.did_methods: Dict[str, Callable[[str], Awaitable[DIDDoc]]] = {
			"web": self.resolve_did_web,
			"plc": self.resolve_did_plc,
		}

		# keep stats for logging
		self.hits = 0
		self.misses = 0

	# note: the uncached methods raise exceptions on failure, but this one returns None
	async def resolve_with_db_cache(
		self, db: Database, did: str
	) -> Optional[DIDDoc]:
		# TODO: prevent concurrent queries for the same DID - use locks?

		# try the db first
		now = int(time.time())
		row = db.con.execute(
			"SELECT doc FROM did_cache WHERE did=? AND expires_at<?", (did, now)
		).fetchone()

		# cache hit
		if row is not None:
			self.hits += 1
			doc = row[0]
			return None if doc is None else json.loads(doc)

		# cache miss
		self.misses += 1
		logger.info(
			f"DID cache miss for {did}. Total hits: {self.hits}, Total misses: {self.misses}"
		)
		try:
			doc = await self.resolve_uncached(did)
		except Exception as e:
			logger.exception(f"Error resolving DID {did}: {e}")
			doc = None

		# update "now" because resolution might've taken a while\n		now = int(time.time())\n		expires_at = now + (\n			static_config.DID_CACHE_ERROR_TTL\n			if doc is None\n			else static_config.DID_CACHE_TTL\n		)\n\n		# update the cache (note: we cache failures too, but with a shorter TTL)\n		# TODO: if current doc is None, only replace if the existing entry is also None\n		db.con.execute(\n			"INSERT OR REPLACE INTO did_cache (did, doc, created_at, expires_at) VALUES (?, ?, ?, ?)",\n			(\n				did,\n				None if doc is None else util.compact_json(doc),\n				now,\n				expires_at,\n			),\n		)\n\n		return doc\n\n	async def resolve_uncached(self, did: str) -> DIDDoc:\n		if len(did) > self.DID_LENGTH_LIMIT:\n			raise ValueError("DID too long for atproto")\n		scheme, method, *_ = did.split(":")\n		if scheme != "did":\n			raise ValueError("not a valid DID")\n		resolver = self.did_methods.get(method)\n		if resolver is None:\n			raise ValueError(f"Unsupported DID method: {method}")\n		return await resolver(did)\n\n	# 64k ought to be enough for anyone!\n	async def _get_json_with_limit(self, url: str, limit: int) -> DIDDoc:\n		async with self.session.get(url) as r:\n			r.raise_for_status()\n			try:\n				await r.content.readexactly(limit)\n				raise ValueError("DID document too large")\n			except asyncio.IncompleteReadError as e:\n				# this is actually the happy path\n				return json.loads(e.partial)\n\n	async def resolve_did_web(self, did: str) -> DIDDoc:\n		# TODO: support port numbers on localhost?\n		if not re.match(r"^did:web:[a-z0-9\.\-]+$", did):\n			raise ValueError("Invalid did:web")\n		host = did.rpartition(":")[2]\n\n		return await self._get_json_with_limit(\n			f"https://{host}/.well-known/did.json", self.DIDDOC_LENGTH_LIMIT\n		)\n\n	async def resolve_did_plc(self, did: str) -> DIDDoc:\n		if not re.match(r"^did:plc:[a-z2-7]+$", did):  # base32-sortable\n			raise ValueError("Invalid did:plc")\n\n		return await self._get_json_with_limit(\n			f"{self.plc_directory_host}/{did}", self.DIDDOC_LENGTH_LIMIT\n		)\n\n\nasync def main() -> None:\n	async with aiohttp.ClientSession() as session:\n		resolver = DIDResolver(session)\n		print(await resolver.resolve_uncached("did:web:retr0.id"))\n		print(\n			await resolver.resolve_uncached("did:plc:vwzwgnygau7ed7b7wt5ux7y2")\n		)\n\n\nif __name__ == "__main__":\n	asyncio.run(main())