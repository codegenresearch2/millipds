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

"""
Security considerations for DID resolution:

- SSRF - not handled here!!! - caller must pass in an "SSRF safe" ClientSession
- Overly long DID strings (handled here via a hard limit (2KiB))
- Overly long DID document responses (handled here via a hard limit (64KiB))
- Servers that are slow to respond (handled via timeouts configured in the ClientSession)
- Non-canonically-encoded DIDs (handled here via strict regex - for now we don't support percent-encoding at all)

"""


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
			logger.info(f"DID {did} resolved successfully.")
		except Exception as e:
			logger.exception(f"Error resolving DID {did}: {e}")
			doc = None

		# update "now" because resolution might've taken a while
		now = int(time.time())
		expires_at = now + (
			static_config.DID_CACHE_ERROR_TTL
			if doc is None
			else static_config.DID_CACHE_TTL
		)

		# update the cache (note: we cache failures too, but with a shorter TTL)
		# TODO: if current doc is None, only replace if the existing entry is also None
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

	async def resolve_uncached(self, did: str) -> DIDDoc:
		if len(did) > self.DID_LENGTH_LIMIT:
			raise ValueError("DID too long for atproto")
		scheme, method, *_ = did.split(":")
		if scheme != "did":
			raise ValueError("not a valid DID")
		resolver = self.did_methods.get(method)
		if resolver is None:
			raise ValueError(f"Unsupported DID method: {method}")
		return await resolver(did)

	# 64k ought to be enough for anyone!
	async def _get_json_with_limit(self, url: str, limit: int) -> DIDDoc:
		async with self.session.get(url) as r:
			r.raise_for_status()
			try:
				await r.content.readexactly(limit)
				raise ValueError("DID document too large")
			except asyncio.IncompleteReadError as e:
				# this is actually the happy path
				return json.loads(e.partial)

	async def resolve_did_web(self, did: str) -> DIDDoc:
		# TODO: support port numbers on localhost?
		if not re.match(r"^did:web:[a-z0-9\.\-]+$", did):
			raise ValueError("Invalid did:web")
		host = did.rpartition(":")[2]

		return await self._get_json_with_limit(
			f"https://{host}/.well-known/did.json", self.DIDDOC_LENGTH_LIMIT
		)

	async def resolve_did_plc(self, did: str) -> DIDDoc:
		if not re.match(r"^did:plc:[a-z2-7]+$", did):  # base32-sortable
			raise ValueError("Invalid did:plc")

		return await self._get_json_with_limit(
			f"{self.plc_directory_host}/{did}", self.DIDDOC_LENGTH_LIMIT
		)


async def main() -> None:
	async with aiohttp.ClientSession() as session:
		resolver = DIDResolver(session)
		print(await resolver.resolve_uncached("did:web:retr0.id"))
		print(
			await resolver.resolve_uncached("did:plc:vwzwgnygau7ed7b7wt5ux7y2")
		)


if __name__ == "__main__":
	asyncio.run(main())