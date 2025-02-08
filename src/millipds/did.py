import aiohttp\nimport asyncio\nfrom typing import Dict, Callable, Any, Awaitable, Optional\nimport re\nimport json\nimport time\nimport logging\n\nfrom .database import Database\nfrom . import util\nfrom . import static_config\n\nlogger = logging.getLogger(__name__)\n\nDIDDoc = Dict[str, Any]\n\nclass DIDResolver:\n    DID_LENGTH_LIMIT = 2048\n    DIDDOC_LENGTH_LIMIT = 64 * 1024\n\n    def __init__(self, session: aiohttp.ClientSession, plc_directory_host: str = 'https://plc.directory'):\n        self.session = session\n        self.plc_directory_host = plc_directory_host\n        self.did_methods = {"web": self.resolve_did_web, "plc": self.resolve_did_plc}\n        self.hits = 0\n        self.misses = 0\n\n    async def resolve_with_db_cache(self, db: Database, did: str) -> Optional[DIDDoc]:\n        now = int(time.time())\n        row = db.con.execute("SELECT doc FROM did_cache WHERE did=? AND expires_at<?", (did, now)).fetchone()\n\n        if row is not None:\n            self.hits += 1\n            doc = row[0]\n            return None if doc is None else json.loads(doc)\n\n        self.misses += 1\n        logger.info(f"DID cache miss for {did}. Total hits: {self.hits}, Total misses: {self.misses}")\n        try:\n            doc = await self.resolve_uncached(did)\n        except Exception as e:\n            logger.exception(f'Error resolving DID {did}: {e}')\n            doc = None\n\n        expires_at = now + (static_config.DID_CACHE_ERROR_TTL if doc is None else static_config.DID_CACHE_TTL)\n        db.con.execute("INSERT OR REPLACE INTO did_cache (did, doc, created_at, expires_at) VALUES (?, ?, ?, ?)",\n                       (did, None if doc is None else json.dumps(doc), now, expires_at))\n        return doc\n\n    async def resolve_uncached(self, did: str) -> DIDDoc:\n        if len(did) > self.DID_LENGTH_LIMIT:\n            raise ValueError('DID too long for atproto')\n        scheme, method, *_ = did.split(':')\n        if scheme != 'did':\n            raise ValueError('not a valid DID')\n        resolver = self.did_methods.get(method)\n        if resolver is None:\n            raise ValueError(f'Unsupported DID method: {method}')\n        return await resolver(did)\n\n    async def _get_json_with_limit(self, url: str, limit: int) -> DIDDoc:\n        async with self.session.get(url) as r:\n            r.raise_for_status()\n            try:\n                await r.content.readexactly(limit)\n                raise ValueError('DID document too large')\n            except asyncio.IncompleteReadError as e:\n                return json.loads(e.partial)\n\n    async def resolve_did_web(self, did: str) -> DIDDoc:\n        if not re.match(r'^did:web:[a-z0-9\\".\-]+$', did):\n            raise ValueError('Invalid did:web')\n        host = did.rpartition(':')[2]\n        return await self._get_json_with_limit("https://{host}/.well-known/did.json", self.DIDDOC_LENGTH_LIMIT)\n\n    async def resolve_did_plc(self, did: str) -> DIDDoc:\n        if not re.match(r'^did:plc:[a-z2-7]+$', did):\n            raise ValueError('Invalid did:plc')\n        return await self._get_json_with_limit("{self.plc_directory_host}/{did}", self.DIDDOC_LENGTH_LIMIT)\n\nasync def main() -> None:\n    async with aiohttp.ClientSession() as session:\n        resolver = DIDResolver(session)\n        print(await resolver.resolve_uncached('did:web:retr0.id'))\n        print(await resolver.resolve_uncached('did:plc:vwzwgnygau7ed7b7wt5ux7y2'))\n\nif __name__ == '__main__':\n    asyncio.run(main())