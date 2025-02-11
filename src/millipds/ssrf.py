import ipaddress
from aiohttp import TCPConnector, ClientSession
import aiohttp.connector
from aiohttp.resolver import DefaultResolver, AbstractResolver

# Monkeypatch to force all hosts to go through the resolver
# This is necessary to prevent SSRF attacks by bypassing the resolver for bare IPs
aiohttp.connector.is_ip_address = lambda _: False

class SSRFException(ValueError):
    """Exception raised when an attempt is made to connect to a private IP."""
    pass

class SSRFSafeResolverWrapper(AbstractResolver):
    """Wrapper for a resolver that checks if the resolved IP is private."""

    def __init__(self, resolver: AbstractResolver):
        self.resolver = resolver

    async def resolve(self, host: str, port: int, family: int):
        result = await self.resolver.resolve(host, port, family)
        for host in result:
            if ipaddress.ip_address(host["host"]).is_private:
                raise SSRFException(f"Can't connect to private IP: {host['host']}")
        return result

    async def close(self) -> None:
        await self.resolver.close()

def get_ssrf_safe_client() -> ClientSession:
    """Returns a ClientSession that uses a resolver wrapper to prevent SSRF attacks."""
    resolver = SSRFSafeResolverWrapper(DefaultResolver())
    connector = TCPConnector(resolver=resolver)
    return ClientSession(connector=connector)

# Database class with handle_cache table and password hashing

class Database:
    """Database class with handle_cache table and password hashing functionality."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.con = self.connect()
        self.create_tables()

    def connect(self):
        # Implement connection logic here
        pass

    def create_tables(self):
        # Create handle_cache table and other necessary tables
        self.con.execute("CREATE TABLE IF NOT EXISTS handle_cache (id INTEGER PRIMARY KEY, handle TEXT, repo_id INTEGER)")

    def hash_password(self, password: str) -> str:
        # Implement password hashing logic here
        pass

# Usage
db = Database(":memory:")
hashed_password = db.hash_password("user_password")