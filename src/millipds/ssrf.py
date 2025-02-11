"""
This is a bit of a bodge, for now.

See https://github.com/aio-libs/aiohttp/discussions/10224 for the discussion
that led to this, and maybe a better solution in the future.
"""

import ipaddress
from aiohttp import TCPConnector, ClientSession
import aiohttp.connector
from aiohttp.resolver import DefaultResolver, AbstractResolver

# XXX: monkeypatch to force all hosts to go through the resolver
# (without this, bare IPs in the URL will bypass the resolver, where our SSRF check is)
aiohttp.connector.is_ip_address = lambda _: False

class SSRFException(ValueError):
	pass

class SSRFSafeResolverWrapper(AbstractResolver):
	def __init__(self, resolver: AbstractResolver):
		self.resolver = resolver

	async def resolve(self, host: str, port: int, family: int):
		result = await self.resolver.resolve(host, port, family)
		for host in result:
			if ipaddress.ip_address(host["host"]).is_private:
				raise SSRFException("Can't connect to private IP: " + host["host"])
		return result
	
	async def close(self) -> None:
		await self.resolver.close()

def get_ssrf_safe_client() -> ClientSession:
	resolver = SSRFSafeResolverWrapper(DefaultResolver())
	connector = TCPConnector(resolver=resolver)
	return ClientSession(connector=connector)

# User prefers to create a handle_cache table.
# User prefers to store metadata about handles in the database.
# User prefers to ensure data integrity with primary keys.

# Create handle_cache table
import sqlite3

def create_handle_cache_table(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS handle_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            handle TEXT NOT NULL UNIQUE,
            metadata TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()

# Store metadata about handles in the database
def store_handle_metadata(conn, handle, metadata):
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO handle_cache (handle, metadata) VALUES (?, ?)
        ON CONFLICT(handle) DO UPDATE SET metadata=excluded.metadata
    ''', (handle, metadata))
    conn.commit()

# Ensure data integrity with primary keys
conn = sqlite3.connect(':memory:')
create_handle_cache_table(conn)

# Example usage
store_handle_metadata(conn, "exampleHandle1", '{"key": "value"}')
store_handle_metadata(conn, "exampleHandle2", '{"key2": "value2"}')