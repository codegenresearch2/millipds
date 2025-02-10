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

# Adding handle_cache table as per user preference
import sqlite3

def create_handle_cache_table(conn: sqlite3.Connection):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS handle_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            handle TEXT NOT NULL UNIQUE,
            data TEXT NOT NULL
        )
    ''')
    conn.commit()

# Identifying users directly via repository ID as per user preference
class UserRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        create_handle_cache_table(self.conn)

    def get_user_by_id(self, user_id: int) -> dict:
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM handle_cache WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        if row:
            return {'id': row[0], 'handle': row[1], 'data': row[2]}
        return None

    def add_user(self, handle: str, data: str) -> None:
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO handle_cache (handle, data) VALUES (?, ?)', (handle, data))
        self.conn.commit()