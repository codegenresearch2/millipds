# This code snippet is a workaround for a known issue in aiohttp that allows bypassing the resolver for bare IPs in URLs.
# This monkeypatch forces all hosts to go through the resolver, where our SSRF check is performed.
# See https://github.com/aio-libs/aiohttp/discussions/10224 for more details.

import ipaddress
from aiohttp import TCPConnector, ClientSession
import aiohttp.connector
from aiohttp.resolver import DefaultResolver, AbstractResolver

# Monkeypatch to force all hosts to go through the resolver
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
                raise SSRFException("Can't connect to private IP: {}".format(host["host"]))
        return result

    async def close(self) -> None:
        await self.resolver.close()

def get_ssrf_safe_client() -> ClientSession:
    resolver = SSRFSafeResolverWrapper(DefaultResolver())
    connector = TCPConnector(resolver=resolver)
    return ClientSession(connector=connector)