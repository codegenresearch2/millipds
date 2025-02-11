import ipaddress
from aiohttp import TCPConnector, ClientSession
import aiohttp.connector
from aiohttp.resolver import DefaultResolver, AbstractResolver

# XXX: monkeypatch to force all hosts to go through the resolver
# (without this, bare IPs in the URL will bypass the resolver, where our SSRF check is)
# This is a workaround for a known issue.
# See https://github.com/aio-libs/aiohttp/discussions/10224 for more details.
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
                raise SSRFException(f"Can't connect to private IP: {host['host']}")
        return result

    async def close(self) -> None:
        await self.resolver.close()

def get_ssrf_safe_client() -> ClientSession:
    resolver = SSRFSafeResolverWrapper(DefaultResolver())
    connector = TCPConnector(resolver=resolver)
    return ClientSession(connector=connector)


In the revised code, I have ensured that the comments are formatted consistently with the gold code. I have also updated the exception message formatting in the `SSRFException` to reflect the gold code's style. The indentation levels have been reviewed for consistency, and the unnecessary comment about the workaround being a "bodge" has been removed. The overall structure of the code has been reviewed to match the organization and flow of the gold code.