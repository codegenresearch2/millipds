import pytest
import asyncio
import aiohttp
from dataclasses import dataclass

@dataclass
class PDSInfo:
    endpoint: str
    db: object

@pytest.fixture(scope='module')
async def session():
    session = aiohttp.ClientSession()
    yield session
    await session.close()

@pytest.mark.parametrize('test_input, expected', [('test_data_1', 'expected_1'), ('test_data_2', 'expected_2')])
def test_hello_world(session, test_input, expected):
    async def fetch(session):
        async with session.get('http://example.com') as response:
            assert response.status == 200
            assert 'Hello' in await response.text()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(fetch(session))

async def test_example_skipped():
    pass