import os
import asyncio
import tempfile
import urllib.parse
import unittest.mock
import pytest
import dataclasses
import aiohttp
import aiohttp.web

from millipds import service
from millipds import database
from millipds import crypto

@dataclasses.dataclass
class PDSInfo:
    endpoint: str
    db: database.Database

old_web_tcpsite_start = aiohttp.web.TCPSite.start

def make_capture_random_bound_port_web_tcpsite_start(queue: asyncio.Queue):
    async def mock_start(site: aiohttp.web.TCPSite, *args, **kwargs):
        nonlocal queue
        await old_web_tcpsite_start(site, *args, **kwargs)
        await queue.put(site._server.sockets[0].getsockname()[1])
    return mock_start

async def service_run_and_capture_port(queue: asyncio.Queue, **kwargs):
    mock_start = make_capture_random_bound_port_web_tcpsite_start(queue)
    with unittest.mock.patch.object(aiohttp.web.TCPSite, "start", new=mock_start):
        await service.run(**kwargs)

if 0:
    TEST_DID = "did:web:alice.test"
    TEST_HANDLE = "alice.test"
    TEST_PASSWORD = "alice_pw"
else:
    TEST_DID = "did:plc:bwxddkvw5c6pkkntbtp2j4lx"
    TEST_HANDLE = "local.dev.retr0.id"
    TEST_PASSWORD = "lol"
TEST_PRIVKEY = crypto.keygen_p256()

@pytest.fixture
async def test_pds(aiolib):
    queue = asyncio.Queue()
    with tempfile.TemporaryDirectory() as tempdir:
        async with aiohttp.ClientSession() as client:
            db_path = f"{tempdir}/millipds-0000.db"
            db = database.Database(path=db_path)

            hostname = "localhost:0"
            db.update_config(
                pds_pfx=f"http://{hostname}",
                pds_did=f"did:web:{urllib.parse.quote(hostname)}",
                bsky_appview_pfx="https://api.bsky.app",
                bsky_appview_did="did:web:api.bsky.app",
            )

            service_run_task = asyncio.create_task(
                service_run_and_capture_port(
                    queue,
                    db=db,
                    client=client,
                    sock_path=None,
                    host="localhost",
                    port=0,
                )
            )
            queue_get_task = asyncio.create_task(queue.get())
            done, pending = await asyncio.wait(
                (queue_get_task, service_run_task),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if done == service_run_task:
                raise service_run_task.execption()
            else:
                port = queue_get_task.result()

            hostname = f"localhost:{port}"
            db.update_config(
                pds_pfx=f"http://{hostname}",
                pds_did=f"did:web:{urllib.parse.quote(hostname)}",
                bsky_appview_pfx="https://api.bsky.app",
                bsky_appview_did="did:web:api.bsky.app",
            )
            db.create_account(
                did=TEST_DID,
                handle=TEST_HANDLE,
                password=TEST_PASSWORD,
                privkey=TEST_PRIVKEY,
            )

            try:
                yield PDSInfo(
                    endpoint=f"http://{hostname}",
                    db=db,
                )
            finally:
                db.con.close()
                service_run_task.cancel()
                try:
                    await service_run_task
                except asyncio.CancelledError:
                    pass

@pytest.fixture
async def s(aiolib):
    async with aiohttp.ClientSession() as s:
        yield s

@pytest.fixture
def pds_host(test_pds) -> str:
    return test_pds.endpoint

async def test_hello_world(s, pds_host):
    async with s.get(pds_host + "/") as r:
        r = await r.text()
        print(r)
        assert "Hello" in r

async def test_describeServer(s, pds_host):
    async with s.get(pds_host + "/xrpc/com.atproto.server.describeServer") as r:
        print(await r.json())

# Add other test cases as needed
