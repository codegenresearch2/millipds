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

# Define a dataclass for PDSInfo with clearer variable assignments
@dataclasses.dataclass
class PDSInfo:
    endpoint: str
    db: database.Database

# Define a function to make capturing the random bound port for the web TCPSite start
def make_capture_random_bound_port_web_tcpsite_start(queue: asyncio.Queue):
    async def mock_start(site: aiohttp.web.TCPSite, *args, **kwargs):
        await old_web_tcpsite_start(site, *args, **kwargs)
        await queue.put(site._server.sockets[0].getsockname()[1])
    return mock_start

# Define an async function to run the service and capture the port
async def service_run_and_capture_port(queue: asyncio.Queue, **kwargs):
    mock_start = make_capture_random_bound_port_web_tcpsite_start(queue)
    with unittest.mock.patch.object(aiohttp.web.TCPSite, "start", new=mock_start):
        await service.run(**kwargs)

# Define test constants with clearer variable assignments
TEST_DID = "did:plc:bwxddkvw5c6pkkntbtp2j4lx"
TEST_HANDLE = "local.dev.retr0.id"
TEST_PASSWORD = "lol"
TEST_PRIVKEY = crypto.keygen_p256()

# Define a pytest fixture for the test PDS
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
                raise service_run_task.exception()
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

# Define a pytest fixture for the aiohttp client session
@pytest.fixture
async def s(aiolib):
    async with aiohttp.ClientSession() as s:
        yield s

# Define a pytest fixture for the PDS host
@pytest.fixture
def pds_host(test_pds) -> str:
    return test_pds.endpoint

# Define a pytest fixture for the authenticated headers
@pytest.fixture
async def auth_headers(s, pds_host):
    async with s.post(
        pds_host + "/xrpc/com.atproto.server.createSession",
        json=valid_logins[0],
    ) as r:
        r = await r.json()
    token = r["accessJwt"]
    return {"Authorization": "Bearer " + token}

# Define a pytest fixture for the populated PDS host
@pytest.fixture
async def populated_pds_host(s, pds_host, auth_headers):
    for i in range(10):
        async with s.post(
            pds_host + "/xrpc/com.atproto.repo.applyWrites",
            headers=auth_headers,
            json={
                "repo": TEST_DID,
                "writes": [
                    {
                        "action": "create",
                        "collection": "app.bsky.feed.like",
                        "rkey": f"{i}-{j}",
                        "value": {"blah": "test record"},
                    }
                    for j in range(30)
                ],
            },
        ) as r:
            assert r.status == 200
    return pds_host

# Define test functions with clearer variable assignments and comments
async def test_hello_world(s, pds_host):
    async with s.get(pds_host + "/") as r:
        response_text = await r.text()
        assert "Hello" in response_text

async def test_describeServer(s, pds_host):
    async with s.get(pds_host + "/xrpc/com.atproto.server.describeServer") as r:
        response_json = await r.json()
        print(response_json)

async def test_createSession_no_args(s, pds_host):
    async with s.post(pds_host + "/xrpc/com.atproto.server.createSession") as r:
        assert r.status != 200

invalid_logins = [
    {"identifier": [], "password": TEST_PASSWORD},
    {"identifier": "example.invalid", "password": "wrongPassword123"},
    {"identifier": TEST_HANDLE, "password": "wrongPassword123"},
]

@pytest.mark.parametrize("login_data", invalid_logins)
async def test_invalid_logins(s, pds_host, login_data):
    async with s.post(
        pds_host + "/xrpc/com.atproto.server.createSession",
        json=login_data,
    ) as r:
        assert r.status != 200

valid_logins = [
    {"identifier": TEST_HANDLE, "password": TEST_PASSWORD},
    {"identifier": TEST_DID, "password": TEST_PASSWORD},
]

@pytest.mark.parametrize("login_data", valid_logins)
async def test_valid_logins(s, pds_host, login_data):
    async with s.post(
        pds_host + "/xrpc/com.atproto.server.createSession",
        json=login_data,
    ) as r:
        response_json = await r.json()
        assert response_json["did"] == TEST_DID
        assert response_json["handle"] == TEST_HANDLE
        assert "accessJwt" in response_json
        assert "refreshJwt" in response_json

async def test_sync_getRepo(s, pds_host):
    async with s.get(
        pds_host + "/xrpc/com.atproto.sync.getRepo",
        params={"did": TEST_DID},
    ) as r:
        assert r.status == 200

async def test_repo_applyWrites(s, pds_host, auth_headers):
    for i in range(10):
        async with s.post(
            pds_host + "/xrpc/com.atproto.repo.applyWrites",
            headers=auth_headers,
            json={
                "repo": TEST_DID,
                "writes": [
                    {
                        "action": "create",
                        "collection": "app.bsky.feed.like",
                        "rkey": f"{i}-{j}",
                        "value": {"blah": "test record"},
                    }
                    for j in range(30)
                ],
            },
        ) as r:
            assert r.status == 200

async def test_repo_uploadBlob(s, pds_host, auth_headers):
    blob = os.urandom(0x100000)

    for _ in range(2):
        async with s.post(
            pds_host + "/xrpc/com.atproto.repo.uploadBlob",
            headers=auth_headers | {"content-type": "blah"},
            data=blob,
        ) as r:
            response_json = await r.json()
            assert r.status == 200

    async with s.get(
        pds_host + "/xrpc/com.atproto.sync.getBlob",
        params={"did": TEST_DID, "cid": response_json["blob"]["ref"]["$link"]},
    ) as r:
        assert r.status == 404

    async with s.post(
        pds_host + "/xrpc/com.atproto.repo.createRecord",
        headers=auth_headers,
        json={
            "repo": TEST_DID,
            "collection": "app.bsky.feed.post",
            "record": {"myblob": response_json},
        },
    ) as r:
        assert r.status == 200

    async with s.get(
        pds_host + "/xrpc/com.atproto.sync.getBlob",
        params={"did": TEST_DID, "cid": response_json["blob"]["ref"]["$link"]},
    ) as r:
        downloaded_blob = await r.read()
        assert downloaded_blob == blob

    async with s.get(
        pds_host + "/xrpc/com.atproto.sync.getRepo",
        params={"did": TEST_DID},
    ) as r:
        assert r.status == 200
        open("repo.car", "wb").write(await r.read())

async def test_sync_getRepo_not_found(s, pds_host):
    async with s.get(
        pds_host + "/xrpc/com.atproto.sync.getRepo",
        params={"did": "did:web:nonexistent.invalid"},
    ) as r:
        assert r.status == 404

async def test_sync_getRecord_nonexistent(s, populated_pds_host):
    async with s.get(
        populated_pds_host + "/xrpc/com.atproto.sync.getRecord",
        params={
            "did": "did:web:nonexistent.invalid",
            "collection": "app.bsky.feed.post",
            "rkey": "nonexistent",
        },
    ) as r:
        assert r.status == 404

    async with s.get(
        populated_pds_host + "/xrpc/com.atproto.sync.getRecord",
        params={
            "did": TEST_DID,
            "collection": "app.bsky.feed.post",
            "rkey": "nonexistent",
        },
    ) as r:
        assert r.status == 200
        assert r.content_type == "application/vnd.ipld.car"
        proof_car = await r.read()
        assert proof_car

async def test_sync_getRecord_existent(s, populated_pds_host):
    async with s.get(
        populated_pds_host + "/xrpc/com.atproto.sync.getRecord",
        params={
            "did": TEST_DID,
            "collection": "app.bsky.feed.like",
            "rkey": "1-1",
        },
    ) as r:
        assert r.status == 200
        assert r.content_type == "application/vnd.ipld.car"
        proof_car = await r.read()
        assert proof_car
        assert b"test record" in proof_car

async def test_serviceauth(s, test_pds, auth_headers):
    async with s.get(
        test_pds.endpoint + "/xrpc/com.atproto.server.getServiceAuth",
        headers=auth_headers,
        params={
            "aud": test_pds.db.config["pds_did"],
            "lxm": "com.atproto.server.getSession",
        },
    ) as r:
        assert r.status == 200
        token = (await r.json())["token"]

    async with s.get(
        test_pds.endpoint + "/xrpc/com.atproto.server.getSession",
        headers={"Authorization": "Bearer " + token},
    ) as r:
        assert r.status == 200
        await r.json()

async def test_refreshSession(s, pds_host):
    async with s.post(
        pds_host + "/xrpc/com.atproto.server.createSession",
        json=valid_logins[0],
    ) as r:
        assert r.status == 200
        r = await r.json()
        orig_session_token = r["accessJwt"]
        orig_refresh_token = r["refreshJwt"]

    async with s.post(
        pds_host + "/xrpc/com.atproto.server.refreshSession",
        headers={"Authorization": "Bearer " + orig_session_token},
    ) as r:
        assert r.status != 200

    async with s.post(
        pds_host + "/xrpc/com.atproto.server.refreshSession",
        headers={"Authorization": "Bearer " + orig_refresh_token},
    ) as r:
        assert r.status == 200
        r = await r.json()
        new_session_token = r["accessJwt"]
        new_refresh_token = r["refreshJwt"]

    async with s.get(
        pds_host + "/xrpc/com.atproto.server.getSession",
        headers={"Authorization": "Bearer " + new_session_token},
    ) as r:
        assert r.status == 200
        await r.json()

    async with s.get(
        pds_host + "/xrpc/com.atproto.server.getSession",
        headers={"Authorization": "Bearer " + orig_session_token},
    ) as r:
        assert r.status != 200

    async with s.post(
        pds_host + "/xrpc/com.atproto.server.refreshSession",
        headers={"Authorization": "Bearer " + orig_refresh_token},
    ) as r:
        assert r.status != 200

async def test_deleteSession(s, pds_host):
    async with s.post(
        pds_host + "/xrpc/com.atproto.server.createSession",
        json=valid_logins[0],
    ) as r:
        assert r.status == 200
        r = await r.json()
        session_token = r["accessJwt"]
        refresh_token = r["refreshJwt"]

    async with s.get(
        pds_host + "/xrpc/com.atproto.server.getSession",
        headers={"Authorization": "Bearer " + session_token},
    ) as r:
        assert r.status == 200
        await r.json()

    async with s.post(
        pds_host + "/xrpc/com.atproto.server.deleteSession",
        headers={"Authorization": "Bearer " + session_token},
    ) as r:
        assert r.status != 200

    async with s.post(
        pds_host + "/xrpc/com.atproto.server.deleteSession",
        headers={"Authorization": "Bearer " + refresh_token},
    ) as r:
        assert r.status == 200

    async with s.get(
        pds_host + "/xrpc/com.atproto.server.getSession",
        headers={"Authorization": "Bearer " + session_token},
    ) as r:
        assert r.status != 200

    async with s.post(
        pds_host + "/xrpc/com.atproto.server.refreshSession",
        headers={"Authorization": "Bearer " + refresh_token},
    ) as r:
        assert r.status != 200

async def test_updateHandle(s, pds_host, auth_headers):
    async with s.post(
        pds_host + "/xrpc/com.atproto.identity.updateHandle",
        headers=auth_headers,
        json={ "handle": "juliet.test" },
    ) as r:
        assert r.status == 200

    async with s.get(
        pds_host + "/xrpc/com.atproto.repo.describeRepo",
        params={ "repo":  TEST_DID },
    ) as r:
        assert r.status == 200
        r = await r.json()
        assert r["handle"] == "juliet.test"