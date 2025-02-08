import os\\nimport asyncio\\\\nimport tempfile\\\\nimport urllib.parse\\\\nimport unittest.mock\\\\nimport pytest\\\\nimport dataclasses\\\\nimport aiohttp\\\\nimport aiohttp.web\\\\n\\nfrom millipds import service\\\\\nfrom millipds import database\\\\\nfrom millipds import crypto\\\\n\\n@dataclasses.dataclass\\\\\nclass PDSInfo:\\\\\n    endpoint: str\\\\n    db: database.Database\\\\n\\nold_web_tcpsite_start = aiohttp.web.TCPSite.start\\\\\ndef make_capture_random_bound_port_web_tcpsite_startstart(queue: asyncio.Queue):\\\\\n    async def mock_start(site: aiohttp.web.TCPSite, *args, **kwargs):\\\\\n        nonlocal queue\\\\n        await old_web_tcpsite_start(site, *args, **kwargs)\\\\n        await queue.put(site._server.sockets[0].getsockname()[1])\\\\n    return mock_start\\\\\n\\nasync def service_run_and_capture_port(queue: asyncio.Queue, **kwargs):\\\\\n    mock_start = make_capture_random_bound_port_web_tcpsite_startstart(queue)\\\\n    with unittest.mock.patch.object(aiohttp.web.TCPSite, "start", new=mock_start):\\\\n        await service.run(**kwargs)\\\\n\\nif 0:\\n    TEST_DID = "did:web:alice.test"\\n    TEST_HANDLE = "alice.test"\\n    TEST_PASSWORD = "alice_pw"\\nelse:\\n    TEST_DID = "did:plc:bwxddkvw5c6pkkntbtp2j4lx"\\n    TEST_HANDLE = "local.dev.retr0.id"\\n    TEST_PASSWORD = "lol"\\nTEST_PRIVKEY = crypto.keygen_p256()\\n\\n@pytest.fixture\\\\nasync def test_pds(aiolib):\\\\n    queue = asyncio.Queue()\\\\n    with tempfile.TemporaryDirectory() as tempdir:\\\\n        async with aiohttp.ClientSession() as client:\\\\n            db_path = f"{tempdir}/millipds-0000.db"\\n            db = database.Database(path=db_path)\\\\n\\n            hostname = "localhost:0"\\n            db.update_config(\\\n                pds_pfx=f"http://{hostname}",\\n                pds_did=f"did:web:{urllib.parse.quote(hostname)}",\\n                bsky_appview_pfx="https://api.bsky.app",\\n                bsky_appview_did="did:web:api.bsky.app",\\n            )\\\n\\n            service_run_task = asyncio.create_task(\\\n                service_run_and_capture_port(\\\n                    queue,\\\\\n                    db=db,\\\\\n                    client=client,\\\\\n                    sock_path=None,\\\\\n                    host="localhost",\\n                    port=0,\\\\\n                )\\n            )\\\n            queue_get_task = asyncio.create_task(queue.get())\\\\n            done, pending = await asyncio.wait(\\\n                (queue_get_task, service_run_task),\\\\\n                return_when=asyncio.FIRST_COMPLETED,\\\\\n            )\\\n            if done == service_run_task:\\\\\n                raise service_run_task.execption()\\n            else:\\\\\n                port = queue_get_task.result()\\n\\n            hostname = f"localhost:{port}"\\n            db.update_config(\\\n                pds_pfx=f"http://{hostname}",\\n                pds_did=f"did:web:{urllib.parse.quote(hostname)}",\\n                bsky_appview_pfx="https://api.bsky.app",\\n                bsky_appview_did="did:web:api.bsky.app",\\n            )\\\n            db.create_account(\\\n                did=TEST_DID,\\\\\n                handle=TEST_HANDLE,\\\\\n                password=TEST_PASSWORD,\\\\\n                privkey=TEST_PRIVKEY,\\\\\n            )\\\n\\n            try:\\\\\n                yield PDSInfo(\\\n                    endpoint=f"http://{hostname}",\\n                    db=db,\\\\\n                )\\\n            finally:\\\\\n                db.con.close()\\n                service_run_task.cancel()\\n                try:\\\\\n                    await service_run_task\\n                except asyncio.CancelledError:\\n                    pass\\n\\n@pytest.fixture\\\\nasync def s(aiolib):\\\\n    async with aiohttp.ClientSession() as s:\\\\n        yield s\\n\\n@pytest.fixture\\\\ndef pds_host(test_pds) -> str:\\\\n    return test_pds.endpoint\\n\\nasync def test_hello_world(s, pds_host):\\\\n    async with s.get(pds_host + "/") as r:\\\\n        r = await r.text()\\n        print(r)\\\\\\n        assert "Hello" in r\\n\\nasync def test_describeServer(s, pds_host):\\\\n    async with s.get(pds_host + "/xrpc/com.atproto.server.describeServer") as r:\\\\n        print(await r.json())\\\\\n\\nasync def test_createSession_no_args(s, pds_host):\\\\n    # no args\\\\\n    async with s.post(pds_host + "/xrpc/com.atproto.server.createSession") as r:\\\\n        assert r.status != 200\\n\\ninvalid_logins = [\\\\\n    {"identifier": [], "password": TEST_PASSWORD},\\\\\n    {"identifier": "example.invalid", "password": "wrongPassword123"},\\\\\n    {"identifier": TEST_HANDLE, "password": "wrongPassword123"}\\\\\n]\\\\\n\\n@pytest.mark.parametrize("login_data", invalid_logins)\\\\nasync def test_invalid_logins(s, pds_host, login_data):\\\\n    async with s.post(\\\n        pds_host + "/xrpc/com.atproto.server.createSession",\\n        json=login_data\\n    ) as r:\\\\n        assert r.status != 200\\n\\nvalid_logins = [\\\\\n    {"identifier": TEST_HANDLE, "password": TEST_PASSWORD},\\\\\n    {"identifier": TEST_DID, "password": TEST_PASSWORD}\\\\\n]\\\\\n\\n@pytest.mark.parametrize("login_data", valid_logins)\\\\nasync def test_valid_logins(s, pds_host, login_data):\\\\n    async with s.post(\\\n        pds_host + "/xrpc/com.atproto.server.createSession",\\n        json=login_data\\n    ) as r:\\\\n        r = await r.json()\\n        assert r["did"] == TEST_DID\\n        assert r["handle"] == TEST_HANDLE\\n        assert "accessJwt" in r\\n        assert "refreshJwt" in r\\\\n\\n        token = r["accessJwt"]\\n        auth_headers = {"Authorization": "Bearer " + token}\\\\\n\\n        # good auth\\\\\n        async with s.get(\\\n            pds_host + "/xrpc/com.atproto.server.getSession",\\n            headers=auth_headers\\n        ) as r:\\\\n            print(await r.json())\\\\\\n            assert r.status == 200\\\\n\\n        # bad auth\\\\\n        async with s.get(\\\n            pds_host + "/xrpc/com.atproto.server.getSession",\\n            headers={"Authorization": "Bearer " + token[:-1]}\\\\\n        ) as r:\\\\n            print(await r.text())\\\\\\n            assert r.status != 200\\\\n\\n        # bad auth\\\\\n        async with s.get(\\\n            pds_host + "/xrpc/com.atproto.server.getSession",\\n            headers={"Authorization": "Bearest"}\\\\\n        ) as r:\\\\n            print(await r.text())\\\\\\n            assert r.status != 200\\n\\nasync def test_sync_getRepo(s, pds_host):\\\\n    async with s.get(\\\n        pds_host + "/xrpc/com.atproto.sync.getRepo",\\n        params={"did": TEST_DID}\\\\\n    ) as r:\\\\n        assert r.status == 200\\n\\n@pytest.fixture\\\\nasync def auth_headers(s, pds_host):\\\\n    async with s.post(\\\n        pds_host + "/xrpc/com.atproto.server.createSession",\\n        json=valid_logins[0]\\\\\n    ) as r:\\\\n        r = await r.json()\\n        token = r["accessJwt"]\\n        return {"Authorization": "Bearer " + token}\\\\\n\\n@pytest.fixture\\\\nasync def populated_pds_host(s, pds_host, auth_headers):\\\\n    # same thing as test_repo_applyWrites, for now\\\\\n    for i in range(10):\\\\\n        async with s.post(\\\n            pds_host + "/xrpc/com.atproto.repo.applyWrites",\\n            headers=auth_headers,\\\n            json={\\\n                "repo": TEST_DID,\\\\\n                "writes": [\\\\\n                    {\\\n                        "$type": "com.atproto.repo.applyWrites#create",\\n                        "action": "create",\\n                        "collection": "app.bsky.feed.like",\\n                        "rkey": f"{i}-{j}",\\n                        "value": {\"blah": "test record"},\\\\\n                    }\\n                    for j in range(30)\\\\\n                ],\\\n            }\\n        ) as r:\\\\n            print(await r.json())\\\\\\n            assert r.status == 200\\n    return pds_host\\\\n\\nasync def test_repo_applyWrites(s, pds_host, auth_headers):\\\\n    # TODO: test more than just "create"!\\\\\n    for i in range(10):\\\\\n        async with s.post(\\\n            pds_host + "/xrpc/com.atproto.repo.applyWrites",\\n            headers=auth_headers,\\\n            json={\\\n                "repo": TEST_DID,\\\\\n                "writes": [\\\\\n                    {\\\n                        "$type": "com.atproto.repo.applyWrites#create",\\n                        "action": "create",\\n                        "collection": "app.bsky.feed.like",\\n                        "rkey": f"{i}-{j}",\\n                        "value": {\"blah": "test record"},\\\\\n                    }\\n                    for j in range(30)\\\\\n                ],\\\n            }\\n        ) as r:\\\\n            print(await r.json())\\\\\\n            assert r.status == 200\\n\\nasync def test_repo_uploadBlob(s, pds_host, auth_headers):\\\\n    blob = os.urandom(0x100000)\\\\\n    for _ in range(2):  # test reupload is nop\\\\\n        async with s.post(\\\n            pds_host + "/xrpc/com.atproto.repo.uploadBlob",\\n            headers=auth_headers | {"content-type": "blah"},\\\\\n            data=blob\\n        ) as r:\\\\n            res = await r.json()\\n            print(res)\\\\\\n            assert r.status == 200\\n\\n        # getBlob should still 404 because refcount==0\\\\\n        async with s.get(\\\n            pds_host + "/xrpc/com.atproto.sync.getBlob",\\n            params={"did": TEST_DID, "cid": res["blob"]["ref"]["$link"]}\\\\\n        ) as r:\\\\n            assert r.status == 404\\n\\n        # get the blob refcount >0\\\\\n        async with s.post(\\\n            pds_host + "/xrpc/com.atproto.repo.createRecord",\\n            headers=auth_headers,\\\n            json={\\\n                "repo": TEST_DID,\\\\\n                "collection": "app.bsky.feed.post",\\n                "record": {\"myblob": res}\\\\\n            }\\n        ) as r:\\\\n            print(await r.json())\\\\\\n            assert r.status == 200\\n\\n        async with s.get(\\\n            pds_host + "/xrpc/com.atproto.sync.getBlob",\\n            params={"did": TEST_DID, "cid": res["blob"]["ref"]["$link"]}\\\\\n        ) as r:\\\\n            downloaded_blob = await r.read()\\n            assert downloaded_blob == blob\\n\\n        async with s.get(\\\n            pds_host + "/xrpc/com.atproto.sync.getRepo",\\n            params={"did": TEST_DID}\\\\\n        ) as r:\\\\n            assert r.status == 200\\n            open("repo.car", "wb").write(await r.read())\\\\\n\\nasync def test_sync_getRepo_not_found(s, pds_host):\\\\n    async with s.get(\\\n        pds_host + "/xrpc/com.atproto.sync.getRepo",\\n        params={"did": "did:web:nonexistent.invalid"}\\\\\n    ) as r:\\\\n        assert r.status == 404\\n\\nasync def test_sync_getRecord_nonexistent(s, populated_pds_host):\\\\n    # nonexistent DID should still 404\\\\\n    async with s.get(\\\n        populated_pds_host + "/xrpc/com.atproto.sync.getRecord",\\n        params={\\\n            "did": "did:web:nonexistent.invalid",\\n            "collection": "app.bsky.feed.post",\\n            "rkey": "nonexistent"\\n        }\\n    ) as r:\\\\n        assert r.status == 404\\n\\n    # but extant DID with nonexistent record should 200, with exclusion proof CAR\\\\\n    async with s.get(\\\n        populated_pds_host + "/xrpc/com.atproto.sync.getRecord",\\n        params={\\\n            "did": TEST_DID,\n            "collection": "app.bsky.feed.post",\\n            "rkey": "nonexistent"\\n        }\\n    ) as r:\\\\n        assert r.status == 200\\n        assert r.content_type == "application/vnd.ipld.car"\\n        proof_car = await r.read()\\n        assert proof_car  # nonempty\\n        # TODO: make sure the proof is valid\\\\\n        assert b"test record" in proof_car\\n\\nasync def test_sync_getRecord_existent(s, populated_pds_host):\\\\n    async with s.get(\\\n        populated_pds_host + "/xrpc/com.atproto.sync.getRecord",\\n        params={\\\n            "did": TEST_DID,\n            "collection": "app.bsky.feed.like",\\n            "rkey": "1-1"\\n        }\\n    ) as r:\\\\n        assert r.status == 200\\n        assert r.content_type == "application/vnd.ipld.car"\\n        proof_car = await r.read()\\n        assert proof_car  # nonempty\\n        # TODO: make sure the proof is valid, and contains the record\\\\\n        assert b"test record" in proof_car\\\\n