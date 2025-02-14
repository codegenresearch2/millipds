from typing import Optional, Tuple
import logging
import asyncio
import json

from aiohttp import web
import cbrrr

from . import static_config
from . import repo_ops
from . import util
from .app_util import *

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

@routes.get("/xrpc/com.atproto.sync.getBlob")
async def sync_get_blob(request: web.Request):
    with get_db(request).new_con(readonly=True) as con:
        cursor = con.execute(
            "SELECT blob.id FROM blob INNER JOIN user ON blob.repo=user.id WHERE did=? AND cid=? AND refcount>0",
            (
                request.query["did"],
                bytes(cbrrr.CID.decode(request.query["cid"])),
            ),
        )
        blob_id = cursor.fetchone()
        cursor.close()

        if blob_id is None:
            raise web.HTTPNotFound(text="blob not found")

        res = web.StreamResponse(
            headers={
                "Content-Disposition": f'attachment; filename="{request.query["cid"]}.bin"'
            }
        )
        res.content_type = "application/octet-stream"
        await res.prepare(request)

        # Using a context manager to ensure the cursor is closed after use
        with con.execute(
            "SELECT data FROM blob_part WHERE blob=? ORDER BY idx",
            (blob_id[0],),
        ) as blob_parts:
            for blob_part, *_ in blob_parts:
                await res.write(blob_part)

        await res.write_eof()
        return res

# TODO: this is mostly untested!!!
@routes.get("/xrpc/com.atproto.sync.getBlocks")
async def sync_get_blocks(request: web.Request):
    did = request.query.get("did")
    if did is None:
        raise web.HTTPBadRequest(text="no did specified")

    try:
        cids = [
            bytes(cbrrr.CID.decode(cid)) for cid in request.query.getall("cids")
        ]
    except ValueError:
        raise web.HTTPBadRequest(text="invalid cid")

    db = get_db(request)
    cursor = db.con.execute("SELECT id FROM user WHERE did=?", (did,))
    user_id = cursor.fetchone()
    cursor.close()

    if user_id is None:
        raise web.HTTPNotFound(text="did not found")

    res = web.StreamResponse()
    res.content_type = "application/vnd.ipld.car"
    await res.prepare(request)
    await res.write(util.serialize_car_header())

    for cid in cids:
        cursor = db.con.execute(
            """\n                SELECT commit_bytes FROM user WHERE head=? AND id=?\n                UNION SELECT value FROM mst WHERE cid=? AND repo=?\n                UNION SELECT value FROM record WHERE cid=? AND repo=?\n            """,
            (cid, user_id[0]) * 3,
        )
        row = cursor.fetchone()
        cursor.close()

        if row is None:
            continue  # hmm, we can't 404 because we already send the response headers\n\n        await res.write(util.serialize_car_entry(cid, row[0]))\n\n    await res.write_eof()\n    return res\n\n@routes.get("/xrpc/com.atproto.sync.getLatestCommit")\nasync def sync_get_latest_commit(request: web.Request):\n    did = request.query.get("did")\n    if did is None:\n        raise web.HTTPBadRequest(text="no did specified")\n\n    cursor = get_db(request).con.execute("SELECT rev, head FROM user WHERE did=?", (did,))\n    row = cursor.fetchone()\n    cursor.close()\n\n    if row is None:\n        raise web.HTTPNotFound(text="did not found")\n\n    rev, head = row\n    return web.json_response({"cid": cbrrr.CID(head).encode(), "rev": rev})\n\n@routes.get("/xrpc/com.atproto.sync.getRecord")\nasync def sync_get_record(request: web.Request):\n    if "did" not in request.query:\n        raise web.HTTPBadRequest(text="missing did")\n    if "collection" not in request.query:\n        raise web.HTTPBadRequest(text="missing collection")\n    if "rkey" not in request.query:\n        raise web.HTTPBadRequest(text="missing rkey")\n\n    # we don't stream the response because it should be compact-ish
    car = repo_ops.get_record(
        get_db(request),
        request.query["did"],
        request.query["collection"] + "/" + request.query["rkey"],
    )

    if car is None:
        raise web.HTTPNotFound(text="did not found")

    return web.Response(body=car, content_type="application/vnd.ipld.car")

@routes.get("/xrpc/com.atproto.sync.getRepoStatus")
async def sync_get_repo_status(request: web.Request):
    did = request.query.get("did")
    if did is None:
        raise web.HTTPBadRequest(text="no did specified")

    cursor = get_db(request).con.execute("SELECT rev FROM user WHERE did=?", (did,))
    row = cursor.fetchone()
    cursor.close()

    if row is None:
        raise web.HTTPNotFound(text="did not found")

    return web.json_response({"did": did, "active": True, "rev": row[0]})

@routes.get("/xrpc/com.atproto.sync.getRepo")
async def sync_get_repo(request: web.Request):
    did = request.query.get("did")
    if did is None:
        raise web.HTTPBadRequest(text="no did specified")

    since = request.query.get("since", "")

    with get_db(request).new_con(readonly=True) as con:
        cursor = con.execute("SELECT id, head, commit_bytes FROM user WHERE did=?", (did,))
        try:
            user_id, head, commit_bytes = cursor.fetchone()
        except TypeError:  # from trying to unpack None
            raise web.HTTPNotFound(text="repo not found")
        finally:
            cursor.close()

        res = web.StreamResponse()
        res.content_type = "application/vnd.ipld.car"
        await res.prepare(request)
        await res.write(util.serialize_car_header(head))
        await res.write(util.serialize_car_entry(head, commit_bytes))

        cursor = con.execute("SELECT cid, value FROM mst WHERE repo=? AND since>?", (user_id, since))
        for mst_cid, mst_value in cursor:
            await res.write(util.serialize_car_entry(mst_cid, mst_value))
        cursor.close()

        cursor = con.execute("SELECT cid, value FROM record WHERE repo=? AND since>?", (user_id, since))
        for record_cid, record_value in cursor:
            await res.write(util.serialize_car_entry(record_cid, record_value))
        cursor.close()

    await res.write_eof()
    return res

@routes.get("/xrpc/com.atproto.sync.listBlobs")
async def sync_list_blobs(request: web.Request):
    did = request.query.get("did")
    if did is None:
        raise web.HTTPBadRequest(text="no did specified")

    since = request.query.get("since", "")
    limit = int(request.query.get("limit", 500))
    if limit < 1 or limit > 1000:
        raise web.HTTPBadRequest(text="limit out of range")

    cursor = int(request.query.get("cursor", 0))

    cids = []
    cursor = get_db(request).con.execute(
        "SELECT blob.id, cid FROM blob INNER JOIN user ON blob.repo=user.id WHERE did=? AND refcount>0 AND since>? AND blob.id>? ORDER BY blob.id LIMIT ?",
        (did, since, cursor, limit),
    )
    for id_, cid in cursor:
        cids.append(cbrrr.CID(cid).encode())
    cursor.close()

    response_data = {"cids": cids}
    if len(cids) == limit:
        response_data["cursor"] = id_

    return web.json_response(response_data)

@routes.get("/xrpc/com.atproto.sync.listRepos")
async def sync_list_repos(request: web.Request):
    repos = []
    cursor = get_db(request).con.execute("SELECT did, head, rev FROM user")
    for did, head, rev in cursor:
        repos.append({
            "did": did,
            "head": head.encode("base32"),
            "rev": rev,
            "active": True,
        })
    cursor.close()

    return web.json_response({"repos": repos})

TOOSLOW_MSG = cbrrr.encode_dag_cbor({"op": -1}) + cbrrr.encode_dag_cbor(
    {"error": "ConsumerTooSlow", "message": "you're not reading my events fast enough :("}
)

FUTURECURSOR_MSG = cbrrr.encode_dag_cbor({"op": -1}) + cbrrr.encode_dag_cbor(
    {"error": "FutureCursor", "message": "woah, are you from the future?"}
)

@routes.get("/xrpc/com.atproto.sync.subscribeRepos")
async def sync_subscribe_repos(request: web.Request):
    logger.info(
        f"NEW FIREHOSE CLIENT {request.remote} {request.headers.get('x-forwarded-for')} {json.dumps(request.query)}"
    )
    ws = web.WebSocketResponse()
    try:
        await ws.prepare(request)

        last_sent_seq = None
        if "cursor" in request.query:
            cursor = int(request.query["cursor"])
            db = get_db(request)
            while True:
                cursor = db.con.execute(
                    "SELECT seq, msg FROM firehose WHERE seq>? ORDER BY seq LIMIT 1",
                    (cursor,),
                )
                row = cursor.fetchone()
                cursor.close()

                if row is None:
                    break

                cursor, msg = row
                await ws.send_bytes(msg)
                last_sent_seq = cursor

            if last_sent_seq is None:
                cursor = db.con.execute("SELECT IFNULL(MAX(seq), 0) FROM firehose")
                current_seq = cursor.fetchone()[0]
                cursor.close()

                if cursor > current_seq:
                    await ws.send_bytes(FUTURECURSOR_MSG)
                    await ws.close()
                    return ws
    except ConnectionResetError:
        await ws.close()
        return ws

    queue: asyncio.Queue[Optional[Tuple[int, bytes]]] = asyncio.Queue(
        static_config.FIREHOSE_QUEUE_SIZE
    )
    async with get_firehose_queues_lock(request):
        get_firehose_queues(request).add(queue)

    try:
        while True:
            msg = await queue.get()
            if msg is None:
                await ws.send_bytes(TOOSLOW_MSG)
                break

            seq, msg_bytes = msg
            await ws.send_bytes(msg_bytes)
    except ConnectionResetError:
        pass
    finally:
        async with get_firehose_queues_lock(request):
            get_firehose_queues(request).discard(queue)

    await ws.close()
    return ws