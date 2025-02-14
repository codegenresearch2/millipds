from typing import Tuple
import logging
import hashlib

from aiohttp import web
import cbrrr
import apsw
import asyncio

from . import repo_ops
from .appview_proxy import service_proxy
from .auth_bearer import authenticated
from .app_util import get_db, get_firehose_queues_lock, get_firehose_queues

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

async def firehose_broadcast(request: web.Request, msg: Tuple[int, bytes]):
    async with get_firehose_queues_lock(request):
        queues_to_remove = set()
        active_queues = get_firehose_queues(request)
        for queue in active_queues:
            try:
                queue.put_nowait(msg)
            except asyncio.QueueFull:
                while not queue.empty():
                    queue.get_nowait()
                queue.put_nowait(None)
                queues_to_remove.add(queue)
        active_queues -= queues_to_remove

async def apply_writes_and_emit_firehose(request: web.Request, req_json: dict) -> dict:
    if req_json.get("repo") != request.get("authed_did"):
        raise web.HTTPUnauthorized(text="not authed for that repo")
    repo = req_json.get("repo")
    writes = req_json.get("writes")
    swap_commit = req_json.get("swapCommit")
    if not repo or not writes:
        raise web.HTTPBadRequest(text="missing required parameters")
    try:
        res, firehose_seq, firehose_bytes = repo_ops.apply_writes(get_db(request), repo, writes, swap_commit)
    except Exception as e:
        raise web.HTTPBadRequest(text=str(e))
    await firehose_broadcast(request, (firehose_seq, firehose_bytes))
    return res

@routes.post("/xrpc/com.atproto.repo.applyWrites")
@authenticated
async def repo_apply_writes(request: web.Request):
    return web.json_response(await apply_writes_and_emit_firehose(request, await request.json()))

@routes.post("/xrpc/com.atproto.repo.createRecord")
@authenticated
async def repo_create_record(request: web.Request):
    orig: dict = await request.json()
    repo = orig.get("repo")
    collection = orig.get("collection")
    record = orig.get("record")
    if not repo or not collection or not record:
        raise web.HTTPBadRequest(text="missing required parameters")
    res = await apply_writes_and_emit_firehose(request, {
        "repo": repo,
        "validate": orig.get("validate"),
        "swapCommit": orig.get("swapCommit"),
        "writes": [{
            "collection": collection,
            "rkey": orig.get("rkey"),
            "validate": orig.get("validate"),
            "value": record,
            "$type": "com.atproto.repo.applyWrites#create"
        }]
    })
    return web.json_response({
        "commit": res["commit"],
        "uri": res["results"][0]["uri"],
        "cid": res["results"][0]["cid"],
        "validationStatus": res["results"][0]["validationStatus"]
    })

@routes.post("/xrpc/com.atproto.repo.putRecord")
@authenticated
async def repo_put_record(request: web.Request):
    orig: dict = await request.json()
    repo = orig.get("repo")
    collection = orig.get("collection")
    rkey = orig.get("rkey")
    record = orig.get("record")
    if not repo or not collection or not rkey or not record:
        raise web.HTTPBadRequest(text="missing required parameters")
    res = await apply_writes_and_emit_firehose(request, {
        "repo": repo,
        "validate": orig.get("validate"),
        "swapCommit": orig.get("swapCommit"),
        "writes": [{
            "collection": collection,
            "rkey": rkey,
            "validate": orig.get("validate"),
            "swapRecord": orig.get("swapRecord"),
            "value": record,
            "$type": "com.atproto.repo.applyWrites#update"
        }]
    })
    return web.json_response({
        "commit": res["commit"],
        "uri": res["results"][0]["uri"],
        "cid": res["results"][0]["cid"],
        "validationStatus": res["results"][0]["validationStatus"]
    })

@routes.post("/xrpc/com.atproto.repo.deleteRecord")
@authenticated
async def repo_delete_record(request: web.Request):
    orig: dict = await request.json()
    repo = orig.get("repo")
    collection = orig.get("collection")
    rkey = orig.get("rkey")
    if not repo or not collection or not rkey:
        raise web.HTTPBadRequest(text="missing required parameters")
    res = await apply_writes_and_emit_firehose(request, {
        "repo": repo,
        "validate": orig.get("validate"),
        "swapCommit": orig.get("swapCommit"),
        "writes": [{
            "collection": collection,
            "rkey": rkey,
            "validate": orig.get("validate"),
            "swapRecord": orig.get("swapRecord"),
            "$type": "com.atproto.repo.applyWrites#delete"
        }]
    })
    return web.json_response({"commit": res["commit"]})

@routes.get("/xrpc/com.atproto.repo.describeRepo")
async def repo_describe_repo(request: web.Request):
    repo = request.query.get("repo")
    if not repo:
        raise web.HTTPBadRequest(text="missing required parameter: repo")
    with get_db(request).new_con(readonly=True) as con:
        user_id, did, handle = con.execute(
            "SELECT id, did, handle FROM user WHERE did=? OR handle=?",
            (repo, repo)
        ).fetchone()
        if not user_id:
            raise web.HTTPNotFound(text="repo not found")
        collections = [row[0] for row in con.execute(
            "SELECT DISTINCT(nsid) FROM record WHERE repo=?",
            (user_id,)
        )]
        return web.json_response({
            "handle": handle,
            "did": did,
            "didDoc": {},  # TODO
            "collections": collections,
            "handleIsCorrect": True  # TODO
        })

@routes.get("/xrpc/com.atproto.repo.getRecord")
async def repo_get_record(request: web.Request):
    repo = request.query.get("repo")
    collection = request.query.get("collection")
    rkey = request.query.get("rkey")
    cid_in = request.query.get("cid")
    if not repo or not collection or not rkey:
        raise web.HTTPBadRequest(text="missing required parameters")
    db = get_db(request)
    row = db.con.execute(
        "SELECT cid, value FROM record WHERE repo=(SELECT id FROM user WHERE did=? OR handle=?) AND nsid=? AND rkey=?",
        (repo, repo, collection, rkey)
    ).fetchone()
    if row is None:
        return await service_proxy(request)
    cid_out, value = row
    cid_out = cbrrr.CID(cid_out)
    if cid_in is not None:
        if cbrrr.CID.decode(cid_in) != cid_out:
            raise web.HTTPNotFound(text="record not found with matching CID")
    return web.json_response({
        "uri": f"at://{repo}/{collection}/{rkey}",
        "cid": cid_out.encode(),
        "value": cbrrr.decode_dag_cbor(value, atjson_mode=True)
    })

@routes.get("/xrpc/com.atproto.repo.listRecords")
async def repo_list_records(request: web.Request):
    repo = request.query.get("repo")
    collection = request.query.get("collection")
    limit = int(request.query.get("limit", 50))
    reverse = request.query.get("reverse") == "true"
    cursor = request.query.get("cursor", "" if reverse else "\xff")
    if not repo or not collection:
        raise web.HTTPBadRequest(text="missing required parameters")
    if limit < 1 or limit > 100:
        raise web.HTTPBadRequest(text="limit out of range")
    records = []
    db = get_db(request)
    for rkey, cid, value in db.con.execute(
        f"""\n            SELECT rkey, cid, value\n            FROM record\n            WHERE repo=(SELECT id FROM user WHERE did=? OR handle=?) AND nsid=? AND rkey{">" if reverse else "<"}?\n            ORDER BY rkey {"ASC" if reverse else "DESC"}\n            LIMIT ?\n        """,
        (repo, repo, collection, cursor, limit)
    ):
        records.append({
            "uri": f"at://{repo}/{collection}/{rkey}",
            "cid": cbrrr.CID(cid).encode(),
            "value": cbrrr.decode_dag_cbor(value, atjson_mode=True)
        })
    response = {"records": records}
    if len(records) == limit:
        response["cursor"] = rkey
    return web.json_response(response)

@routes.post("/xrpc/com.atproto.repo.uploadBlob")
@authenticated
async def repo_upload_blob(request: web.Request):
    mime = request.headers.get("content-type", "application/octet-stream")
    BLOCK_SIZE = 0x10000
    db = get_db(request)
    db.con.execute("INSERT INTO blob (repo, refcount) VALUES ((SELECT id FROM user WHERE did=?), 0)", (request["authed_did"],))
    blob_id = db.con.last_insert_rowid()
    length_read = 0
    part_idx = 0
    hasher = hashlib.sha256()
    while True:
        try:
            chunk = await request.content.readexactly(BLOCK_SIZE)
        except asyncio.IncompleteReadError as e:
            chunk = e.partial
        if not chunk:
            break
        length_read += len(chunk)
        hasher.update(chunk)
        db.con.execute("INSERT INTO blob_part (blob, idx, data) VALUES (?, ?, ?)", (blob_id, part_idx, chunk))
        part_idx += 1
        if len(chunk) < BLOCK_SIZE:
            break
    digest = hasher.digest()
    cid = cbrrr.CID(cbrrr.CID.CIDV1_RAW_SHA256_32_PFX + digest)
    try:
        db.con.execute("UPDATE blob SET cid=? WHERE id=?", (bytes(cid), blob_id))
    except apsw.ConstraintError:
        db.con.execute("DELETE FROM blob_part WHERE blob=?", (blob_id,))
        db.con.execute("DELETE FROM blob WHERE id=?", (blob_id,))
        logger.info("uploaded blob already existed, dropping duplicate")
    return web.json_response({
        "blob": {
            "$type": "blob",
            "ref": {"$link": cid.encode()},
            "mimeType": mime,
            "size": length_read
        }
    })