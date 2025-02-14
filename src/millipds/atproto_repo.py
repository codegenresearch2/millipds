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
from .app_util import get_db, get_firehose_queues, get_firehose_queues_lock

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

async def handle_firehose_broadcast(request: web.Request, msg: Tuple[int, bytes]):
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

async def apply_writes_and_broadcast(request: web.Request, req_json: dict) -> dict:
    if req_json.get("repo") != request["authed_did"]:
        raise web.HTTPUnauthorized(text="Not authenticated for this repository")
    res, firehose_seq, firehose_bytes = repo_ops.apply_writes(
        get_db(request),
        request["authed_did"],
        req_json.get("writes", []),
        req_json.get("swapCommit"),
    )
    await handle_firehose_broadcast(request, (firehose_seq, firehose_bytes))
    return res

@routes.post("/xrpc/com.atproto.repo.applyWrites")
@authenticated
async def repo_apply_writes(request: web.Request):
    return web.json_response(
        await apply_writes_and_broadcast(request, await request.json())
    )

@routes.post("/xrpc/com.atproto.repo.createRecord")
@authenticated
async def repo_create_record(request: web.Request):
    req_data = await request.json()
    if not all(key in req_data for key in ["repo", "collection", "record"]):
        raise web.HTTPBadRequest(text="Missing required parameters")
    res = await apply_writes_and_broadcast(
        request,
        {
            "repo": req_data["repo"],
            "validate": req_data.get("validate"),
            "swapCommit": req_data.get("swapCommit"),
            "writes": [
                {
                    "collection": req_data["collection"],
                    "rkey": req_data.get("rkey"),
                    "validate": req_data.get("validate"),
                    "value": req_data["record"],
                    "$type": "com.atproto.repo.applyWrites#create",
                }
            ],
        },
    )
    return web.json_response(
        {
            "commit": res["commit"],
            "uri": res["results"][0]["uri"],
            "cid": res["results"][0]["cid"],
            "validationStatus": res["results"][0]["validationStatus"],
        }
    )

@routes.post("/xrpc/com.atproto.repo.putRecord")
@authenticated
async def repo_put_record(request: web.Request):
    req_data = await request.json()
    if not all(key in req_data for key in ["repo", "collection", "rkey", "record"]):
        raise web.HTTPBadRequest(text="Missing required parameters")
    res = await apply_writes_and_broadcast(
        request,
        {
            "repo": req_data["repo"],
            "validate": req_data.get("validate"),
            "swapCommit": req_data.get("swapCommit"),
            "writes": [
                {
                    "collection": req_data["collection"],
                    "rkey": req_data["rkey"],
                    "validate": req_data.get("validate"),
                    "swapRecord": req_data.get("swapRecord"),
                    "value": req_data["record"],
                    "$type": "com.atproto.repo.applyWrites#update",
                }
            ],
        },
    )
    return web.json_response(
        {
            "commit": res["commit"],
            "uri": res["results"][0]["uri"],
            "cid": res["results"][0]["cid"],
            "validationStatus": res["results"][0]["validationStatus"],
        }
    )

@routes.post("/xrpc/com.atproto.repo.deleteRecord")
@authenticated
async def repo_delete_record(request: web.Request):
    req_data = await request.json()
    if not all(key in req_data for key in ["repo", "collection", "rkey"]):
        raise web.HTTPBadRequest(text="Missing required parameters")
    res = await apply_writes_and_broadcast(
        request,
        {
            "repo": req_data["repo"],
            "validate": req_data.get("validate"),
            "swapCommit": req_data.get("swapCommit"),
            "writes": [
                {
                    "collection": req_data["collection"],
                    "rkey": req_data["rkey"],
                    "validate": req_data.get("validate"),
                    "swapRecord": req_data.get("swapRecord"),
                    "$type": "com.atproto.repo.applyWrites#delete",
                }
            ],
        },
    )
    return web.json_response({"commit": res["commit"]})

@routes.get("/xrpc/com.atproto.repo.describeRepo")
async def repo_describe_repo(request: web.Request):
    repo = request.query.get("repo")
    if not repo:
        raise web.HTTPBadRequest(text="Missing repository parameter")
    with get_db(request).new_con(readonly=True) as con:
        user_id, did, handle = con.execute(
            "SELECT id, did, handle FROM user WHERE did=? OR handle=?",
            (repo, repo),
        ).fetchone()
        if not user_id:
            raise web.HTTPNotFound(text="Repository not found")
        collections = [
            row[0]
            for row in con.execute(
                "SELECT DISTINCT(nsid) FROM record WHERE repo=?",
                (user_id,),
            )
        ]
        return web.json_response(
            {
                "handle": handle,
                "did": did,
                "didDoc": {},
                "collections": collections,
                "handleIsCorrect": True,
            }
        )

@routes.get("/xrpc/com.atproto.repo.getRecord")
async def repo_get_record(request: web.Request):
    repo = request.query.get("repo")
    collection = request.query.get("collection")
    rkey = request.query.get("rkey")
    cid_in = request.query.get("cid")
    if not all([repo, collection, rkey]):
        raise web.HTTPBadRequest(text="Missing required parameters")
    db = get_db(request)
    row = db.con.execute(
        "SELECT cid, value FROM record WHERE repo=(SELECT id FROM user WHERE did=? OR handle=?) AND nsid=? AND rkey=?",
        (repo, repo, collection, rkey),
    ).fetchone()
    if row is None:
        return await service_proxy(request)
    cid_out, value = row
    cid_out = cbrrr.CID(cid_out)
    if cid_in is not None and cbrrr.CID.decode(cid_in) != cid_out:
        raise web.HTTPNotFound(text="Record not found with matching CID")
    return web.json_response(
        {
            "uri": f"at://{repo}/{collection}/{rkey}",
            "cid": cid_out.encode(),
            "value": cbrrr.decode_dag_cbor(value, atjson_mode=True),
        }
    )

@routes.get("/xrpc/com.atproto.repo.listRecords")
async def repo_list_records(request: web.Request):
    repo = request.query.get("repo")
    collection = request.query.get("collection")
    if not all([repo, collection]):
        raise web.HTTPBadRequest(text="Missing required parameters")
    limit = int(request.query.get("limit", 50))
    if limit < 1 or limit > 100:
        raise web.HTTPBadRequest(text="Limit out of range")
    reverse = request.query.get("reverse") == "true"
    cursor = request.query.get("cursor", "" if reverse else "\xff")
    records = []
    db = get_db(request)
    for rkey, cid, value in db.con.execute(
        f"""\n            SELECT rkey, cid, value\n            FROM record\n            WHERE repo=(SELECT id FROM user WHERE did=? OR handle=?)\n                AND nsid=? AND rkey{">" if reverse else "<"}?\n            ORDER BY rkey {"ASC" if reverse else "DESC"}\n            LIMIT ?\n        """,
        (repo, repo, collection, cursor, limit),
    ):
        records.append(
            {
                "uri": f"at://{repo}/{collection}/{rkey}",
                "cid": cbrrr.CID(cid).encode(),
                "value": cbrrr.decode_dag_cbor(value, atjson_mode=True),
            }
        )
    return web.json_response(
        {"records": records} | ({"cursor": rkey} if len(records) == limit else {})
    )

@routes.post("/xrpc/com.atproto.repo.uploadBlob")
@authenticated
async def repo_upload_blob(request: web.Request):
    mime = request.headers.get("content-type", "application/octet-stream")
    BLOCK_SIZE = 0x10000
    db = get_db(request)
    db.con.execute(
        "INSERT INTO blob (repo, refcount) VALUES ((SELECT id FROM user WHERE did=?), 0)",
        (request["authed_did"],),
    )
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
        db.con.execute(
            "INSERT INTO blob_part (blob, idx, data) VALUES (?, ?, ?)",
            (blob_id, part_idx, chunk),
        )
        part_idx += 1
        if len(chunk) < BLOCK_SIZE:
            break
    digest = hasher.digest()
    cid = cbrrr.CID(cbrrr.CID.CIDV1_RAW_SHA256_32_PFX + digest)
    try:
        db.con.execute(
            "UPDATE blob SET cid=? WHERE id=?", (bytes(cid), blob_id)
        )
    except apsw.ConstraintError:
        db.con.execute(
            "DELETE FROM blob_part WHERE blob=?", (blob_id,)
        )
        db.con.execute("DELETE FROM blob WHERE id=?", (blob_id,))
        logger.info("Uploaded blob already existed, dropping duplicate")
    return web.json_response(
        {
            "blob": {
                "ref": {"$link": cid.encode()},
                "mimeType": mime,
                "size": length_read,
                "$type": "blob",
            }
        }
    )