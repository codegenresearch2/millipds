from typing import Dict, Any
import logging
import hashlib
from aiohttp import web
import cbrrr
import apsw
import asyncio

from . import repo_ops
from .appview_proxy import service_proxy
from .auth_bearer import authenticated
from .app_util import *

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

async def apply_writes_and_emit_firehose(request: web.Request, req_json: Dict[str, Any]) -> Dict[str, Any]:
    if req_json["repo"] != request["authed_did"]:
        raise web.HTTPUnauthorized(text="not authed for that repo")
    res, firehose_seq, firehose_bytes = repo_ops.apply_writes(
        get_db(request),
        request["authed_did"],
        req_json["writes"],
        req_json.get("swapCommit"),
    )
    await firehose_broadcast(request, (firehose_seq, firehose_bytes))
    return res

@routes.post("/xrpc/com.atproto.repo.applyWrites")
@authenticated
async def repo_apply_writes(request: web.Request):
    return web.json_response(await apply_writes_and_emit_firehose(request, await request.json()))

@routes.post("/xrpc/com.atproto.repo.createRecord")
@authenticated
async def repo_create_record(request: web.Request):
    orig: Dict[str, Any] = await request.json()
    res = await apply_writes_and_emit_firehose(
        request,
        {
            "$type": "com.atproto.repo.applyWrites#create",
            "repo": orig["repo"],
            "validate": orig.get("validate"),
            "swapCommit": orig.get("swapCommit"),
            "writes": [
                {
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": orig["collection"],
                    "rkey": orig.get("rkey"),
                    "validate": orig.get("validate"),
                    "value": orig["record"],
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

# Similar modifications for repo_put_record and repo_delete_record functions

@routes.get("/xrpc/com.atproto.repo.describeRepo")
async def repo_describe_repo(request: web.Request):
    if "repo" not in request.query:
        raise web.HTTPBadRequest(text="missing repo")
    did_or_handle = request.query["repo"]
    with get_db(request).new_con(readonly=True) as con:
        user_id, did, handle = con.execute(
            "SELECT id, did, handle FROM user WHERE did=? OR handle=?",
            (did_or_handle, did_or_handle),
        ).fetchone()

        return web.json_response(
            {
                "handle": handle,
                "did": did,
                "didDoc": {},  # TODO
                "collections": [
                    row[0]
                    for row in con.execute(
                        "SELECT DISTINCT(nsid) FROM record WHERE repo=?",
                        (user_id,),
                    )  # TODO: is this query efficient? do we want an index?
                ],
                "handleIsCorrect": True,  # TODO
            }
        )

# Similar modifications for repo_get_record and repo_list_records functions

@routes.post("/xrpc/com.atproto.repo.uploadBlob")
@authenticated
async def repo_upload_blob(request: web.Request):
    mime = request.headers.get("content-type", "application/octet-stream")
    BLOCK_SIZE = 0x10000  # Comment about potential performance tweaks
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
        logger.info("uploaded blob already existed, dropping duplicate")

    return web.json_response(
        {
            "blob": {
                "type": "blob",
                "ref": {"$link": cid.encode()},
                "mimeType": mime,
                "size": length_read,
            }
        }
    )