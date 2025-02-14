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

# Function to broadcast firehose messages to all active queues
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

# Function to apply writes and emit firehose events
async def apply_writes_and_emit_firehose(request: web.Request, req_json: dict) -> dict:
    # Ensure the authenticated user is authorized for the repository
    if req_json["repo"] != request["authed_did"]:
        raise web.HTTPUnauthorized(text="Not authenticated for this repository")

    # Apply writes to the repository and get the result, firehose sequence, and firehose bytes
    result, firehose_seq, firehose_bytes = repo_ops.apply_writes(
        get_db(request),
        request["authed_did"],
        req_json["writes"],
        req_json.get("swapCommit"),
    )

    # Broadcast the firehose message to all active queues
    await firehose_broadcast(request, (firehose_seq, firehose_bytes))

    return result

# Route to apply writes to a repository
@routes.post("/xrpc/com.atproto.repo.applyWrites")
@authenticated
async def repo_apply_writes(request: web.Request):
    return web.json_response(
        await apply_writes_and_emit_firehose(request, await request.json())
    )

# Route to create a record in a repository
@routes.post("/xrpc/com.atproto.repo.createRecord")
@authenticated
async def repo_create_record(request: web.Request):
    original_request = await request.json()
    result = await apply_writes_and_emit_firehose(
        request,
        {
            "repo": original_request["repo"],
            "validate": original_request.get("validate"),
            "swapCommit": original_request.get("swapCommit"),
            "writes": [
                {
                    "collection": original_request["collection"],
                    "rkey": original_request.get("rkey"),
                    "validate": original_request.get("validate"),
                    "value": original_request["record"],
                    "$type": "com.atproto.repo.applyWrites#create",
                }
            ],
        },
    )
    return web.json_response(
        {
            "commit": result["commit"],
            "uri": result["results"][0]["uri"],
            "cid": result["results"][0]["cid"],
            "validationStatus": result["results"][0]["validationStatus"],
        }
    )

# Route to update a record in a repository
@routes.post("/xrpc/com.atproto.repo.putRecord")
@authenticated
async def repo_put_record(request: web.Request):
    original_request = await request.json()
    result = await apply_writes_and_emit_firehose(
        request,
        {
            "repo": original_request["repo"],
            "validate": original_request.get("validate"),
            "swapCommit": original_request.get("swapCommit"),
            "writes": [
                {
                    "collection": original_request["collection"],
                    "rkey": original_request["rkey"],
                    "validate": original_request.get("validate"),
                    "swapRecord": original_request.get("swapRecord"),
                    "value": original_request["record"],
                    "$type": "com.atproto.repo.applyWrites#update",
                }
            ],
        },
    )
    return web.json_response(
        {
            "commit": result["commit"],
            "uri": result["results"][0]["uri"],
            "cid": result["results"][0]["cid"],
            "validationStatus": result["results"][0]["validationStatus"],
        }
    )

# Route to delete a record from a repository
@routes.post("/xrpc/com.atproto.repo.deleteRecord")
@authenticated
async def repo_delete_record(request: web.Request):
    original_request = await request.json()
    result = await apply_writes_and_emit_firehose(
        request,
        {
            "repo": original_request["repo"],
            "validate": original_request.get("validate"),
            "swapCommit": original_request.get("swapCommit"),
            "writes": [
                {
                    "collection": original_request["collection"],
                    "rkey": original_request["rkey"],
                    "validate": original_request.get("validate"),
                    "swapRecord": original_request.get("swapRecord"),
                    "$type": "com.atproto.repo.applyWrites#delete",
                }
            ],
        },
    )
    return web.json_response({"commit": result["commit"]})

# Route to describe a repository
@routes.get("/xrpc/com.atproto.repo.describeRepo")
async def repo_describe_repo(request: web.Request):
    if "repo" not in request.query:
        raise web.HTTPBadRequest(text="Missing repository parameter")

    did_or_handle = request.query["repo"]
    with get_db(request).new_con(readonly=True) as con:
        user_id, did, handle = con.execute(
            "SELECT id, did, handle FROM users WHERE did=? OR handle=?",
            (did_or_handle, did_or_handle),
        ).fetchone()

        return web.json_response(
            {
                "handle": handle,
                "did": did,
                "didDoc": {},  # TODO: Implement this
                "collections": [
                    row[0]
                    for row in con.execute(
                        "SELECT DISTINCT(collection) FROM records WHERE user_id=?",
                        (user_id,),
                    )
                ],
                "handleIsCorrect": True,  # TODO: Implement this
            }
        )

# Route to get a record from a repository
@routes.get("/xrpc/com.atproto.repo.getRecord")
async def repo_get_record(request: web.Request):
    if "repo" not in request.query:
        raise web.HTTPBadRequest(text="Missing repository parameter")
    if "collection" not in request.query:
        raise web.HTTPBadRequest(text="Missing collection parameter")
    if "rkey" not in request.query:
        raise web.HTTPBadRequest(text="Missing record key parameter")

    did_or_handle = request.query["repo"]
    collection = request.query["collection"]
    rkey = request.query["rkey"]
    cid_in = request.query.get("cid")
    db = get_db(request)
    row = db.con.execute(
        "SELECT cid, value FROM records WHERE user_id=(SELECT id FROM users WHERE did=? OR handle=?) AND collection=? AND rkey=?",
        (did_or_handle, did_or_handle, collection, rkey),
    ).fetchone()

    if row is None:
        return await service_proxy(request)  # Forward to appview if record not found

    cid_out, value = row
    cid_out = cbrrr.CID(cid_out)
    if cid_in is not None:
        if cbrrr.CID.decode(cid_in) != cid_out:
            raise web.HTTPNotFound(text="Record not found with matching CID")

    return web.json_response(
        {
            "uri": f"at://{did_or_handle}/{collection}/{rkey}",
            "cid": cid_out.encode(),
            "value": cbrrr.decode_dag_cbor(value, atjson_mode=True),
        }
    )

# Route to list records in a repository
@routes.get("/xrpc/com.atproto.repo.listRecords")
async def repo_list_records(request: web.Request):
    if "repo" not in request.query:
        raise web.HTTPBadRequest(text="Missing repository parameter")
    if "collection" not in request.query:
        raise web.HTTPBadRequest(text="Missing collection parameter")

    limit = int(request.query.get("limit", 50))
    if limit < 1 or limit > 100:
        raise web.HTTPBadRequest(text="Limit out of range")

    reverse = request.query.get("reverse") == "true"
    cursor = request.query.get("cursor", "" if reverse else "\xff")
    did_or_handle = request.query["repo"]
    collection = request.query["collection"]
    records = []
    db = get_db(request)

    for rkey, cid, value in db.con.execute(
        f"""\n            SELECT rkey, cid, value\n            FROM records\n            WHERE user_id=(SELECT id FROM users WHERE did=? OR handle=?)\n                AND collection=? AND rkey{">" if reverse else "<"}?\n            ORDER BY rkey {"ASC" if reverse else "DESC"}\n            LIMIT ?\n        """,
        (did_or_handle, did_or_handle, collection, cursor, limit),
    ):
        records.append(
            {
                "uri": f"at://{did_or_handle}/{collection}/{rkey}",
                "cid": cbrrr.CID(cid).encode(),
                "value": cbrrr.decode_dag_cbor(value, atjson_mode=True),
            }
        )

    return web.json_response(
        {"records": records} | ({"cursor": rkey} if len(records) == limit else {})
    )

# Route to upload a blob to a repository
@routes.post("/xrpc/com.atproto.repo.uploadBlob")
@authenticated
async def repo_upload_blob(request: web.Request):
    mime = request.headers.get("content-type", "application/octet-stream")
    BLOCK_SIZE = 0x10000  # 64k for now, might tweak this upwards for performance
    db = get_db(request)

    db.con.execute(
        "INSERT INTO blobs (user_id, refcount) VALUES ((SELECT id FROM users WHERE did=?), 0)",
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

        if not chunk:  # Zero-length final chunk
            break

        length_read += len(chunk)
        hasher.update(chunk)
        db.con.execute(
            "INSERT INTO blob_parts (blob_id, idx, data) VALUES (?, ?, ?)",
            (blob_id, part_idx, chunk),
        )
        part_idx += 1

        if len(chunk) < BLOCK_SIZE:
            break

    digest = hasher.digest()
    cid = cbrrr.CID(cbrrr.CID.CIDV1_RAW_SHA256_32_PFX + digest)

    try:
        db.con.execute(
            "UPDATE blobs SET cid=? WHERE id=?", (bytes(cid), blob_id)
        )
    except apsw.ConstraintError:
        db.con.execute(
            "DELETE FROM blob_parts WHERE blob_id=?", (blob_id,)
        )
        db.con.execute("DELETE FROM blobs WHERE id=?", (blob_id,))
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