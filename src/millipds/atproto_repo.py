from typing import Tuple
from aiohttp import web
import cbrrr
import apsw
import asyncio
import hashlib
import logging

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

async def apply_writes_and_emit_firehose(request: web.Request, req_json: dict) -> dict:
    if req_json["repo"] != request["authed_did"]:
        raise web.HTTPUnauthorized(text="not authed for that repo")
    
    # Ensure 'writes' key is present in req_json
    if "writes" not in req_json:
        raise web.HTTPBadRequest(text="Missing 'writes' key in request JSON")
    
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
    orig = await request.json()
    writes = [
        {
            "$type": "com.atproto.repo.applyWrites#create",
            "collection": orig["collection"],
            "rkey": orig.get("rkey"),
            "value": orig["record"],
        }
    ]
    res = await apply_writes_and_emit_firehose(request, {"writes": writes, "repo": orig["repo"]})
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
    orig = await request.json()
    writes = [
        {
            "$type": "com.atproto.repo.applyWrites#update",
            "collection": orig["collection"],
            "rkey": orig["rkey"],
            "value": orig["record"],
        }
    ]
    res = await apply_writes_and_emit_firehose(request, {"writes": writes, "repo": orig["repo"]})
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
    orig = await request.json()
    writes = [
        {
            "$type": "com.atproto.repo.applyWrites#delete",
            "collection": orig["collection"],
            "rkey": orig["rkey"],
        }
    ]
    res = await apply_writes_and_emit_firehose(request, {"writes": writes, "repo": orig["repo"]})
    return web.json_response({"commit": res["commit"]})

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

@routes.get("/xrpc/com.atproto.repo.getRecord")
async def repo_get_record(request: web.Request):
    if "repo" not in request.query:
        raise web.HTTPBadRequest(text="missing repo")
    if "collection" not in request.query:
        raise web.HTTPBadRequest(text="missing collection")
    if "rkey" not in request.query:
        raise web.HTTPBadRequest(text="missing rkey")
    did_or_handle = request.query["repo"]
    collection = request.query["collection"]
    rkey = request.query["rkey"]
    cid_in = request.query.get("cid")
    db = get_db(request)
    row = db.con.execute(
        "SELECT cid, value FROM record WHERE repo=(SELECT id FROM user WHERE did=? OR handle=?) AND nsid=? AND rkey=?",
        (did_or_handle, did_or_handle, collection, rkey),
    ).fetchone()
    if row is None:
        return await service_proxy(request)  # forward to appview
    cid_out, value = row
    cid_out = cbrrr.CID(cid_out)
    if cid_in is not None:
        if cbrrr.CID.decode(cid_in) != cid_out:
            raise web.HTTPNotFound(text="record not found with matching CID")
    return web.json_response(
        {
            "uri": f"at://{did_or_handle}/{collection}/{rkey}",  # TODO rejig query to get the did out always,
            "cid": cid_out.encode(),
            "value": cbrrr.decode_dag_cbor(value, atjson_mode=True),
        }
    )