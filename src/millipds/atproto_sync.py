from typing import Optional, Tuple
import logging
import asyncio

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
    """
    Retrieve a blob from the repository.
    
    Args:
        request (web.Request): The HTTP request object.
    
    Returns:
        web.Response: The HTTP response containing the blob data.
    """
    db = get_db(request)
    try:
        async with db.new_con(readonly=True) as con:
            blob_id = await con.execute(
                "SELECT blob.id FROM blob INNER JOIN user ON blob.repo=user.id WHERE did=? AND cid=? AND refcount>0",
                (
                    request.query["did"],
                    bytes(cbrrr.CID.decode(request.query["cid"])),
                ),
            )
            blob_id = blob_id.fetchone()
            if blob_id is None:
                raise web.HTTPNotFound(text="blob not found")
            res = web.StreamResponse(
                headers={
                    "Content-Disposition": f'attachment; filename="{request.query["cid"]}.bin"'
                }
            )
            res.content_type = "application/octet-stream"
            await res.prepare(request)
            async for blob_part in con.execute_fetchall(
                "SELECT data FROM blob_part WHERE blob=?",
                (blob_id[0],),
            ):
                await res.write(blob_part)
            await res.write_eof()
            return res
    except web.HTTPNotFound:
        raise
    except Exception as e:
        logger.error(f"Error fetching blob: {e}")
        raise web.HTTPInternalServerError(text="Internal Server Error")


@routes.get("/xrpc/com.atproto.sync.getBlocks")
async def sync_get_blocks(request: web.Request):
    """
    Retrieve blocks from the repository.
    
    Args:
        request (web.Request): The HTTP request object.
    
    Returns:
        web.Response: The HTTP response containing the blocks data.
    """
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
    try:
        row = await db.con.execute("SELECT id FROM user WHERE did=?", (did,))
        row = row.fetchone()
        if row is None:
            raise web.HTTPNotFound(text="did not found")
        user_id = row[0]
        res = web.StreamResponse()
        res.content_type = "application/vnd.ipld.car"
        await res.prepare(request)
        await res.write(util.serialize_car_header())
        for cid in cids:
            row = await db.con.execute(
                """
                    SELECT commit_bytes FROM user WHERE head=? AND id=?
                    UNION SELECT value FROM mst WHERE cid=? AND repo=?
                    UNION SELECT value FROM record WHERE cid=? AND repo=?
                """,
                (cid, user_id) * 3,
            )
            row = row.fetchone()
            if row is None:
                continue
            await res.write(util.serialize_car_entry(cid, row[0]))
        await res.write_eof()
        return res
    except web.HTTPNotFound:
        raise
    except Exception as e:
        logger.error(f"Error fetching blocks: {e}")
        raise web.HTTPInternalServerError(text="Internal Server Error")


@routes.get("/xrpc/com.atproto.sync.getLatestCommit")
async def sync_get_latest_commit(request: web.Request):
    """
    Retrieve the latest commit for a repository.
    
    Args:
        request (web.Request): The HTTP request object.
    
    Returns:
        web.Response: The HTTP response containing the latest commit information.
    """
    did = request.query.get("did")
    if did is None:
        raise web.HTTPBadRequest(text="no did specified")
    try:
        row = await (get_db(request).con.execute("SELECT rev, head FROM user WHERE did=?", (did,)))
        row = row.fetchone()
        if row is None:
            raise web.HTTPNotFound(text="did not found")
        rev, head = row
        return web.json_response({"cid": cbrrr.CID(head).encode(), "rev": rev})
    except web.HTTPNotFound:
        raise
    except Exception as e:
        logger.error(f"Error fetching latest commit: {e}")
        raise web.HTTPInternalServerError(text="Internal Server Error")


@routes.get("/xrpc/com.atproto.sync.getRecord")
async def sync_get_record(request: web.Request):
    """
    Retrieve a record from the repository.
    
    Args:
        request (web.Request): The HTTP request object.
    
    Returns:
        web.Response: The HTTP response containing the record data.
    """
    if "did" not in request.query:
        raise web.HTTPBadRequest(text="missing did")
    if "collection" not in request.query:
        raise web.HTTPBadRequest(text="missing collection")
    if "rkey" not in request.query:
        raise web.HTTPBadRequest(text="missing rkey")

    try:
        car = await repo_ops.get_record(
            get_db(request),
            request.query["did"],
            request.query["collection"] + "/" + request.query["rkey"],
        )
        if car is None:
            raise web.HTTPNotFound(text="record not found")
        return web.Response(body=car, content_type="application/vnd.ipld.car")
    except web.HTTPNotFound:
        raise
    except Exception as e:
        logger.error(f"Error fetching record: {e}")
        raise web.HTTPInternalServerError(text="Internal Server Error")


@routes.get("/xrpc/com.atproto.sync.getRepoStatus")
async def sync_get_repo_status(request: web.Request):
    """
    Retrieve the status of a repository.
    
    Args:
        request (web.Request): The HTTP request object.
    
    Returns:
        web.Response: The HTTP response containing the repository status.
    """
    did = request.query.get("did")
    if did is None:
        raise web.HTTPBadRequest(text="no did specified")
    try:
        row = await (get_db(request).con.execute("SELECT rev FROM user WHERE did=?", (did,)))
        row = row.fetchone()
        if row is None:
            raise web.HTTPNotFound(text="did not found")
        return web.json_response({"did": did, "active": True, "rev": row[0]})
    except web.HTTPNotFound:
        raise
    except Exception as e:
        logger.error(f"Error fetching repo status: {e}")
        raise web.HTTPInternalServerError(text="Internal Server Error")


@routes.get("/xrpc/com.atproto.sync.getRepo")
async def sync_get_repo(request: web.Request):
    """
    Retrieve the repository data.
    
    Args:
        request (web.Request): The HTTP request object.
    
    Returns:
        web.Response: The HTTP response containing the repository data.
    """
    did = request.query.get("did")
    if did is None:
        raise web.HTTPBadRequest(text="no did specified")
    since = request.query.get("since", "")

    try:
        async with get_db(request).new_con(readonly=True) as con:
            row = await con.execute(
                "SELECT id, head, commit_bytes FROM user WHERE did=?", (did,)
            )
            row = row.fetchone()
            if row is None:
                raise web.HTTPNotFound(text="repo not found")
            user_id, head, commit_bytes = row
            res = web.StreamResponse()
            res.content_type = "application/vnd.ipld.car"
            await res.prepare(request)
            await res.write(util.serialize_car_header(head))
            await res.write(util.serialize_car_entry(head, commit_bytes))

            async for mst_cid, mst_value in con.execute_fetchall(
                "SELECT cid, value FROM mst WHERE repo=? AND since>?",
                (user_id, since),
            ):
                await res.write(util.serialize_car_entry(mst_cid, mst_value))

            async for record_cid, record_value in con.execute_fetchall(
                "SELECT cid, value FROM record WHERE repo=? AND since>?",
                (user_id, since),
            ):
                await res.write(util.serialize_car_entry(record_cid, record_value))

        await res.write_eof()
        return res
    except web.HTTPNotFound:
        raise
    except Exception as e:
        logger.error(f"Error fetching repo: {e}")
        raise web.HTTPInternalServerError(text="Internal Server Error")