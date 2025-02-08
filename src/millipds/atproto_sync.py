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
    db = get_db(request)
    with db.new_con(readonly=True) as con:
        blob_id = con.execute(
            """
            SELECT blob.id FROM blob 
            INNER JOIN user ON blob.repo=user.id 
            WHERE did=%s AND cid=%s AND refcount>0""",
            (request.query['did'], bytes(cbrrr.CID.decode(request.query['cid']))),
        ).fetchone()
        if blob_id is None:
            raise web.HTTPNotFound(text='blob not found')
        res = web.StreamResponse(
            headers={'Content-Disposition': f'attachment; filename="{request.query['cid']}.bin"' }
        )
        res.content_type = 'application/octet-stream'
        await res.prepare(request)
        async for (blob_part, *_) in con.execute(
            'SELECT data FROM blob_part WHERE blob=? ORDER BY idx',
            (blob_id[0],),
        ):
            await res.write(blob_part)
        await res.write_eof()
        return res