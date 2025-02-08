from typing import Tuple\\nimport logging\\nimport hashlib\\n\\nfrom aiohttp import web\\nimport cbrrr\\nimport apsw\\nimport asyncio\\n\\nfrom . import repo_ops\\nfrom .appview_proxy import service_proxy\\nfrom .auth_bearer import authenticated\\nfrom .app_util import *\\n\\nlogger = logging.getLogger(__name__)\\n\\nroutes = web.RouteTableDef()\\n\\n\\nasync def firehose_broadcast(request: web.Request, msg: Tuple[int, bytes]):\\n    async with get_firehose_queues_lock(request):\\n        queues_to_remove = set()\\n        active_queues = get_firehose_queues(request)\\n        for queue in active_queues:\\n            try:\\n                queue.put_nowait(msg)\\n\\n            except asyncio.QueueFull:\\n                while not queue.empty():\\n                    queue.get_nowait()\\n                queue.put_nowait(None)\\n                queues_to_remove.add(queue)\\n\\n        active_queues -= queues_to_remove\\n\\n\\nasync def apply_writes_and_emit_firehose(request: web.Request, req_json: dict) -> dict:\\n    if req_json['repo'] != request['authed_did']:\\n        raise web.HTTPUnauthorized(text='not authed for that repo')\\n    res, firehose_seq, firehose_bytes = repo_ops.apply_writes(get_db(request), request['authed_did'], req_json['writes'], req_json.get('swapCommit'))\\n    await firehose_broadcast(request, (firehose_seq, firehose_bytes))\\\\\n    return res\\n\\n@routes.post('/xrpc/com.atproto.repo.applyWrites')\\n@authenticated\\nasync def repo_apply_writes(request):\\n    return web.json_response(await apply_writes_and_emit_firehose(request, await request.json()))\\n\\n@routes.post('/xrpc/com.atproto.repo.createRecord')\\n@authenticated\\nasync def repo_create_record(request):\\n    orig = await request.json()\\n    res = await apply_writes_and_emit_firehose(request, {\"repo\": orig['repo'], \"writes\": [\"$type\": \"com.atproto.repo.applyWrites#create\", \"collection\": orig['collection'], \"value\": orig['record']}]})\\n    return web.json_response({\"commit\": res['commit'], \"uri\": res['results'][0]['uri'], \"cid\": res['results'][0]['cid'], \"validationStatus\": res['results'][0]['validationStatus']})\\n\\n@routes.post('/xrpc/com.atproto.repo.putRecord')\\n@authenticated\\nasync def repo_put_record(request):\\n    orig = await request.json()\\n    res = await apply_writes_and_emit_firehose(request, {\"repo\": orig['repo'], \"writes\": [\"$type\": \"com.atproto.repo.applyWrites#update\", \"collection\": orig['collection'], \"rkey\": orig['rkey'], \"value\": orig['record']}]})\\n    return web.json_response({\"commit\": res['commit'], \"uri\": res['results'][0]['uri'], \"cid\": res['results'][0]['cid'], \"validationStatus\": res['results'][0]['validationStatus']})\\n\\n@routes.post('/xrpc/com.atproto.repo.deleteRecord')\\n@authenticated\\nasync def repo_delete_record(request):\\n    orig = await request.json()\\n    res = await apply_writes_and_emit_firehose(request, {\"repo\": orig['repo'], \"writes\": [\"$type\": \"com.atproto.repo.applyWrites#delete\", \"collection\": orig['collection'], \"rkey\": orig['rkey']}]})\\n    return web.json_response({\"commit\": res['commit']})\\n\\n@routes.get('/xrpc/com.atproto.repo.describeRepo')\\ndef repo_describe_repo(request):\\n    if 'repo' not in request.query:\\n        raise web.HTTPBadRequest(text='missing repo')\\n    did_or_handle = request.query['repo']\\n    with get_db(request).new_con(readonly=True) as con:\\n        user_id, did, handle = con.execute(\"SELECT id, did, handle FROM user WHERE did=? OR handle=?\", (did_or_handle, did_or_handle)).fetchone()\\n\\n        return web.json_response({\"handle\": handle, \"did\": did, \"didDoc\": {}, \"collections\": [row[0] for row in con.execute(\"SELECT DISTINCT(nsid) FROM record WHERE repo=?\", (user_id,))]})\\n\\n@routes.get('/xrpc/com.atproto.repo.getRecord')\\nasync def repo_get_record(request):\\n    if 'repo' not in request.query:\\n        raise web.HTTPBadRequest(text='missing repo')\\n    if 'collection' not in request.query:\\n        raise web.HTTPBadRequest(text='missing collection')\\n    if 'rkey' not in request.query:\\n        raise web.HTTPBadRequest(text='missing rkey')\\n    did_or_handle = request.query['repo']\\n    collection = request.query['collection']\\n    rkey = request.query['rkey']\\n    cid_in = request.query.get('cid')\n    db = get_db(request)\n    row = db.con.execute(\"SELECT cid, value FROM record WHERE repo=(SELECT id FROM user WHERE did=? OR handle=?) AND nsid=? AND rkey=?\", (did_or_handle, did_or_handle, collection, rkey)).fetchone()\\n    if row is None:\\n        return await service_proxy(request) \\n        # raise web.HTTPNotFound(text='record not found')\n    cid_out, value = row\\n    cid_out = cbrrr.CID(cid_out)\n    if cid_in is not None:\\n        if cbrrr.CID.decode(cid_in) != cid_out:\\n            raise web.HTTPNotFound(text='record not found with matching CID')\n    return web.json_response({\"uri\": f'at://{did_or_handle}/{collection}/{rkey}', \"cid\": cid_out.encode(), \"value\": cbrrr.decode_dag_cbor(value, atjson_mode=True)})\\n\\n@routes.get('/xrpc/com.atproto.repo.listRecords')\\ndef repo_list_records(request):\\n    if 'repo' not in request.query:\\n        raise web.HTTPBadRequest(text='missing repo')\n    if 'collection' not in request.query:\\n        raise web.HTTPBadRequest(text='missing collection')\n    limit = int(request.query.get('limit', 50))\n    if limit < 1 or limit > 100:\\n        raise web.HTTPBadRequest(text='limit out of range')\n    reverse = request.query.get('reverse') == 'true'\n    cursor = request.query.get('cursor', '' if reverse else '\xff')\n    did_or_handle = request.query['repo']\n    collection = request.query['collection']\n    records = []\n    db = get_db(request)\n    for rkey, cid, value in db.con.execute(\"SELECT rkey, cid, value FROM record WHERE repo=(SELECT id FROM user WHERE did=? OR handle=?) AND nsid=? AND rkey{'>' if reverse else '<'}? ORDER BY rkey {'ASC' if reverse else 'DESC'} LIMIT ?\", (did_or_handle, did_or_handle, collection, cursor, limit)):\\n        records.append({\"uri\": f'at://{did_or_handle}/{collection}/{rkey}', \"cid\": cbrrr.CID(cid).encode(), \"value\": cbrrr.decode_dag_cbor(value, atjson_mode=True)})\\n    return web.json_response({\"records\": records} | ({{\"cursor\": rkey}} if len(records) == limit else {}))\n\\n@routes.post('/xrpc/com.atproto.repo.uploadBlob')\\n@authenticated\\nasync def repo_upload_blob(request):\\n    mime = request.headers.get('content-type', 'application/octet-stream')\n    BLOCK_SIZE = 0x10000 \n    db = get_db(request)\n    db.con.execute(\"INSERT INTO blob (repo, refcount) VALUES ((SELECT id FROM user WHERE did=?), 0)\", (request['authed_did'],))\n    blob_id = db.con.last_insert_rowid()\n    length_read = 0\n    part_idx = 0\n    hasher = hashlib.sha256()\n    while True:\n        try:\n            chunk = await request.content.readexactly(BLOCK_SIZE)\n        except asyncio.IncompleteReadError as e:\n            chunk = e.partial\n        if not chunk: \n            break\n        length_read += len(chunk)\n        hasher.update(chunk)\n        db.con.execute(\"INSERT INTO blob_part (blob, idx, data) VALUES (?, ?, ?)\", (blob_id, part_idx, chunk))\n        part_idx += 1\n        if len(chunk) < BLOCK_SIZE:\n            break\n    digest = hasher.digest()\n    cid = cbrrr.CID(cbrrr.CID.CIDV1_RAW_SHA256_32_PFX + digest)\n    try:\n        db.con.execute(\"UPDATE blob SET cid=? WHERE id=?\", (bytes(cid), blob_id))\n    except apsw.ConstraintError:\n        db.con.execute(\"DELETE FROM blob_part WHERE blob=?\", (blob_id,))\n        db.con.execute(\"DELETE FROM blob WHERE id=?\", (blob_id,))\n        logger.info('uploaded blob already existed, dropping duplicate')\n\\n    return web.json_response({\"blob\": {\"$type\": 'blob', \"ref\": {\"$link\": cid.encode()}, \"mimeType\": mime, \"size\": length_read}})}"}