import logging
import apsw
import argon2
import cbrrr
from atmst.blockstore import BlockStore
from atmst.mst.node import MSTNode
from . import static_config
from . import crypto

logger = logging.getLogger(__name__)

class Database:
    def __init__(self, path):
        self.path = path
        self.config = {}
        self.pw_hasher = argon2.PasswordHasher()
        self.con = self._new_con()

    def _new_con(self, readonly=False):
        return apsw.Connection(
            self.path,
            flags=(apsw.SQLITE_OPEN_READONLY if readonly else apsw.SQLITE_OPEN_READWRITE | apsw.SQLITE_OPEN_CREATE)
        )

    def update_config(self, pds_pfx=None, pds_did=None, bsky_appview_pfx=None, bsky_appview_did=None):
        if pds_pfx is not None:
            self.config['pds_pfx'] = pds_pfx
        if pds_did is not None:
            self.config['pds_did'] = pds_did
        if bsky_appview_pfx is not None:
            self.config['bsky_appview_pfx'] = bsky_appview_pfx
        if bsky_appview_did is not None:
            self.config['bsky_appview_did'] = bsky_appview_did

    @property
    def config(self):
        return self._config

    @config.setter
    def config(self, value):
        self._config = value

    def create_account(self, did, handle, password, privkey):
        pw_hash = self.pw_hasher.hash(password)
        privkey_pem = crypto.privkey_to_pem(privkey)
        logger.info(f'Creating account for did={did}, handle={handle}')

        with self.con:
            tid = util.tid_now()
            empty_mst = MSTNode.empty_root()
            initial_commit = {
                'did': did,
                'version': static_config.ATPROTO_REPO_VERSION_3,
                'data': empty_mst.cid,
                'rev': tid,
                'prev': None,
            }
            initial_commit['sig'] = crypto.raw_sign(
                privkey, cbrrr.encode_dag_cbor(initial_commit)
            )
            commit_bytes = cbrrr.encode_dag_cbor(initial_commit)
            commit_cid = cbrrr.CID.cidv1_dag_cbor_sha256_32_from(commit_bytes)
            self.con.execute(
                '''
                INSERT INTO user(
                    did,
                    handle,
                    prefs,
                    pw_hash,
                    signing_key,
                    head,
                    rev,
                    commit_bytes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    did,
                    handle,
                    b'{}\