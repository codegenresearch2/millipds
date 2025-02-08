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
    def __init__(self, path: str):
        self.path = path
        self.config = {}
        self.pw_hasher = argon2.PasswordHasher()
        self.con = self._new_con()

    def _new_con(self, readonly: bool = False) -> apsw.Connection:
        return apsw.Connection(
            self.path,
            flags=(apsw.SQLITE_OPEN_READONLY if readonly else apsw.SQLITE_OPEN_READWRITE | apsw.SQLITE_OPEN_CREATE)
        )

    def update_config(self, pds_pfx: str = None, pds_did: str = None, bsky_appview_pfx: str = None, bsky_appview_did: str = None):
        if pds_pfx is not None:
            self.config['pds_pfx'] = pds_pfx
        if pds_did is not None:
            self.config['pds_did'] = pds_did
        if bsky_appview_pfx is not None:
            self.config['bsky_appview_pfx'] = bsky_appview_pfx
        if bsky_appview_did is not None:
            self.config['bsky_appview_did'] = bsky_appview_did

    @property
    def config(self) -> dict:
        return self._config

    @config.setter
    def config(self, value: dict):
        self._config = value

    def create_account(self, did: str, handle: str, password: str, privkey: crypto.ec.EllipticCurvePrivateKey):
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
                INSERT INTO user(did, handle, prefs, pw_hash, signing_key, head, rev, commit_bytes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (did, handle, b'{}', pw_hash, privkey_pem, bytes(commit_cid), tid, commit_bytes)
            )

    def _init_tables(self):
        logger.info('Initializing tables')
        self.con.execute(
            """
            CREATE TABLE IF NOT EXISTS config(
                db_version INTEGER NOT NULL,
                pds_pfx TEXT,
                pds_did TEXT,
                bsky_appview_pfx TEXT,
                bsky_appview_did TEXT,
                jwt_access_secret TEXT NOT NULL
            )"
        )
        self.con.execute(
            """
            INSERT INTO config(db_version, jwt_access_secret)
            VALUES (?, ?)"",
            (static_config.MILLIPDS_DB_VERSION, crypto.generate_secret())
        )
        self.con.execute(
            """
            CREATE TABLE IF NOT EXISTS user(
                id INTEGER PRIMARY KEY NOT NULL,
                did TEXT NOT NULL,
                handle TEXT NOT NULL,
                prefs BLOB NOT NULL,
                pw_hash TEXT NOT NULL,
                signing_key TEXT NOT NULL,
                head BLOB NOT NULL,
                rev TEXT NOT NULL,
                commit_bytes BLOB NOT NULL
            )"
        )
        self.con.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS user_by_did ON user(did)"
        )
        self.con.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS user_by_handle ON user(handle)"
        )
        self.con.execute(
            """
            CREATE TABLE IF NOT EXISTS firehose(
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                msg BLOB NOT NULL
            )"
        )
        self.con.execute(
            """
            CREATE TABLE IF NOT EXISTS mst(
                repo INTEGER NOT NULL,
                cid BLOB NOT NULL,
                since TEXT NOT NULL,
                value BLOB NOT NULL,
                FOREIGN KEY (repo) REFERENCES user(id),
                PRIMARY KEY (repo, cid)
            )"
        )
        self.con.execute("""
            CREATE INDEX IF NOT EXISTS mst_since ON mst(since)"
        )
        self.con.execute(
            """
            CREATE TABLE IF NOT EXISTS record(
                repo INTEGER NOT NULL,
                nsid TEXT NOT NULL,
                rkey TEXT NOT NULL,
                cid BLOB NOT NULL,
                since TEXT NOT NULL,
                value BLOB NOT NULL,
                FOREIGN KEY (repo) REFERENCES user(id),
                PRIMARY KEY (repo, nsid, rkey)
            )"
        )
        self.con.execute("""
            CREATE INDEX IF NOT EXISTS record_since ON record(since)"
        )
        self.con.execute(
            """
            CREATE TABLE IF NOT EXISTS blob(
                id INTEGER PRIMARY KEY NOT NULL,
                repo INTEGER NOT NULL,
                cid BLOB,
                refcount INTEGER NOT NULL,
                since TEXT,
                FOREIGN KEY (repo) REFERENCES user(id)
            )"
        )
        self.con.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS blob_repo_cid ON blob(repo, cid)"
        )
        self.con.execute(
            """
            CREATE TABLE IF NOT EXISTS blob_part(
                blob INTEGER NOT NULL,
                idx INTEGER NOT NULL,
                data BLOB NOT NULL,
                PRIMARY KEY (blob, idx),
                FOREIGN KEY (blob) REFERENCES blob(id)
            )"
        )
        self.con.execute(
            """
            CREATE TABLE IF NOT EXISTS did_cache(
                did TEXT PRIMARY KEY NOT NULL,
                doc TEXT,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )"
        )

    def verify_account_login(self, did_or_handle: str, password: str) -> tuple[str, str, str, str]:
        row = self.con.execute(
            """
            SELECT did, handle, pw_hash FROM user WHERE did=? OR handle=?"",
            (did_or_handle, did_or_handle)
        ).fetchone()
        if row is None:
            raise KeyError('No account found for did')
        did, handle, pw_hash = row
        try:
            self.pw_hasher.verify(pw_hash, password)
        except argon2.exceptions.VerifyMismatchError:
            raise ValueError('Invalid password')
        return did, handle

    def did_by_handle(self, handle: str) -> str:
        row = self.con.execute(
            """
            SELECT did FROM user WHERE handle=?"",
            (handle,)
        ).fetchone()
        if row is None:
            return None
        return row[0]

    def handle_by_did(self, did: str) -> str:
        row = self.con.execute(
            """
            SELECT handle FROM user WHERE did=?"",
            (did,)
        ).fetchone()
        if row is None:
            return None
        return row[0]

    def signing_key_pem_by_did(self, did: str) -> str:
        row = self.con.execute(
            """
            SELECT signing_key FROM user WHERE did=?"",
            (did,)
        ).fetchone()
        if row is None:
            return None
        return row[0]

    def list_repos(self) -> list[tuple[str, cbrrr.CID, str]]:
        return [
            (did, cbrrr.CID(head), rev)
            for did, head, rev in self.con.execute(
                """
                SELECT did, head, rev FROM user"""
            )
        ]

    def get_blockstore(self, did: str) -> 'DBBlockStore':
        return DBBlockStore(self.con, did)

class DBBlockStore(BlockStore):
    def __init__(self, db_connection: apsw.Connection, repo_id: int):
        self.db_connection = db_connection
        self.repo_id = repo_id
        self.logger = logging.getLogger(__name__)

    def get_block(self, key: bytes) -> bytes:
        try:
            row = self.db_connection.execute(
                """
                SELECT value FROM mst WHERE repo=? AND cid=?""",
                (self.repo_id, key)
            ).fetchone()
            if row is None:
                raise KeyError('Block not found in db')
            return row[0]
        except Exception as e:
            self.logger.error(f'Error retrieving block with key: {key} - {e}')
            raise

    def put_block(self, key: bytes, value: bytes):
        try:
            self.db_connection.execute(
                """
                INSERT INTO mst (repo, cid, since, value) VALUES (?, ?, ?, ?)"",
                (self.repo_id, key, util.tid_now(), value)
            )
        except Exception as e:
            self.logger.error(f'Error putting block with key: {key} - {e}')
            raise

    def del_block(self, key: bytes):
        try:
            self.db_connection.execute(
                """
                DELETE FROM mst WHERE repo=? AND cid=?""",
                (self.repo_id, key)
            )
        except Exception as e:
            self.logger.error(f'Error deleting block with key: {key} - {e}')
            raise
