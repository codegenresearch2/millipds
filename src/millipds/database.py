import argon2
import apsw
import cbrrr
import logging
from atmst.blockstore import BlockStore
from typing import Optional, Dict, List, Tuple
from functools import cached_property

logger = logging.getLogger(__name__)

class DBBlockStore(BlockStore):
    def __init__(self, db: 'Database', repo: str) -> None:
        self.db = db
        self.user_id = self.db.con.execute(
            "SELECT id FROM user WHERE did=?", (repo,))
        ).fetchone()[0]

    def get_block(self, key: bytes) -> bytes:
        row = self.db.con.execute(
            "SELECT value FROM mst WHERE repo=? AND cid=?", (self.user_id, key))
        if row is None:
            raise KeyError("block not found in db")
        return row[0]

class Database:
    def __init__(self, path: str = 'default_path') -> None:
        logger.info(f"opening database at {path}")
        self.path = path
        self.con = self.new_con()
        self.pw_hasher = argon2.PasswordHasher()

        try:
            if self.config['db_version'] != static_config.MILLIPDS_DB_VERSION:
                raise Exception(
                    'unrecognised db version (TODO: db migrations)?')
        except apsw.SQLError as e:
            if 'no such table' not in str(e):
                raise
            with self.con:
                self._init_tables()

    def new_con(self, readonly: bool = False) -> apsw.Connection:
        return apsw.Connection(
            self.path,
            flags=(
                apsw.SQLITE_OPEN_READONLY
                if readonly
                else apsw.SQLITE_OPEN_READWRITE | apsw.SQLITE_OPEN_CREATE
            )
        )

    def _init_tables(self) -> None:
        logger.info('initializing tables')
        self.con.execute(
            '''
            CREATE TABLE config(
                db_version INTEGER NOT NULL,
                pds_pfx TEXT,
                pds_did TEXT,
                bsky_appview_pfx TEXT,
                bsky_appview_did TEXT,
                jwt_access_secret TEXT NOT NULL
            )
            ''')
        self.con.execute(
            "INSERT INTO config(db_version, jwt_access_secret) VALUES (?, ?)",
            (static_config.MILLIPDS_DB_VERSION, secrets.token_hex())
        )
        self.con.execute(
            "CREATE TABLE user(\n                id INTEGER PRIMARY KEY NOT NULL,\n                did TEXT NOT NULL,\n                handle TEXT NOT NULL,\n                prefs BLOB NOT NULL,\n                pw_hash TEXT NOT NULL,\n                signing_key TEXT NOT NULL,\n                head BLOB NOT NULL,\n                rev TEXT NOT NULL,\n                commit_bytes BLOB NOT NULL\n            )"
        )
        self.con.execute('CREATE UNIQUE INDEX user_by_did ON user(did)')
        self.con.execute('CREATE UNIQUE INDEX user_by_handle ON user(handle)')
        self.con.execute(
            "CREATE TABLE firehose(\n                seq INTEGER PRIMARY KEY AUTOINCREMENT,\n                timestamp INTEGER NOT NULL,\n                msg BLOB NOT NULL\n            )"
        )
        self.con.execute(
            "CREATE TABLE mst(\n                repo INTEGER NOT NULL,\n                cid BLOB NOT NULL,\n                since TEXT NOT NULL,\n                value BLOB NOT NULL,\n                FOREIGN KEY (repo) REFERENCES user(id),\n                PRIMARY KEY (repo, cid)\n            )"
        )
        self.con.execute('CREATE INDEX mst_since ON mst(since)')
        self.con.execute(
            "CREATE TABLE record(\n                repo INTEGER NOT NULL,\n                nsid TEXT NOT NULL,\n                rkey TEXT NOT NULL,\n                cid BLOB NOT NULL,\n                since TEXT NOT NULL,\n                value BLOB NOT NULL,\n                FOREIGN KEY (repo) REFERENCES user(id),\n                PRIMARY KEY (repo, nsid, rkey)\n            )"
        )
        self.con.execute('CREATE INDEX record_since ON record(since)')
        self.con.execute(
            "CREATE TABLE blob(\n                id INTEGER PRIMARY KEY NOT NULL,\n                repo INTEGER NOT NULL,\n                cid BLOB,\n                refcount INTEGER NOT NULL,\n                since TEXT,\n                FOREIGN KEY (repo) REFERENCES user(id)\n            )"
        )
        self.con.execute('CREATE INDEX blob_isrefd ON blob(refcount, refcount > 0)')
        self.con.execute('CREATE UNIQUE INDEX blob_repo_cid ON blob(repo, cid)')
        self.con.execute('CREATE INDEX blob_since ON blob(since)')
        self.con.execute(
            "CREATE TABLE blob_part(\n                blob INTEGER NOT NULL,\n                idx INTEGER NOT NULL,\n                data BLOB NOT NULL,\n                PRIMARY KEY (blob, idx),\n                FOREIGN KEY (blob) REFERENCES blob(id)\n            )"
        )

    def update_config(self, pds_pfx: Optional[str] = None, pds_did: Optional[str] = None, bsky_appview_pfx: Optional[str] = None, bsky_appview_did: Optional[str] = None) -> None:
        with self.con:
            if pds_pfx is not None:
                self.con.execute('UPDATE config SET pds_pfx=?', (pds_pfx,))
            if pds_did is not None:
                self.con.execute('UPDATE config SET pds_did=?', (pds_did,))
            if bsky_appview_pfx is not None:
                self.con.execute('UPDATE config SET bsky_appview_pfx=?', (bsky_appview_pfx,))
            if bsky_appview_did is not None:
                self.con.execute('UPDATE config SET bsky_appview_did=?', (bsky_appview_did,))

        try:
            del self.config
        except AttributeError:
            pass

    @cached_property
    def config(self) -> Dict[str, object]:
        config_fields = (
            'db_version',
            'pds_pfx',
            'pds_did',
            'bsky_appview_pfx',
            'bsky_appview_did',
            'jwt_access_secret'
        )

        cfg = self.con.execute(
            f"SELECT {', '.join(config_fields)} FROM config"
        ).fetchone()

        return dict(zip(config_fields, cfg))

    def config_is_initialised(self) -> bool:
        return all(v is not None for v in self.config.values())

    def print_config(self, redact_secrets: bool = True) -> None:
        maxlen = max(map(len, self.config))
        for k, v in self.config.items():
            if redact_secrets and 'secret' in k:
                v = '[REDACTED]'
            print(f"{k:<{maxlen}} : {v!r}")

    def create_account(self, did: str, handle: str, password: str, privkey: crypto.ec.EllipticCurvePrivateKey) -> None:
        pw_hash = self.pw_hasher.hash(password)
        privkey_pem = crypto.privkey_to_pem(privkey)
        logger.info(f"creating account for did={did}, handle={handle}")

        with self.con:
            tid = util.tid_now()
            empty_mst = MSTNode.empty_root()
            initial_commit = {
                'did': did,
                'version': static_config.ATPROTO_REPO_VERSION_3,
                'data': empty_mst.cid,
                'rev': tid,
                'prev': None
            }
            initial_commit['sig'] = crypto.raw_sign(
                privkey, cbrrr.encode_dag_cbor(initial_commit)
            )
            commit_bytes = cbrrr.encode_dag_cbor(initial_commit)
            commit_cid = cbrrr.CID.cidv1_dag_cbor_sha256_32_from(commit_bytes)
            self.con.execute(
                """
                INSERT INTO user(\n                    did,\n                    handle,\n                    prefs,\n                    pw_hash,\n                    signing_key,\n                    head,\n                    rev,\n                    commit_bytes\n                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (did,\n                 handle,\n                 b"{}",\n                 pw_hash,\n                 privkey_pem,\n                 bytes(commit_cid),\n                 tid,\n                 commit_bytes)
            )
            user_id = self.con.last_insert_rowid()
            self.con.execute(
                'INSERT INTO mst(repo, cid, since, value) VALUES (?, ?, ?, ?)', (user_id, bytes(empty_mst.cid), tid, empty_mst.serialised)
            )

    def verify_account_login(self, did_or_handle: str, password: str) -> Tuple[str, str, str, str]:
        row = self.con.execute(
            'SELECT did, handle, pw_hash FROM user WHERE did=? OR handle=?', (did_or_handle, did_or_handle))
        if row is None:
            raise KeyError('no account found for did')
        did, handle, pw_hash = row
        try:
            self.pw_hasher.verify(pw_hash, password)
        except argon2.exceptions.VerifyMismatchError:
            raise ValueError('invalid password')
        return did, handle

    def did_by_handle(self, handle: str) -> Optional[str]:
        row = self.con.execute('SELECT did FROM user WHERE handle=?', (handle,)).fetchone()
        if row is None:
            return None
        return row[0]

    def handle_by_did(self, did: str) -> Optional[str]:
        row = self.con.execute('SELECT handle FROM user WHERE did=?', (did,)).fetchone()
        if row is None:
            return None
        return row[0]

    def signing_key_pem_by_did(self, did: str) -> Optional[str]:
        row = self.con.execute('SELECT signing_key FROM user WHERE did=?', (did,)).fetchone()
        if row is None:
            return None
        return row[0]

    def list_repos(self) -> List[Tuple[str, cbrrr.CID, str]]:
        return [
            (did, cbrrr.CID(head), rev) for did, head, rev in self.con.execute('SELECT did, head, rev FROM user').fetchall()
        ]

    def get_blockstore(self, did: str) -> 'Database':
        return DBBlockStore(self, did)
