from typing import Optional, Dict, List, Tuple
from functools import cached_property
import secrets
import logging
import time

import jwt
import argon2
import apsw
import apsw.bestpractice

import cbrrr
from atmst.blockstore import BlockStore
from atmst.mst.node import MSTNode

from . import static_config
from . import util
from . import crypto

logger = logging.getLogger(__name__)

apsw.bestpractice.apply(apsw.bestpractice.recommended)

class DBBlockStore(BlockStore):
    def __init__(self, db: apsw.Connection, repo: str) -> None:
        self.db = db
        self.user_id = self.db.execute(
            "SELECT id FROM user WHERE did=?", (repo,)
        ).fetchone()[0]

    def get_block(self, key: bytes) -> bytes:
        row = self.db.execute(
            "SELECT value FROM mst WHERE repo=? AND cid=?", (self.user_id, key)
        ).fetchone()
        if row is None:
            raise KeyError("block not found in db")
        return row[0]

    def del_block(self, key: bytes) -> None:
        raise NotImplementedError("TODO?")

    def put_block(self, key: bytes, value: bytes) -> None:
        raise NotImplementedError("TODO?")

class Database:
    def __init__(self, path: str = static_config.MAIN_DB_PATH) -> None:
        logger.info(f"opening database at {path}")
        self.path = path
        if "/" in path:
            util.mkdirs_for_file(path)
        self.con = self.new_con()
        self.pw_hasher = argon2.PasswordHasher()

        config_exists = self.con.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='config'"
        ).fetchone()[0]

        if config_exists:
            if self.config["db_version"] != static_config.MILLIPDS_DB_VERSION:
                raise Exception(
                    "unrecognised db version (TODO: db migrations?!)"
                )
        else:
            with self.con:
                self._init_tables()

    def new_con(self, readonly=False):
        return apsw.Connection(
            self.path,
            flags=(
                apsw.SQLITE_OPEN_READONLY
                if readonly
                else apsw.SQLITE_OPEN_READWRITE | apsw.SQLITE_OPEN_CREATE
            ),
        )

    def _init_tables(self):
        logger.info("initing tables")
        self.con.execute(
            """\n            CREATE TABLE config(\n                db_version INTEGER NOT NULL,\n                pds_pfx TEXT,\n                pds_did TEXT,\n                bsky_appview_pfx TEXT,\n                bsky_appview_did TEXT,\n                jwt_access_secret TEXT NOT NULL,\n                jwt_revoked_tokens TEXT\n            ) STRICT\n            """
        )

        self.con.execute(
            """\n            INSERT INTO config(\n                db_version,\n                jwt_access_secret\n            ) VALUES (?, ?)\n            """,
            (static_config.MILLIPDS_DB_VERSION, secrets.token_hex()),
        )

        self.con.execute(
            """\n            CREATE TABLE user(\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                did TEXT NOT NULL,\n                handle TEXT NOT NULL,\n                prefs BLOB NOT NULL,\n                pw_hash TEXT NOT NULL,\n                signing_key TEXT NOT NULL,\n                head BLOB NOT NULL,\n                rev TEXT NOT NULL,\n                commit_bytes BLOB NOT NULL,\n                jwt_revoked_tokens TEXT\n            ) STRICT\n            """
        )

        self.con.execute("CREATE UNIQUE INDEX user_by_did ON user(did)")
        self.con.execute("CREATE UNIQUE INDEX user_by_handle ON user(handle)")

        # ... rest of the code ...

    def update_config(
        self,
        pds_pfx: Optional[str] = None,
        pds_did: Optional[str] = None,
        bsky_appview_pfx: Optional[str] = None,
        bsky_appview_did: Optional[str] = None,
    ):
        with self.con:
            if pds_pfx is not None:
                self.con.execute("UPDATE config SET pds_pfx=?", (pds_pfx,))
            if pds_did is not None:
                self.con.execute("UPDATE config SET pds_did=?", (pds_did,))
            if bsky_appview_pfx is not None:
                self.con.execute(
                    "UPDATE config SET bsky_appview_pfx=?", (bsky_appview_pfx,)
                )
            if bsky_appview_did is not None:
                self.con.execute(
                    "UPDATE config SET bsky_appview_did=?", (bsky_appview_did,)
                )

        try:
            del self.config  # invalidate the cached value
        except AttributeError:
            pass

    @cached_property
    def config(self) -> Dict[str, object]:
        config_fields = (
            "db_version",
            "pds_pfx",
            "pds_did",
            "bsky_appview_pfx",
            "bsky_appview_did",
            "jwt_access_secret",
            "jwt_revoked_tokens",
        )

        cfg = self.con.execute(
            f"SELECT {', '.join(config_fields)} FROM config"
        ).fetchone()

        return dict(zip(config_fields, cfg))

    def create_account(
        self,
        did: str,
        handle: str,
        password: str,
        privkey: crypto.ec.EllipticCurvePrivateKey,
    ) -> None:
        pw_hash = self.pw_hasher.hash(password)
        privkey_pem = crypto.privkey_to_pem(privkey)
        logger.info(f"creating account for did={did}, handle={handle}")

        with self.con:
            tid = util.tid_now()
            empty_mst = MSTNode.empty_root()
            initial_commit = {
                "did": did,
                "version": static_config.ATPROTO_REPO_VERSION_3,
                "data": empty_mst.cid,
                "rev": tid,
                "prev": None,
            }
            initial_commit["sig"] = crypto.raw_sign(
                privkey, cbrrr.encode_dag_cbor(initial_commit)
            )
            commit_bytes = cbrrr.encode_dag_cbor(initial_commit)
            commit_cid = cbrrr.CID.cidv1_dag_cbor_sha256_32_from(commit_bytes)
            self.con.execute(
                """\n                INSERT INTO user(\n                    did,\n                    handle,\n                    prefs,\n                    pw_hash,\n                    signing_key,\n                    head,\n                    rev,\n                    commit_bytes,\n                    jwt_revoked_tokens\n                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)\n                """,
                (
                    did,
                    handle,
                    b'{"preferences":[]}',
                    pw_hash,
                    privkey_pem,
                    bytes(commit_cid),
                    tid,
                    commit_bytes,
                    "",
                ),
            )
            user_id = self.con.last_insert_rowid()
            self.con.execute(
                "INSERT INTO mst(repo, cid, since, value) VALUES (?, ?, ?, ?)",
                (user_id, bytes(empty_mst.cid), tid, empty_mst.serialised),
            )

    def verify_account_login(
        self, did_or_handle: str, password: str
    ) -> Tuple[str, str, str, str]:
        row = self.con.execute(
            "SELECT did, handle, pw_hash FROM user WHERE did=? OR handle=?",
            (did_or_handle, did_or_handle),
        ).fetchone()
        if row is None:
            raise KeyError("no account found for did")
        did, handle, pw_hash = row
        try:
            self.pw_hasher.verify(pw_hash, password)
        except argon2.exceptions.VerifyMismatchError:
            raise ValueError("invalid password")

        # Add JWT revocation check
        jwt_revoked_tokens = self.con.execute(
            "SELECT jwt_revoked_tokens FROM user WHERE did=?", (did,)
        ).fetchone()[0]
        if jwt_revoked_tokens:
            revoked_tokens = jwt_revoked_tokens.split(",")
            if password in revoked_tokens:
                raise ValueError("token has been revoked")

        return did, handle

    def generate_jwt(self, did: str, handle: str) -> str:
        payload = {
            "iss": self.config["pds_did"],
            "sub": did,
            "exp": int(time.time()) + 3600,
            "handle": handle,
        }
        return jwt.encode(payload, self.config["jwt_access_secret"], algorithm="HS256")

    def revoke_jwt(self, did: str, token: str) -> None:
        with self.con:
            revoked_tokens = self.con.execute(
                "SELECT jwt_revoked_tokens FROM user WHERE did=?", (did,)
            ).fetchone()[0]
            if revoked_tokens:
                revoked_tokens += "," + token
            else:
                revoked_tokens = token
            self.con.execute(
                "UPDATE user SET jwt_revoked_tokens=? WHERE did=?",
                (revoked_tokens, did),
            )

    # ... rest of the code ...