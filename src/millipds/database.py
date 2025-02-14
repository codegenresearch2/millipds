"""\nIdeally, all SQL statements are contained within this file.\n\nPassword hashing also happens in here, because it doesn't make much sense to do\nit anywhere else.\n"""

from typing import Optional, Dict, List, Tuple
from functools import cached_property
import secrets
import logging
import jwt

import argon2  # maybe this should come from .crypto?
import apsw
import apsw.bestpractice

import cbrrr
from atmst.blockstore import BlockStore
from atmst.mst.node import MSTNode

from . import static_config
from . import util
from . import crypto

logger = logging.getLogger(__name__)

# https://rogerbinns.github.io/apsw/bestpractice.html
apsw.bestpractice.apply(apsw.bestpractice.recommended)

class DBBlockStore(BlockStore):
    """\n    Adapt the db for consumption by the atmst library\n    """

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
        """\n        https://rogerbinns.github.io/apsw/cursor.html\n        "Cursors on the same Connection are not isolated from each other.
        Anything done on one cursor is immediately visible to all other Cursors
        on the same connection. This still applies if you start transactions.
        Connections are isolated from each other with cursors on other
        connections not seeing changes until they are committed."\n\n        therefore we frequently spawn new connections when we need an isolated cursor\n        """
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
            """\n            CREATE TABLE config(\n                db_version INTEGER NOT NULL,\n                pds_pfx TEXT,\n                pds_did TEXT,\n                bsky_appview_pfx TEXT,\n                bsky_appview_did TEXT,\n                jwt_access_secret TEXT NOT NULL\n            ) STRICT\n            """
        )

        self.con.execute(
            """\n            INSERT INTO config(\n                db_version,\n                jwt_access_secret\n            ) VALUES (?, ?)\n            """,
            (static_config.MILLIPDS_DB_VERSION, secrets.token_hex()),
        )

        # TODO: head and rev are redundant, technically (rev contained within commit_bytes)
        self.con.execute(
            """\n            CREATE TABLE user(\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                did TEXT NOT NULL,\n                handle TEXT NOT NULL,\n                prefs BLOB NOT NULL,\n                pw_hash TEXT NOT NULL,\n                signing_key TEXT NOT NULL,\n                head BLOB NOT NULL,\n                rev TEXT NOT NULL,\n                commit_bytes BLOB NOT NULL,\n                jti TEXT,\n                sub TEXT\n            ) STRICT\n            """
        )

        self.con.execute("CREATE UNIQUE INDEX user_by_did ON user(did)")
        self.con.execute("CREATE UNIQUE INDEX user_by_handle ON user(handle)")

        # rest of the code...

    def verify_account_login(
        self, did_or_handle: str, password: str
    ) -> Tuple[str, str, str, str]:
        row = self.con.execute(
            "SELECT did, handle, pw_hash, jti, sub FROM user WHERE did=? OR handle=?",
            (did_or_handle, did_or_handle),
        ).fetchone()
        if row is None:
            raise KeyError("no account found for did")
        did, handle, pw_hash, jti, sub = row
        try:
            self.pw_hasher.verify(pw_hash, password)
        except argon2.exceptions.VerifyMismatchError:
            raise ValueError("invalid password")

        # Validate JWT against revoked tokens
        self.validate_jwt(jti, sub)

        return did, handle

    def validate_jwt(self, jti: str, sub: str) -> None:
        # Fetch revoked tokens from the database
        revoked_tokens = self.con.execute(
            "SELECT jti FROM revoked_tokens WHERE jti=? AND sub=?", (jti, sub)
        ).fetchone()

        if revoked_tokens:
            raise ValueError("JWT is revoked")

        # Add additional claims validation logic if needed

    def create_access_token(self, did: str, handle: str) -> str:
        # Add 'jti' and 'sub' claims to the JWT
        payload = {
            "sub": did,
            "handle": handle,
            "jti": secrets.token_hex(16),  # Generate a unique identifier for each token
            # Add additional claims as needed
        }

        # Sign the JWT with the access secret
        access_token = jwt.encode(payload, self.config["jwt_access_secret"], algorithm="HS256")

        # Store the 'jti' and 'sub' in the database
        with self.con:
            self.con.execute(
                "UPDATE user SET jti=?, sub=? WHERE did=?", (payload["jti"], payload["sub"], did)
            )

        return access_token