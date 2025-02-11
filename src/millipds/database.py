"""
Ideally, all SQL statements are contained within this file.

Password hashing also happens in here, because it doesn't make much sense to do
it anywhere else.
"""

from typing import Optional, Dict, List, Tuple
from functools import cached_property
import secrets
import logging

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
    """
    Adapt the db for consumption by the atmst library
    """

    def __init__(self, db: apsw.Connection, repo: str) -> None:
        self.db = db
        self.user_id = self.db.execute(
            "SELECT user_id FROM handle_cache WHERE handle=?", (repo,)
        ).fetchone()
        if self.user_id is None:
            raise ValueError(f"No user found with handle: {repo}")
        self.user_id = self.user_id[0]

    def get_block(self, key: bytes) -> bytes:
        row = self.db.execute(
            "SELECT value FROM mst WHERE repo=? AND cid=?", (self.user_id, key)
        ).fetchone()
        if row is None:
            raise KeyError("Block not found in database")
        return row[0]

    def del_block(self, key: bytes) -> None:
        raise NotImplementedError("TODO?")

    def put_block(self, key: bytes, value: bytes) -> None:
        raise NotImplementedError("TODO?")

class Database:
    def __init__(self, path: str = static_config.MAIN_DB_PATH) -> None:
        logger.info(f"Opening database at {path}")
        self.path = path
        if "/" in path:
            util.mkdirs_for_file(path)
        self.con = self.new_con()
        self.pw_hasher = argon2.PasswordHasher()

        try:
            if self.config["db_version"] != static_config.MILLIPDS_DB_VERSION:
                raise Exception(
                    "Unrecognized database version (TODO: db migrations?)"
                )
        except apsw.SQLError as e:
            if "no such table" in str(e):
                logger.warning("Database schema not initialized. Initializing now.")
                with self.con:
                    self._init_tables()
                    self._populate_test_data()
            else:
                raise

    def new_con(self, readonly=False):
        """
        https://rogerbinns.github.io/apsw/cursor.html
        "Cursors on the same Connection are not isolated from each other.
        Anything done on one cursor is immediately visible to all other Cursors
        on the same connection. This still applies if you start transactions.
        Connections are isolated from each other with cursors on other
        connections not seeing changes until they are committed."

        Therefore, we frequently spawn new connections when we need an isolated cursor
        """
        return apsw.Connection(
            self.path,
            flags=(
                apsw.SQLITE_OPEN_READONLY
                if readonly
                else apsw.SQLITE_OPEN_READWRITE | apsw.SQLITE_OPEN_CREATE
            ),
        )

    def _init_tables(self):
        logger.info("Initializing tables")
        self.con.execute(
            """
            CREATE TABLE config(
                db_version INTEGER NOT NULL,
                pds_pfx TEXT,
                pds_did TEXT,
                bsky_appview_pfx TEXT,
                bsky_appview_did TEXT,
                jwt_access_secret TEXT NOT NULL
            )
            """
        )

        self.con.execute(
            """
            INSERT INTO config(
                db_version,
                jwt_access_secret
            ) VALUES (?, ?)
            """,
            (static_config.MILLIPDS_DB_VERSION, secrets.token_hex()),
        )

        # TODO: head and rev are redundant, technically (rev contained within commit_bytes)
        self.con.execute(
            """
            CREATE TABLE user(
                id INTEGER PRIMARY KEY NOT NULL,
                did TEXT NOT NULL,
                handle TEXT NOT NULL,
                prefs BLOB NOT NULL,
                pw_hash TEXT NOT NULL,
                signing_key TEXT NOT NULL,
                head BLOB NOT NULL,
                rev TEXT NOT NULL,
                commit_bytes BLOB NOT NULL
            )
            """
        )

        self.con.execute("CREATE UNIQUE INDEX user_by_did ON user(did)")
        self.con.execute("CREATE UNIQUE INDEX user_by_handle ON user(handle)")

        self.con.execute(
            """
            CREATE TABLE handle_cache(
                handle TEXT PRIMARY KEY NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES user(id)
            )
            """
        )

    def _populate_test_data(self):
        logger.info("Populating test data")
        # Add code to populate the database with a default user and associated handle
        # This will ensure that the DBBlockStore can find a user when it is instantiated

    # ... rest of the code ...