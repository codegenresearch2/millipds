from typing import Optional, Dict, List, Tuple
from functools import cached_property
import secrets
import logging
import json

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
    """
    Adapt the db for consumption by the atmst library
    """
    def __init__(self, db: apsw.Connection, repo: str) -> None:
        self.db = db
        self.user_id = self.db.execute(
            "SELECT id FROM user WHERE did=?", (repo,)
        ).fetchone()
        if self.user_id is None:
            raise ValueError(f"No user found with DID: {repo}")
        self.user_id = self.user_id[0]

    def get_block(self, key: bytes) -> bytes:
        """
        Retrieve a block from the database by its key.

        Args:
            key (bytes): The key of the block to retrieve.

        Returns:
            bytes: The value of the block.

        Raises:
            KeyError: If the block is not found in the database.
        """
        row = self.db.execute(
            "SELECT value FROM mst WHERE repo=? AND cid=?", (self.user_id, key)
        ).fetchone()
        if row is None:
            raise KeyError("block not found in db")
        return row[0]

    def del_block(self, key: bytes) -> None:
        """
        Delete a block from the database by its key.

        Args:
            key (bytes): The key of the block to delete.

        Raises:
            NotImplementedError: If the method is not implemented yet.
        """
        raise NotImplementedError("TODO?")

    def put_block(self, key: bytes, value: bytes) -> None:
        """
        Put a block into the database with the given key and value.

        Args:
            key (bytes): The key of the block.
            value (bytes): The value of the block.

        Raises:
            NotImplementedError: If the method is not implemented yet.
        """
        raise NotImplementedError("TODO?")

class Database:
    """
    A class representing the database for the application.
    """
    def __init__(self, path: str = static_config.MAIN_DB_PATH) -> None:
        logger.info(f"opening database at {path}")
        self.path = path
        util.mkdirs_for_file(path)
        self.con = self.new_con()
        self.pw_hasher = argon2.PasswordHasher()

        try:
            if self.config["db_version"] != static_config.MILLIPDS_DB_VERSION:
                raise Exception(
                    "unrecognised db version (TODO: db migrations?!)"
                )
        except apsw.SQLError as e:
            if "no such table" not in str(e):
                raise
            self._init_tables()

    def new_con(self, readonly=False) -> apsw.Connection:
        """
        Create a new database connection.

        Args:
            readonly (bool, optional): Whether the connection should be read-only. Defaults to False.

        Returns:
            apsw.Connection: The new database connection.
        """
        return apsw.Connection(
            self.path,
            flags=(
                apsw.SQLITE_OPEN_READONLY
                if readonly
                else apsw.SQLITE_OPEN_READWRITE | apsw.SQLITE_OPEN_CREATE
            ),
        )

    def _init_tables(self) -> None:
        """
        Initialize the database tables.
        """
        logger.info("initing tables")
        with self.con:
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
                CREATE TABLE firehose(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    msg BLOB NOT NULL
                )
                """
            )

            self.con.execute(
                """
                CREATE TABLE mst(
                    repo INTEGER NOT NULL,
                    cid BLOB NOT NULL,
                    since TEXT NOT NULL,
                    value BLOB NOT NULL,
                    FOREIGN KEY (repo) REFERENCES user(id),
                    PRIMARY KEY (repo, cid)
                )
                """
            )
            self.con.execute("CREATE INDEX mst_since ON mst(since)")

            self.con.execute(
                """
                CREATE TABLE record(
                    repo INTEGER NOT NULL,
                    nsid TEXT NOT NULL,
                    rkey TEXT NOT NULL,
                    cid BLOB NOT NULL,
                    since TEXT NOT NULL,
                    value BLOB NOT NULL,
                    FOREIGN KEY (repo) REFERENCES user(id),
                    PRIMARY KEY (repo, nsid, rkey)
                )
                """
            )
            self.con.execute("CREATE INDEX record_since ON record(since)")

            self.con.execute(
                """
                CREATE TABLE blob(
                    id INTEGER PRIMARY KEY NOT NULL,
                    repo INTEGER NOT NULL,
                    cid BLOB,
                    refcount INTEGER NOT NULL,
                    since TEXT,
                    FOREIGN KEY (repo) REFERENCES user(id)
                )
                """
            )
            self.con.execute(
                "CREATE INDEX blob_isrefd ON blob(refcount, refcount > 0)"
            )
            self.con.execute("CREATE UNIQUE INDEX blob_repo_cid ON blob(repo, cid)")
            self.con.execute("CREATE INDEX blob_since ON blob(since)")

            self.con.execute(
                """
                CREATE TABLE blob_part(
                    blob INTEGER NOT NULL,
                    idx INTEGER NOT NULL,
                    data BLOB NOT NULL,
                    PRIMARY KEY (blob, idx),
                    FOREIGN KEY (blob) REFERENCES blob(id)
                )
                """
            )

    def update_config(
        self,
        pds_pfx: Optional[str] = None,
        pds_did: Optional[str] = None,
        bsky_appview_pfx: Optional[str] = None,
        bsky_appview_did: Optional[str] = None,
    ) -> None:
        """
        Update the configuration in the database.

        Args:
            pds_pfx (Optional[str], optional): The new PDS prefix. Defaults to None.
            pds_did (Optional[str], optional): The new PDS DID. Defaults to None.
            bsky_appview_pfx (Optional[str], optional): The new AppView prefix. Defaults to None.
            bsky_appview_did (Optional[str], optional): The new AppView DID. Defaults to None.
        """
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
            del self.config
        except AttributeError:
            pass

    @cached_property
    def config(self) -> Dict[str, object]:
        """
        Get the configuration from the database.

        Returns:
            Dict[str, object]: The configuration as a dictionary.

        Raises:
            ValueError: If the configuration is not initialized.
        """
        config_fields = (
            "db_version",
            "pds_pfx",
            "pds_did",
            "bsky_appview_pfx",
            "bsky_appview_did",
            "jwt_access_secret",
        )

        cfg = self.con.execute(
            f"SELECT {', '.join(config_fields)} FROM config"
        ).fetchone()

        if cfg is None:
            raise ValueError("Config not initialized")

        return dict(zip(config_fields, cfg))

    def config_is_initialised(self) -> bool:
        """
        Check if the configuration is initialized.

        Returns:
            bool: True if the configuration is initialized, False otherwise.
        """
        return all(v is not None for v in self.config.values())

    def print_config(self, redact_secrets: bool = True) -> None:
        """
        Print the configuration.

        Args:
            redact_secrets (bool, optional): Whether to redact secrets in the output. Defaults to True.
        """
        maxlen = max(map(len, self.config))
        for k, v in self.config.items():
            if redact_secrets and "secret" in k:
                v = "[REDACTED]"
            print(f"{k:<{maxlen}} : {v!r}")

    def create_account(
        self,
        did: str,
        handle: str,
        password: str,
        privkey: crypto.ec.EllipticCurvePrivateKey,
    ) -> None:
        """
        Create a new account in the database.

        Args:
            did (str): The DID of the account.
            handle (str): The handle of the account.
            password (str): The password of the account.
            privkey (crypto.ec.EllipticCurvePrivateKey): The private key of the account.
        """
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
                """
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
                """,
                (
                    did,
                    handle,
                    b'{"preferences":[]}',
                    pw_hash,
                    privkey_pem,
                    bytes(commit_cid),
                    tid,
                    commit_bytes,
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
        """
        Verify the login credentials for an account.

        Args:
            did_or_handle (str): The DID or handle of the account.
            password (str): The password of the account.

        Returns:
            Tuple[str, str, str, str]: The DID, handle, and other account information.

        Raises:
            KeyError: If no account is found for the given DID or handle.
            ValueError: If the password is invalid.
        """
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
        return did, handle

    def did_by_handle(self, handle: str) -> Optional[str]:
        """
        Get the DID of an account by its handle.

        Args:
            handle (str): The handle of the account.

        Returns:
            Optional[str]: The DID of the account, or None if no account is found.
        """
        row = self.con.execute(
            "SELECT did FROM user WHERE handle=?", (handle,)
        ).fetchone()
        if row is None:
            return None
        return row[0]

    def handle_by_did(self, did: str) -> Optional[str]:
        """
        Get the handle of an account by its DID.

        Args:
            did (str): The DID of the account.

        Returns:
            Optional[str]: The handle of the account, or None if no account is found.
        """
        row = self.con.execute(
            "SELECT handle FROM user WHERE did=?", (did,)
        ).fetchone()
        if row is None:
            return None
        return row[0]

    def signing_key_pem_by_did(self, did: str) -> Optional[str]:
        """
        Get the signing key PEM of an account by its DID.

        Args:
            did (str): The DID of the account.

        Returns:
            Optional[str]: The signing key PEM of the account, or None if no account is found.
        """
        row = self.con.execute(
            "SELECT signing_key FROM user WHERE did=?", (did,)
        ).fetchone()
        if row is None:
            return None
        return row[0]

    def list_repos(
        self,
    ) -> List[Tuple[str, cbrrr.CID, str]]:
        """
        List all repositories in the database.

        Returns:
            List[Tuple[str, cbrrr.CID, str]]: A list of tuples containing the DID, head CID, and revision of each repository.
        """
        repos = self.con.execute(
            "SELECT did, head, rev FROM user"
        ).fetchall()
        if not repos:
            return []
        return [(did, cbrrr.CID(head), rev) for did, head, rev in repos]

    def get_blockstore(self, did: str) -> "DBBlockStore":
        """
        Get the blockstore for a repository by its DID.

        Args:
            did (str): The DID of the repository.

        Returns:
            DBBlockStore: The blockstore for the repository.
        """
        return DBBlockStore(self.con, did)

    def get_preferences(self, did: str) -> Dict[str, object]:
        """
        Get the preferences of a user by their DID.

        Args:
            did (str): The DID of the user.

        Returns:
            Dict[str, object]: The preferences of the user.

        Raises:
            KeyError: If no account is found for the given DID.
        """
        row = self.con.execute(
            "SELECT prefs FROM user WHERE did=?", (did,)
        ).fetchone()
        if row is None:
            raise KeyError("no account found for did")
        return json.loads(row[0])

    def set_preferences(self, did: str, prefs: Dict[str, object]) -> None:
        """
        Set the preferences of a user by their DID.

        Args:
            did (str): The DID of the user.
            prefs (Dict[str, object]): The preferences to set.
        """
        with self.con:
            self.con.execute(
                "UPDATE user SET prefs=? WHERE did=?",
                (json.dumps(prefs), did),
            )

    def get_response_structure(self, success: bool, data: Optional[Dict[str, object]] = None) -> Dict[str, object]:
        """
        Get a response structure with the given success status and data.

        Args:
            success (bool): The success status of the response.
            data (Optional[Dict[str, object]], optional): The data to include in the response. Defaults to None.

        Returns:
            Dict[str, object]: The response structure.
        """
        response = {"success": success}
        if data is not None:
            response["data"] = data
        return response