"""\nIdeally, all SQL statements are contained within this file.\n\nPassword hashing also happens in here, because it doesn't make much sense to do\nit anywhere else.\n"""

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
	"""\n	Adapt the db for consumption by the atmst library\n	"""

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
		"""\n		https://rogerbinns.github.io/apsw/cursor.html\n		"Cursors on the same Connection are not isolated from each other.
		Anything done on one cursor is immediately visible to all other Cursors
		on the same connection. This still applies if you start transactions.
		Therefore we frequently spawn new connections when we need an isolated cursor
		"""\n		return apsw.Connection(\n			self.path,\n			flags=(\n				apsw.SQLITE_OPEN_READONLY\n				if readonly\n				else apsw.SQLITE_OPEN_READWRITE | apsw.SQLITE_OPEN_CREATE\n			),\n		)\n\n	def _init_tables(self):\n		logger.info("initing tables")\n		self.con.execute(\n			"""
			CREATE TABLE config(
				db_version INTEGER NOT NULL,
				pds_pfx TEXT,
				pds_did TEXT,
				bsky_appview_pfx TEXT,
				bsky_appview_did TEXT,
				jwt_access_secret TEXT NOT NULL
			) STRICT
			"""\n		)\n\n		self.con.execute(\n			"""
			INSERT INTO config(
				db_version,
				jwt_access_secret
			) VALUES (?, ?)
			""",\n			(static_config.MILLIPDS_DB_VERSION, secrets.token_hex()),\n		)\n\n		self.con.execute(\n			"""
			CREATE TABLE user(
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				did TEXT NOT NULL,
				handle TEXT NOT NULL,
				prefs BLOB NOT NULL,
				pw_hash TEXT NOT NULL,
				signing_key TEXT NOT NULL,
				head BLOB NOT NULL,
				rev TEXT NOT NULL,
				commit_bytes BLOB NOT NULL
			) STRICT
			"""\n		)\n\n		self.con.execute("CREATE UNIQUE INDEX user_by_did ON user(did)")\n		self.con.execute("CREATE UNIQUE INDEX user_by_handle ON user(handle)")\n\n		self.con.execute(\n			"""
			CREATE TABLE firehose(
				seq INTEGER PRIMARY KEY AUTOINCREMENT,
				timestamp INTEGER NOT NULL,
				msg BLOB NOT NULL
			) STRICT
			"""\n		)\n\n		self.con.execute(\n			"""
			CREATE TABLE mst(
				repo INTEGER NOT NULL,
				cid BLOB NOT NULL,
				since TEXT NOT NULL,
				value BLOB NOT NULL,
				FOREIGN KEY (repo) REFERENCES user(id),
				PRIMARY KEY (repo, cid)
			) STRICT, WITHOUT ROWID
			"""\n		)\n		self.con.execute("CREATE INDEX mst_since ON mst(since)")\n\n		self.con.execute(\n			"""
			CREATE TABLE record(
				repo INTEGER NOT NULL,
				nsid TEXT NOT NULL,
				rkey TEXT NOT NULL,
				cid BLOB NOT NULL,
				since TEXT NOT NULL,
				value BLOB NOT NULL,
				FOREIGN KEY (repo) REFERENCES user(id),
				PRIMARY KEY (repo, nsid, rkey)
			) STRICT, WITHOUT ROWID
			"""\n		)\n		self.con.execute("CREATE INDEX record_since ON record(since)")\n\n		self.con.execute(\n			"""
			CREATE TABLE blob(
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				repo INTEGER NOT NULL,
				cid BLOB,
				refcount INTEGER NOT NULL,
				since TEXT,
				FOREIGN KEY (repo) REFERENCES user(id)
			) STRICT
			"""\n		)\n		self.con.execute(\n			"CREATE INDEX blob_isrefd ON blob(refcount, refcount > 0)"\n		)\n		self.con.execute("CREATE UNIQUE INDEX blob_repo_cid ON blob(repo, cid)")\n		self.con.execute("CREATE INDEX blob_since ON blob(since)")\n\n		self.con.execute(\n			"""
			CREATE TABLE blob_part(
				blob INTEGER NOT NULL,
				idx INTEGER NOT NULL,
				data BLOB NOT NULL,
				PRIMARY KEY (blob, idx),
				FOREIGN KEY (blob) REFERENCES blob(id)
			) STRICT, WITHOUT ROWID
			"""\n		)\n\n		self.con.execute(\n			"""
			CREATE TABLE did_cache(
				did TEXT PRIMARY KEY NOT NULL,
				doc BLOB,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL
			) STRICT, WITHOUT ROWID
			"""\n		)\n\n		self.con.execute(\n			"""
			CREATE TABLE handle_cache(
				handle TEXT PRIMARY KEY NOT NULL,
				did TEXT,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL
			) STRICT, WITHOUT ROWID
			"""\n		)\n\n	def update_config(\n		self,\n		pds_pfx: Optional[str] = None,\n		pds_did: Optional[str] = None,\n		bsky_appview_pfx: Optional[str] = None,\n		bsky_appview_did: Optional[str] = None,\n	):\n		with self.con:\n			if pds_pfx is not None:\n				self.con.execute("UPDATE config SET pds_pfx=?", (pds_pfx,))\n			if pds_did is not None:\n				self.con.execute("UPDATE config SET pds_did=?", (pds_did,))\n			if bsky_appview_pfx is not None:\n				self.con.execute(\n					"UPDATE config SET bsky_appview_pfx=?", (bsky_appview_pfx,)\n				)\n			if bsky_appview_did is not None:\n				self.con.execute(\n					"UPDATE config SET bsky_appview_did=?", (bsky_appview_did,)\n				)\n\n		try:\n			del self.config  # invalidate the cached value\n		except AttributeError:\n			pass\n\n	@cached_property\n	def config(self) -> Dict[str, object]:\n		config_fields = (\n			"db_version",\n			"pds_pfx",\n			"pds_did",\n			"bsky_appview_pfx",\n			"bsky_appview_did",\n			"jwt_access_secret",\n		)\n\n		cfg = self.con.execute(\n			f"SELECT {', '.join(config_fields)} FROM config"\n		).fetchone()\n\n		return dict(zip(config_fields, cfg))\n\n	def config_is_initialised(self) -> bool:\n		return all(v is not None for v in self.config.values())\n\n	def print_config(self, redact_secrets: bool = True) -> None:\n		maxlen = max(map(len, self.config))\n		for k, v in self.config.items():\n			if redact_secrets and "secret" in k:\n				v = "[REDACTED]"\n			print(f"{k:<{maxlen}} : {v!r}")\n\n	def create_account(\n		self,\n		did: str,\n		handle: str,\n		password: str,\n		privkey: crypto.ec.EllipticCurvePrivateKey,\n	) -> None:\n		pw_hash = self.pw_hasher.hash(password)\n		privkey_pem = crypto.privkey_to_pem(privkey)\n		logger.info(f"creating account for did={did}, handle={handle}")\n\n		with self.con:\n			tid = util.tid_now()\n			empty_mst = MSTNode.empty_root()\n			initial_commit = {\n				"did": did,\n				"version": static_config.ATPROTO_REPO_VERSION_3,\n				"data": empty_mst.cid,\n				"rev": tid,\n				"prev": None,\n			}\n			initial_commit["sig"] = crypto.raw_sign(\n				privkey, cbrrr.encode_dag_cbor(initial_commit)\n			)\n			commit_bytes = cbrrr.encode_dag_cbor(initial_commit)\n			commit_cid = cbrrr.CID.cidv1_dag_cbor_sha256_32_from(commit_bytes)\n			self.con.execute(\n				"""
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
				""",\n				(\n					did,\n					handle,\n					b'{"preferences":[]}',\n					pw_hash,\n					privkey_pem,\n					bytes(commit_cid),\n					tid,\n					commit_bytes,\n				),\n			)\n			user_id = self.con.last_insert_rowid()\n			self.con.execute(\n				"INSERT INTO mst(repo, cid, since, value) VALUES (?, ?, ?, ?)",\n				(user_id, bytes(empty_mst.cid), tid, empty_mst.serialised),\n			)\n\n	def verify_account_login(\n		self, did_or_handle: str, password: str\n	) -> Tuple[str, str, str, str]:\n		row = self.con.execute(\n			"SELECT did, handle, pw_hash FROM user WHERE did=? OR handle=?",\n			(did_or_handle, did_or_handle),\n		).fetchone()\n		if row is None:\n			raise KeyError("no account found for did")\n		did, handle, pw_hash = row\n		try:\n			self.pw_hasher.verify(pw_hash, password)\n		except argon2.exceptions.VerifyMismatchError:\n			raise ValueError("invalid password")\n		return did, handle\n\n	def did_by_handle(self, handle: str) -> Optional[str]:\n		row = self.con.execute(\n			"SELECT did FROM user WHERE handle=?", (handle,)\n		).fetchone()\n		if row is None:\n			return None\n		return row[0]\n\n	def handle_by_did(self, did: str) -> Optional[str]:\n		row = self.con.execute(\n			"SELECT handle FROM user WHERE did=?", (did,)\n		).fetchone()\n		if row is None:\n			return None\n		return row[0]\n\n	def signing_key_pem_by_did(self, did: str) -> Optional[str]:\n		row = self.con.execute(\n			"SELECT signing_key FROM user WHERE did=?", (did,)\n		).fetchone()\n		if row is None:\n			return None\n		return row[0]\n\n	def list_repos(\n		self,\n	) -> List[Tuple[str, cbrrr.CID, str]]:\n		return [\n			(did, cbrrr.CID(head), rev)\n			for did, head, rev in self.con.execute(\n				"SELECT did, head, rev FROM user"\n			).fetchall()\n		]\n\n	def get_blockstore(self, did: str) -> "Database":\n		return DBBlockStore(self, did)