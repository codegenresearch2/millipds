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

		# Initialize config attribute
		self.config = self._load_config()

		try:
			if self.config["db_version"] != static_config.MILLIPDS_DB_VERSION:
				raise Exception(
					"unrecognised db version (TODO: db migrations?!)"
				)

		except apsw.SQLError as e:  # no such table, so lets create it
			if "no such table" not in str(e):
				raise
			with self.con:
				self._init_tables()

	def _load_config(self) -> Dict[str, object]:
		# Load config from database or default to a predefined value
		# This method should be implemented based on the actual configuration source
		# For now, let's assume a default value is used
		return {
			"db_version": static_config.MILLIPDS_DB_VERSION,
			# Add other config fields as needed
		}

	# Rest of the code remains the same