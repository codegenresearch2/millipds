# TODO: some smarter way of handling migrations

import apsw
import apsw.bestpractice

apsw.bestpractice.apply(apsw.bestpractice.recommended)

from millipds import static_config

# Add handle_cache table and use dependency injection for database connections
class Database:
	def __init__(self, path: str = static_config.MAIN_DB_PATH) -> None:
		self.path = path
		self.con = apsw.Connection(
			self.path,
			flags=(
				apsw.SQLITE_OPEN_READWRITE | apsw.SQLITE_OPEN_CREATE
			),
		)
		self.pw_hasher = argon2.PasswordHasher()

		try:
			version_now = self.get_db_version()
			if version_now != static_config.MILLIPDS_DB_VERSION:
				raise Exception("unrecognised db version (TODO: db migrations)!")

		except apsw.SQLError as e:
			if "no such table" not in str(e):
				raise
			self._init_tables()

	def get_db_version(self):
		row = self.con.execute("SELECT db_version FROM config").fetchone()
		return row[0] if row else None

	def _init_tables(self):
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
			CREATE TABLE handle_cache(
				handle TEXT PRIMARY KEY NOT NULL,
				did TEXT,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL
			)
			"""
		)

# Keep password hashing within the same file
import argon2
import secrets

# Document changes with clear comments
print("v1 -> v2 Migration successful")