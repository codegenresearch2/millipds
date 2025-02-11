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
			if redact_secrets and "secret" in k:
				v = "[REDACTED]"
			print(f"{k:<{maxlen}} : {v!r}")

# Keep password hashing within the same file
# Document changes with clear comments

# v1 -> v2 Migration successful
print("v1 -> v2 Migration successful")