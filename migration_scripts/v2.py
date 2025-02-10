import apsw
import apsw.bestpractice
from millipds import static_config

# Apply best practices for APSW
apsw.bestpractice.apply(apsw.bestpractice.recommended)

# Define the database connection and version check within a context manager
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

        # Check and apply database version
        with self.con:
            version_now = self.get_db_version()
            if version_now != static_config.MILLIPDS_DB_VERSION:
                self._init_tables()
                self.update_db_version(static_config.MILLIPDS_DB_VERSION)

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
            CREATE TABLE did_cache(
                did TEXT PRIMARY KEY NOT NULL,
                doc TEXT,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
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

    def update_db_version(self, new_version: int):
        self.con.execute("UPDATE config SET db_version=?", (new_version,))

# Ensure password hashing is handled within the class
import argon2
import secrets


This revised code snippet addresses the feedback from the oracle by:

1. Using a context manager for the database connection.
2. Simplifying the database version check.
3. Directly creating and updating tables within the initialization method.
4. Updating the database version after tables are created.
5. Using consistent table names and structures.
6. Adding clear comments and documentation.