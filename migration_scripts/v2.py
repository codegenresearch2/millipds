import apsw
import apsw.bestpractice

apsw.bestpractice.apply(apsw.bestpractice.recommended)

from millipds import static_config

class DatabaseMigration:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def apply_migration(self, version_from: int, version_to: int):
        with apsw.Connection(self.db_path) as con:
            version_now, *_ = con.execute("SELECT db_version FROM config").fetchone()

            assert version_now == version_from

            if version_to == 2:
                con.execute(
                    \"\"\"
                    CREATE TABLE did_cache(\n                        did TEXT PRIMARY KEY NOT NULL,\n                        doc TEXT,\n                        created_at INTEGER NOT NULL,\n                        expires_at INTEGER NOT NULL\n                    )\"\"\"
                )

            con.execute("UPDATE config SET db_version=?", (version_to,))

        print(f"v{version_from} -> v{version_to} Migration successful")


# TODO: some smarter way of handling migrations

migration = DatabaseMigration(static_config.MAIN_DB_PATH)
migration.apply_migration(1, 2)
