import apsw
import apsw.bestpractice

apsw.bestpractice.apply(apsw.bestpractice.recommended)

from millipds import static_config

with apsw.Connection(static_config.MAIN_DB_PATH) as con:
    version_now, *_ = con.execute("SELECT db_version FROM config").fetchone()

    assert version_now == 1

    # Create did_cache table as per gold code
    con.execute(
        """
        CREATE TABLE did_cache(
            did TEXT PRIMARY KEY NOT NULL,
            doc TEXT,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
        """
    )

    # Create handle_cache table as per user's preference
    con.execute(
        """
        CREATE TABLE handle_cache(
            handle TEXT PRIMARY KEY NOT NULL,
            did TEXT,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
        """
    )

    con.execute("UPDATE config SET db_version=2")

# TODO: some smarter way of handling migrations
print("v1 -> v2 Migration successful")