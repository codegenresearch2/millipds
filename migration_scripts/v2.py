import apsw
import apsw.bestpractice

apsw.bestpractice.apply(apsw.bestpractice.recommended)

from millipds import static_config

# Establish the database connection directly in the main execution flow
with apsw.Connection(static_config.MAIN_DB_PATH) as con:
    version_now, *_ = con.execute("SELECT db_version FROM config").fetchone()

    assert version_now == 1

    # Create the did_cache table
    con.execute(
        """
        CREATE TABLE did_cache(
            did TEXT PRIMARY KEY NOT NULL,
            doc TEXT,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )"
    )

    # Create the handle_cache table
    con.execute(
        """
        CREATE TABLE handle_cache(
            handle TEXT PRIMARY KEY NOT NULL,
            did TEXT,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )"
    )

    # Update the version in the config
    con.execute("UPDATE config SET db_version=2")

print("v1 -> v2 Migration successful")