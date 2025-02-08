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
        "\n        CREATE TABLE did_cache(\n            did TEXT PRIMARY KEY NOT NULL,\n            doc TEXT,\n            created_at INTEGER NOT NULL,\n            expires_at INTEGER NOT NULL\n        )"
    )

    # Create the handle_cache table
    con.execute(
        "\n        CREATE TABLE handle_cache(\n            handle TEXT PRIMARY KEY NOT NULL,\n            did TEXT,\n            created_at INTEGER NOT NULL,\n            expires_at INTEGER NOT NULL\n        )"
    )

    # Update the version in the config
    con.execute("UPDATE config SET db_version=2")

print("v1 -> v2 Migration successful")

# Future improvement: revisit migration handling
# This is a placeholder comment indicating a future improvement.