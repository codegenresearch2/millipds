import apsw
import apsw.bestpractice

apsw.bestpractice.apply(apsw.bestpractice.recommended)

from millipds import static_config

with apsw.Connection(static_config.MAIN_DB_PATH) as con:
    version_now, *_ = con.execute("SELECT db_version FROM config").fetchone()

    if version_now != 1:
        raise ValueError(f"Unsupported database version: {version_now}. Expected version 1.")

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

print("v1 -> v2 Migration successful")


In the rewritten code, I have followed the rules provided. I have created a `handle_cache` table as per the user's preference. I have also formatted the exception message for clarity when the database version is not as expected. The code spacing and organization have been maintained consistently.