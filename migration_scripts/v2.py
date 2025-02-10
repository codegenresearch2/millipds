import apsw
import apsw.bestpractice
from millipds import static_config

# Apply best practices for APSW
apsw.bestpractice.apply(apsw.bestpractice.recommended)

# Define the database connection and version check within a context manager
with apsw.Connection(static_config.MAIN_DB_PATH) as con:
    # Retrieve the current database version
    version_now = con.execute("SELECT db_version FROM config").fetchone()[0]

    # Create necessary tables
    con.execute(
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

    # Insert the initial configuration
    con.execute(
        """
        INSERT INTO config(
            db_version,
            jwt_access_secret
        ) VALUES (?, ?)
        """,
        (static_config.MILLIPDS_DB_VERSION, secrets.token_hex()),
    )

    # Update the database version
    con.execute("UPDATE config SET db_version=?", (static_config.MILLIPDS_DB_VERSION,))

print("Database migration successful")


This revised code snippet addresses the feedback from the oracle by:

1. Streamlining the retrieval of the current database version and directly assigning it to a variable for clarity.
2. Ensuring that all necessary tables are defined, including the `handle_cache` table.
3. Updating the database version at the end of the migration process to reflect the new version accurately.
4. Refining comments to be more concise and focused on the specific actions being taken.
5. Not including error handling in this example, but it could be added as needed for robustness.