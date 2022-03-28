import base64
import os

import apsw  # type: ignore

from modules.utils.parallel_compute import execute_with_ray


def convert_hash(b):
    return base64.b64encode(b).decode()


databases = [x for x in os.listdir("databases") if x.endswith(".db")]


async def proc(db):
    conn = apsw.Connection(f"databases/{db}")
    conn.setbusytimeout(15000)
    conn.createscalarfunction("convert_hash", convert_hash, 1)

    cur = conn.cursor()

    cur.execute("PRAGMA auto_vacuum = FULL")  # https://www.sqlite.org/pragma.html#pragma_auto_vacuum
    cur.execute("PRAGMA temp_store = MEMORY")  # https://www.sqlite.org/pragma.html#pragma_temp_store
    cur.execute("PRAGMA journal_mode = WAL")  # https://www.sqlite.org/wal.html

    # skip if no urls table found
    cur = cur.execute(
        """
    SELECT name FROM
    sqlite_schema WHERE
    type ='table' AND
    name NOT LIKE 'sqlite_%';
    """
    )

    if db == "malicious.db":
        if "maliciousHashPrefixes" not in [x[0] for x in cur.fetchall()]:
            conn.close()
            return

        # Rename hash column to hash2
        cur.execute("ALTER TABLE maliciousHashPrefixes RENAME COLUMN hashPrefix TO hashPrefix2")

        # Create hash column type text
        cur.execute("ALTER TABLE maliciousHashPrefixes ADD COLUMN hashPrefix text")

        # Copy converted hash2 values to hash
        cur.execute("UPDATE maliciousHashPrefixes SET hashPrefix = convert_hash(hashPrefix2)")

        # delete hash2 column
        cur.execute("ALTER TABLE maliciousHashPrefixes DROP COLUMN hashPrefix2")

    else:
        if cur.fetchall()[0][0] != "urls":
            conn.close()
            return

        # Rename hash column to hash2
        cur.execute("ALTER TABLE urls RENAME COLUMN hash TO hash2")

        # Create hash column type text
        cur.execute("ALTER TABLE urls ADD COLUMN hash text")

        # Copy converted hash2 values to hash
        cur.execute("UPDATE urls SET hash = convert_hash(hash2)")

        # delete hash2 column
        cur.execute("ALTER TABLE urls DROP COLUMN hash2")

    # vacuum the database to reclaim free space
    cur.execute("VACUUM")

    conn.close()


execute_with_ray(proc, [(db,) for db in databases])
