import base64
import os

import apsw  # type: ignore
from tqdm import tqdm


def convert_hash(b):
    return base64.b64encode(b).decode()


databases = [x for x in os.listdir("databases") if x != "malicious.db" and x.endswith(".db")]
for db in tqdm(databases):
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

    if cur.fetchall()[0][0] != "urls":
        conn.close()
        continue

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
