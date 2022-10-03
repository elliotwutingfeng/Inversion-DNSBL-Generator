import apsw
from apsw import Error
from modules.utils.log import init_logger

logger = init_logger()


def vacuum_and_close(conn: apsw.Connection) -> None:
    if conn is not None:
        try:
            cur = conn.cursor()
            cur.execute("VACUUM")
        except Error as error:
            logger.error("Vacuum and Close Failed | %s", error)
        conn.close()
