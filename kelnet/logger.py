import logging
import sys
from datetime import datetime
from sqlite3 import connect


class DataBaseHandler(logging.Handler):
    """
    DB Handler for kelnetlib
    """

    def __init__(self, dbfile):
        """
        Creates table if it doesnt exist.
        """
        super().__init__()
        self.dbfile = dbfile
        self.db = connect(self.dbfile)
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS logs (
                date TEXT,
                time TEXT,
                lvl INTEGER,
                lvl_name TEXT,
                msg TEXT,
                logger TEXT,
                lineno INTEGER
                )"""
        )

    def emit(self, record):
        """
        Conditionally emit the specified logging record.
        """
        params = [
            datetime.now().strftime("%A, %d %B, %Y"),
            datetime.now().strftime("%I:%M %S %f"),
            record.levelno,
            record.levelname,
            record.msg,
            record.name,
            record.lineno,
        ]
        self.db.execute(
            """INSERT INTO logs (date, time, lvl,
                                    lvl_name, msg, logger,
                                    lineno )
                            VALUES (?, ?, ?,
                                    ?, ?, ?,
                                    ?)""",
            (params),
        )
        self.db.commit()

    def check(self):
        """
        Prints all present tables. Sanity check used for testing.
        """
        query = """SELECT name FROM sqlite_master
        WHERE type='table';"""
        res = self.db.execute(query)  # returns a cursor
        print(res.fetchall())
        res.close()

    def close(self):
        self.db.close()
        super().close()


def getLogger(dbfile=None, name=None, logfile=None, loglevel=None):
    """
    Configure custom logger.
    Log levels warning and above are written to stderr/console
    Log levels debug and above are written to db and logfile.
    """
    logger = logging.getLogger(name) if name else logging.getLogger(__name__)
    logger.level = logging.DEBUG

    # Create handlers
    c_handler = logging.StreamHandler(stream=sys.stderr)

    # set loglevel
    if loglevel:
        c_handler.setLevel(loglevel)
    else:
        c_handler.setLevel(logging.WARNING)
    # Create formatters and add it to handlers
    c_format = logging.Formatter(
        "%(name)s - %(levelname)s - %(funcName)s - %(lineno)d - %(message)s"
    )
    c_handler.setFormatter(c_format)

    # Add handlers to the logger
    logger.addHandler(c_handler)

    if logfile:
        f_handler = logging.FileHandler(logfile, encoding="utf8")
        f_handler.setLevel(logging.DEBUG)
        f_format = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s -%(funcName)s - %(lineno)d - %(message)s"
        )
        f_handler.setFormatter(f_format)
        logger.addHandler(f_handler)

    if dbfile:
        db_handler = DataBaseHandler(dbfile)  # check name is correct!
        db_handler.setLevel(logging.DEBUG)
        logger.addHandler(db_handler)

    return logger


def main():
    logger = getLogger(__name__)
    logger.setLevel(10)
    db_handler = DataBaseHandler(r"logs.db")
    logger.addHandler(db_handler)
    db_handler.setLevel(10)
    db_handler.check()
    logger.log(msg="something happened", level=10)


if __name__ == "__main__":
    main()
