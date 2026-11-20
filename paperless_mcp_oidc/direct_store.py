"""SQLite persistence for direct-mode OAuth clients, codes and token pairs."""

import hashlib
import os
import sqlite3
import time
from contextlib import closing, contextmanager
from pathlib import Path


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class DirectStore:
    def __init__(self, path: str):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            if os.fstat(fd).st_mode & 0o077:
                raise ValueError("DIRECT_AUTH_DB_PATH must be accessible only to its owner (chmod 600)")
        finally:
            os.close(fd)

        with self.connect(write=True) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS oauth_state (
                    kind TEXT NOT NULL, key TEXT NOT NULL, data TEXT NOT NULL,
                    expires INTEGER, paperless_token TEXT,
                    PRIMARY KEY (kind, key)
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS oauth_state_expiry ON oauth_state (expires)")
            db.execute("""
                CREATE TABLE IF NOT EXISTS oauth_grants (
                    access_hash TEXT PRIMARY KEY, refresh_hash TEXT NOT NULL UNIQUE,
                    access_expires INTEGER NOT NULL, refresh_expires INTEGER NOT NULL,
                    client_id TEXT NOT NULL, subject TEXT NOT NULL, scopes TEXT NOT NULL,
                    resource TEXT NOT NULL, paperless_token TEXT NOT NULL
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS oauth_grants_expiry ON oauth_grants (refresh_expires)")

    @contextmanager
    def connect(self, *, write: bool = False):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.row_factory = sqlite3.Row
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db

    def remember(self, kind: str, key: str, data: str, expires: int | None = None) -> None:
        with self.connect(write=True) as db:
            db.execute("DELETE FROM oauth_state WHERE expires <= ?", (time.time(),))
            db.execute("DELETE FROM oauth_grants WHERE refresh_expires <= ?", (time.time(),))
            db.execute("INSERT INTO oauth_state VALUES (?, ?, ?, ?, NULL)", (kind, key, data, expires))

    def state(self, kind: str, key: str) -> sqlite3.Row | None:
        with self.connect() as db:
            return db.execute(
                "SELECT data FROM oauth_state WHERE kind = ? AND key = ? "
                "AND (expires IS NULL OR expires > ?)",
                (kind, key, time.time()),
            ).fetchone()

    def complete_login(self, flow: str, code: str, data: str, expires: int, paperless_token: str) -> bool:
        with self.connect(write=True) as db:
            used = db.execute(
                "DELETE FROM oauth_state WHERE kind = 'login' AND key = ? AND expires > ?",
                (digest(flow), time.time()),
            )
            if not used.rowcount:
                return False
            db.execute(
                "INSERT INTO oauth_state VALUES ('code', ?, ?, ?, ?)",
                (digest(code), data, expires, paperless_token),
            )
            return True

    def grant(self, token: str, *, refresh: bool = False) -> sqlite3.Row | None:
        sql = (
            "SELECT * FROM oauth_grants WHERE refresh_hash = ? AND refresh_expires > ?"
            if refresh
            else "SELECT * FROM oauth_grants WHERE access_hash = ? AND access_expires > ?"
        )
        with self.connect() as db:
            return db.execute(sql, (digest(token), time.time())).fetchone()

    def issue(
        self,
        previous: str,
        access: str,
        refresh: str,
        access_expires: int,
        refresh_expires: int,
        client_id: str,
        subject: str,
        scopes: str,
        resource: str,
        *,
        rotate: bool,
    ) -> bool:
        with self.connect(write=True) as db:
            if rotate:
                sql = """
                    DELETE FROM oauth_grants WHERE refresh_hash = ? AND refresh_expires > ?
                    AND client_id = ? RETURNING paperless_token
                """
            else:
                sql = """
                    DELETE FROM oauth_state WHERE kind = 'code' AND key = ? AND expires > ?
                    AND json_extract(data, '$.client_id') = ?
                    RETURNING paperless_token
                """
            source = db.execute(sql, (digest(previous), time.time(), client_id)).fetchone()
            if source is None:
                return False
            db.execute(
                "INSERT INTO oauth_grants VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    digest(access),
                    digest(refresh),
                    access_expires,
                    refresh_expires,
                    client_id,
                    subject,
                    scopes,
                    resource,
                    source["paperless_token"],
                ),
            )
            return True

    def revoke(self, token: str, client_id: str) -> None:
        hashed = digest(token)
        with self.connect(write=True) as db:
            db.execute(
                "DELETE FROM oauth_grants WHERE client_id = ? AND (access_hash = ? OR refresh_hash = ?)",
                (client_id, hashed, hashed),
            )
