import sqlite3
from pathlib import Path
from typing import Any, Dict

DB_PATH = Path(__file__).resolve().parent / "websiteattack.db"

class Database:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self):
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS endpoints (
                url TEXT PRIMARY KEY,
                method TEXT,
                status INTEGER,
                headers TEXT,
                query_params TEXT
            )
            """
        )
        self.conn.commit()

    def save_endpoint(self, endpoint: Dict[str, Any]):
        self.conn.execute(
            "INSERT OR REPLACE INTO endpoints (url, method, status, headers, query_params) VALUES (?, ?, ?, ?, ?)",
            (
                endpoint["url"],
                endpoint["method"],
                endpoint["status"],
                str(endpoint["headers"]),
                str(endpoint["query_params"]),
            ),
        )
        self.conn.commit()

    def get_all_endpoints(self):
        cursor = self.conn.execute("SELECT * FROM endpoints")
        return [dict(row) for row in cursor.fetchall()]
