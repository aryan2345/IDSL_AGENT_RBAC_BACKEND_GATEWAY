import os
import psycopg2
from psycopg2.extras import DictCursor

class PostgresSQL:
    def __init__(self, db_url: str = os.getenv('DATABASE_URL')):
        self.conn = psycopg2.connect(db_url)
        self.cursor = self.conn.cursor(cursor_factory=DictCursor)

    def execute_query(self, query, params=None):
        self.cursor.execute(query, params)
        self.conn.commit()

    def fetch_one(self, query, params=None):
        self.cursor.execute(query, params)
        return self.cursor.fetchone()

    def fetch_all(self, query, params=None):
        self.cursor.execute(query, params)
        return self.cursor.fetchall()

    def close(self):
        self.cursor.close()
        self.conn.close()
