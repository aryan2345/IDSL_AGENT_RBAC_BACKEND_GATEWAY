import os
import psycopg2
from psycopg2.extras import DictCursor

class PostgresSQL:
    def __init__(self, db_url: str = os.getenv('DATABASE_URL')):
        self.conn = psycopg2.connect(db_url)
        self.conn.autocommit = True  # Set autocommit to True by default
        self.cursor = self.conn.cursor(cursor_factory=DictCursor)

    def execute_query(self, query, params=None):
        try:
            self.cursor.execute(query, params)
            if not self.conn.autocommit:
                self.conn.commit()
        except Exception as e:
            if not self.conn.autocommit:
                self.conn.rollback()
            raise e

    def fetch_one(self, query, params=None):
        try:
            self.cursor.execute(query, params)
            return self.cursor.fetchone()
        except Exception as e:
            if not self.conn.autocommit:
                self.conn.rollback()
            raise e

    def fetch_all(self, query, params=None):
        try:
            self.cursor.execute(query, params)
            return self.cursor.fetchall()
        except Exception as e:
            if not self.conn.autocommit:
                self.conn.rollback()
            raise e

    def begin_transaction(self):
        """Start a transaction by disabling autocommit"""
        self.conn.autocommit = False

    def commit_transaction(self):
        """Commit the current transaction and re-enable autocommit"""
        self.conn.commit()
        self.conn.autocommit = True

    def rollback_transaction(self):
        """Rollback the current transaction and re-enable autocommit"""
        self.conn.rollback()
        self.conn.autocommit = True

    def close(self):
        self.cursor.close()
        self.conn.close()
