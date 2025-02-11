class Database:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.create_tables()

    def create_tables(self):
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS revoked_token (
                token TEXT PRIMARY KEY
            )
        ''')
        self.conn.commit()

    def add_revoked_token(self, token: str):
        try:
            self.conn.execute('''
                INSERT INTO revoked_token (token) VALUES (?)
            ''', (token,))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"An error occurred: {e}")
            self.conn.rollback()

    def is_token_revoked(self, token: str) -> bool:
        cursor = self.conn.execute('''
            SELECT 1 FROM revoked_token WHERE token = ?
        ''', (token,))
        return cursor.fetchone() is not None

    def handle_exception(self, e):
        response = {
            "error": {
                "type": type(e).__name__,
                "message": str(e)
            }
        }
        return jsonify(response), 500

    def query(self, query, params=()):
        try:
            cursor = self.conn.execute(query, params)
            self.conn.commit()
            return cursor.fetchall()
        except sqlite3.Error as e:
            return self.handle_exception(e)

# Example usage
if __name__ == "__main__":
    db = Database('test.db')
    db.add_revoked_token('abc123')
    print(db.is_token_revoked('abc123'))  # Should print True
    print(db.is_token_revoked('def456'))  # Should print False


This code snippet addresses the feedback by ensuring the `revoked_token` table is created during the initialization of the database. It also includes error handling for database operations to prevent plain text responses and ensure JSON responses are returned. The `query` method is updated to handle exceptions and return structured JSON responses.