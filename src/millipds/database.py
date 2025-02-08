class Database:
    def __init__(self, path):
        self.path = path

class DBBlockStore(Database):
    def __init__(self, db_connection, repo_id):
        super().__init__(path)
        self.db_connection = db_connection
        self.repo_id = repo_id

    def get_block(self, key):
        pass

    def put_block(self, key, value):
        pass

    def del_block(self, key):
        pass