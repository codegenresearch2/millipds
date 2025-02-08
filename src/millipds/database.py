import logging

class Database:
    def __init__(self, path):
        self.path = path
        self.config = {}

    def update_config(self, pds_pfx=None, pds_did=None, bsky_appview_pfx=None, bsky_appview_did=None):
        if pds_pfx is not None:
            self.config['pds_pfx'] = pds_pfx
        if pds_did is not None:
            self.config['pds_did'] = pds_did
        if bsky_appview_pfx is not None:
            self.config['bsky_appview_pfx'] = bsky_appview_pfx
        if bsky_appview_did is not None:
            self.config['bsky_appview_did'] = bsky_appview_did

    def get_config(self):
        return self.config

class DBBlockStore(Database):
    def __init__(self, db_connection, repo_id):
        super().__init__(path)
        self.db_connection = db_connection
        self.repo_id = repo_id
        self.logger = logging.getLogger(__name__)

    def get_block(self, key):
        try:
            # Implementation for retrieving a block
            self.logger.info(f'Retrieving block with key: {key}')
        except Exception as e:
            self.logger.error(f'Error retrieving block with key: {key} - {e}')
            raise

    def put_block(self, key, value):
        try:
            # Implementation for putting a block
            self.logger.info(f'Putting block with key: {key} and value: {value}')
        except Exception as e:
            self.logger.error(f'Error putting block with key: {key} - {e}')
            raise

    def del_block(self, key):
        try:
            # Implementation for deleting a block
            self.logger.info(f'Deleting block with key: {key}')
        except Exception as e:
            self.logger.error(f'Error deleting block with key: {key} - {e}')
            raise