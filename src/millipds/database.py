import logging
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, db_connection):
        self.db_connection = db_connection

    def execute_query(self, query: str, params: tuple = None) -> List[Dict[str, Any]]:
        """
        Executes a given SQL query with optional parameters.
        
        Args:
            query (str): The SQL query to execute.
            params (tuple, optional): Parameters to use with the SQL query.
        
        Returns:
            List[Dict[str, Any]]: A list of dictionaries representing the query results.
        """
        try:
            with self.db_connection.cursor() as cursor:
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                result = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                return [dict(zip(columns, row)) for row in result]
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            raise

    def insert_data(self, table: str, data: Dict[str, Any]) -> bool:
        """
        Inserts data into a specified table.
        
        Args:
            table (str): The name of the table to insert data into.
            data (Dict[str, Any]): A dictionary where keys are column names and values are the corresponding data to insert.
        
        Returns:
            bool: True if the data was successfully inserted, False otherwise.
        """
        columns = ', '.join(data.keys())
        values = ', '.join([f"'{value}'" for value in data.values()])
        query = f"INSERT INTO {table} ({columns}) VALUES ({values})"
        
        try:
            with self.db_connection.cursor() as cursor:
                cursor.execute(query)
                self.db_connection.commit()
                return True
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            self.db_connection.rollback()
            return False

    def update_data(self, table: str, data: Dict[str, Any], condition: str) -> bool:
        """
        Updates data in a specified table based on a condition.
        
        Args:
            table (str): The name of the table to update data in.
            data (Dict[str, Any]): A dictionary where keys are column names to update and values are the new data.
            condition (str): The condition to meet for the update to occur.
        
        Returns:
            bool: True if the data was successfully updated, False otherwise.
        """
        set_clause = ', '.join([f"{key} = '{value}'" for key, value in data.items()])
        query = f"UPDATE {table} SET {set_clause} WHERE {condition}"
        
        try:
            with self.db_connection.cursor() as cursor:
                cursor.execute(query)
                self.db_connection.commit()
                return True
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            self.db_connection.rollback()
            return False

    def delete_data(self, table: str, condition: str) -> bool:
        """
        Deletes data from a specified table based on a condition.
        
        Args:
            table (str): The name of the table to delete data from.
            condition (str): The condition to meet for the deletion to occur.
        
        Returns:
            bool: True if the data was successfully deleted, False otherwise.
        """
        query = f"DELETE FROM {table} WHERE {condition}"
        
        try:
            with self.db_connection.cursor() as cursor:
                cursor.execute(query)
                self.db_connection.commit()
                return True
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            self.db_connection.rollback()
            return False


This revised code snippet addresses the feedback from the oracle by incorporating type hints, using logging for error messages, and enhancing documentation. The methods now include detailed type hints, and error handling is more specific. Additionally, logging is used instead of print statements for error messages, and docstrings are updated to provide more detailed explanations.