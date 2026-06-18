"""
MySQL connection utilities for IDS pipeline database operations.

Edit the values below to match your MySQL environment.
"""

from typing import Optional


# Editable MySQL connection parameters
DB_USER = "root"
DB_PASSWORD = "password"
DB_HOST = "127.0.0.1"
DB_PORT = 3306
DB_NAME = "ids_pipeline"


def get_mysql_connection():
    """
    Create and return a MySQL connection.

    Raises:
        RuntimeError: If mysql-connector-python is not installed.
        mysql.connector.Error: If the connection fails.
    """
    try:
        import mysql.connector
    except ImportError as exc:
        raise RuntimeError(
            "mysql-connector-python is required for RAW_DB_FLOW. "
            "Install it with: pip install mysql-connector-python"
        ) from exc

    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        port=DB_PORT,
        database=DB_NAME,
    )


def close_connection(connection: Optional[object]) -> None:
    """Safely close a MySQL connection if present."""
    if connection is not None:
        connection.close()
