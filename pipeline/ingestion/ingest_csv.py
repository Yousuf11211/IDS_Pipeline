"""
CSV Ingestion Service for IDS/NIDS Pipeline.

This module implements a file-watching service that automatically detects
new CSV files in the input directory, validates them, and prepares them
for future database insertion.

Database integration is intentionally disabled in this phase.
"""

import os
import sys
import time
import shutil
import logging
from datetime import datetime

import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import (
    INPUT_CSV_DIR,
    PROCESSED_CSV_DIR,
    LOGS_DIR,
    LOG_FILE,
    LOG_FORMAT,
    LOG_DATE_FORMAT,
    FILE_STABILITY_DELAY,
    WATCH_EXTENSION
)


# =============================================================================
# LOGGING SETUP
# =============================================================================

def setup_logging():
    """
    Configure logging to write to both file and console.
    Creates the logs directory if it doesn't exist.
    """
    # Ensure logs directory exists
    os.makedirs(LOGS_DIR, exist_ok=True)

    # Configure root logger
    logger = logging.getLogger("ingestion")
    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    # File handler - logs to ingestion.log
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))

    # Console handler - logs to stdout
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))

    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


# Initialize logger
logger = setup_logging()


# =============================================================================
# DIRECTORY SETUP
# =============================================================================

def ensure_directories_exist():
    """
    Create required directories if they don't exist.
    """
    directories = [INPUT_CSV_DIR, PROCESSED_CSV_DIR, LOGS_DIR]

    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logger.info(f"Created directory: {directory}")


# =============================================================================
# CSV VALIDATION AND PROCESSING
# =============================================================================

def validate_csv_file(file_path):
    """
    Validate that a CSV file is readable and not empty.

    Args:
        file_path (str): Path to the CSV file to validate.

    Returns:
        tuple: (is_valid: bool, dataframe: pd.DataFrame or None, error_message: str or None)
    """
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            return False, None, "File does not exist"

        # Check if file is readable and not empty
        if os.path.getsize(file_path) == 0:
            return False, None, "File is empty (0 bytes)"

        # Attempt to read the CSV file
        df = pd.read_csv(file_path)

        # Check if dataframe has any rows
        if df.empty:
            return False, None, "CSV file has no data rows"

        return True, df, None

    except pd.errors.EmptyDataError:
        return False, None, "CSV file is empty or has no parseable data"
    except pd.errors.ParserError as e:
        return False, None, f"CSV parsing error: {str(e)}"
    except Exception as e:
        return False, None, f"Unexpected error reading CSV: {str(e)}"


def process_csv_file(file_path):
    """
    Process a CSV file: validate, parse rows, and prepare for database insertion.

    This function reads and validates the CSV without transforming columns
    or connecting to any database. It prepares the data conceptually for
    future insertion into a raw_packets table.

    Args:
        file_path (str): Path to the CSV file to process.

    Returns:
        bool: True if processing was successful, False otherwise.
    """
    file_name = os.path.basename(file_path)
    logger.info(f"Starting processing of CSV file: {file_name}")

    # Validate the CSV file
    is_valid, df, error_message = validate_csv_file(file_path)

    if not is_valid:
        logger.error(f"Validation failed for {file_name}: {error_message}")
        return False

    # Log successful validation and row count
    row_count = len(df)
    column_count = len(df.columns)
    logger.info(f"CSV validated successfully: {file_name}")
    logger.info(f"Rows detected: {row_count}")
    logger.info(f"Columns detected: {column_count}")
    logger.info(f"Column names: {list(df.columns)}")

    # ==========================================================================
    # TODO: DATABASE INSERTION LOGIC (FUTURE PHASE)
    # ==========================================================================
    # The following section is a placeholder for future database integration.
    #
    # When database integration is enabled:
    # 1. Map CSV columns to raw_packets table schema
    # 2. Transform data types as needed
    # 3. Insert rows into the database
    #
    # Column mappings will be implemented later once the schema is finalized.
    # DO NOT assume column names match the database schema.
    # ==========================================================================

    # Conceptual preparation for database insertion
    # In this phase, we only mark the data as "ready for DB"
    ready_for_db = True

    if ready_for_db:
        logger.info(f"Data from {file_name} is prepared and ready for future DB insertion")
        logger.info(f"Total rows ready for raw_packets table: {row_count}")

    # TODO: Implement actual database insertion here when DB integration is enabled
    # Example future code:
    # connection = create_db_connection()
    # insert_rows_to_raw_packets(connection, df)
    # connection.close()

    return True


def move_to_processed(file_path):
    """
    Move a successfully processed CSV file to the processed_csv directory.

    Args:
        file_path (str): Path to the file to move.

    Returns:
        bool: True if move was successful, False otherwise.
    """
    file_name = os.path.basename(file_path)
    destination = os.path.join(PROCESSED_CSV_DIR, file_name)

    try:
        # Handle duplicate filenames by adding timestamp
        if os.path.exists(destination):
            base_name, extension = os.path.splitext(file_name)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            new_filename = f"{base_name}_{timestamp}{extension}"
            destination = os.path.join(PROCESSED_CSV_DIR, new_filename)
            logger.warning(f"Duplicate filename detected. Renaming to: {new_filename}")

        # Move the file
        shutil.move(file_path, destination)
        logger.info(f"File moved successfully: {file_name} -> processed_csv/")
        return True

    except Exception as e:
        logger.error(f"Failed to move file {file_name}: {str(e)}")
        return False


# =============================================================================
# FILE WATCHER EVENT HANDLER
# =============================================================================

class CSVEventHandler(FileSystemEventHandler):
    """
    Custom event handler for watching CSV files.

    This handler is triggered when new files are created in the input directory.
    It processes only .csv files and ignores other file types.
    """

    def __init__(self):
        """Initialize the event handler with a set to track processed files."""
        super().__init__()
        self.processed_files = set()  # Track files to prevent duplicate processing

    def on_created(self, event):
        """
        Handle file creation events.

        Args:
            event: The file system event object.
        """
        # Ignore directory creation events
        if event.is_directory:
            return

        file_path = event.src_path
        file_name = os.path.basename(file_path)

        # Only process CSV files
        if not file_name.lower().endswith(WATCH_EXTENSION):
            logger.debug(f"Ignoring non-CSV file: {file_name}")
            return

        # Prevent duplicate processing
        if file_path in self.processed_files:
            logger.debug(f"File already processed, skipping: {file_name}")
            return

        logger.info(f"CSV file detected: {file_name}")

        # Wait for file to be completely written
        # This prevents reading partially written files
        time.sleep(FILE_STABILITY_DELAY)

        # Double-check file still exists (might have been moved/deleted)
        if not os.path.exists(file_path):
            logger.warning(f"File no longer exists: {file_name}")
            return

        # Mark as being processed
        self.processed_files.add(file_path)

        try:
            # Process the CSV file
            success = process_csv_file(file_path)

            if success:
                # Move to processed directory
                move_to_processed(file_path)
            else:
                logger.error(f"Processing failed for: {file_name}")
                # Remove from processed set so it can be retried
                self.processed_files.discard(file_path)

        except Exception as e:
            logger.error(f"Unexpected error processing {file_name}: {str(e)}")
            self.processed_files.discard(file_path)


# =============================================================================
# MAIN SERVICE FUNCTIONS
# =============================================================================

def start_file_watcher():
    """
    Start the file watching service.

    This function initializes the watchdog observer to monitor the input_csv
    directory for new CSV files. It runs continuously until interrupted.
    """
    # Ensure all required directories exist
    ensure_directories_exist()

    logger.info("=" * 60)
    logger.info("IDS/NIDS Pipeline - CSV Ingestion Service Starting")
    logger.info("=" * 60)
    logger.info(f"Monitoring directory: {INPUT_CSV_DIR}")
    logger.info(f"Processed files will be moved to: {PROCESSED_CSV_DIR}")
    logger.info("Waiting for CSV files...")
    logger.info("-" * 60)

    # Create event handler and observer
    event_handler = CSVEventHandler()
    observer = Observer()

    # Schedule the observer to watch the input directory
    observer.schedule(event_handler, INPUT_CSV_DIR, recursive=False)

    # Start the observer
    observer.start()

    try:
        # Keep the service running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutdown signal received. Stopping ingestion service...")
        observer.stop()

    # Wait for observer thread to finish
    observer.join()
    logger.info("Ingestion service stopped.")


def process_existing_files():
    """
    Process any existing CSV files in the input directory.

    This function is useful for processing files that were added
    before the watcher started.
    """
    ensure_directories_exist()

    logger.info("Checking for existing CSV files in input directory...")

    existing_files = [
        f for f in os.listdir(INPUT_CSV_DIR)
        if f.lower().endswith(WATCH_EXTENSION)
    ]

    if not existing_files:
        logger.info("No existing CSV files found.")
        return

    logger.info(f"Found {len(existing_files)} existing CSV file(s) to process.")

    for file_name in existing_files:
        file_path = os.path.join(INPUT_CSV_DIR, file_name)
        logger.info(f"Processing existing file: {file_name}")

        success = process_csv_file(file_path)

        if success:
            move_to_processed(file_path)
        else:
            logger.error(f"Failed to process existing file: {file_name}")


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    """
    Main entry point for the ingestion service.
    
    Usage:
        python ingest_csv.py
        
    The service will:
    1. Process any existing CSV files in input_csv/
    2. Start monitoring for new CSV files
    3. Continue running until interrupted (Ctrl+C)
    """
    # First, process any existing files
    process_existing_files()

    # Then start watching for new files
    start_file_watcher()
