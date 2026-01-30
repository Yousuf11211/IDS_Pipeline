"""
CSV Ingestion Service for IDS/NIDS Pipeline.

This module implements a file-watching service that automatically detects
new CSV files in the input directory, processes them row by row through
an isolation model for anomaly detection, and outputs results to separate
CSV files for benign and malicious traffic.

Flow:
1. Watch input_csv/ folder for new CSV files
2. Process each row with a unique serial number
3. Send row (excluding ignored columns) to isolation model
4. Append result to benign_results.csv or malicious_results.csv
5. Move processed CSV to processed_csv/ folder
"""

import os
import sys
import time
import shutil
import logging
import pickle
from datetime import datetime

import pandas as pd
import numpy as np
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
    WATCH_EXTENSION,
    ISOLATION_MODEL_DIR,
    ISOLATION_MODEL_FILE,
    RESULTS_DIR,
    BENIGN_RESULTS_FILE,
    MALICIOUS_RESULTS_FILE,
    COLUMNS_TO_IGNORE,
    ANOMALY_LABEL,
    NORMAL_LABEL
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
    directories = [
        INPUT_CSV_DIR,
        PROCESSED_CSV_DIR,
        LOGS_DIR,
        ISOLATION_MODEL_DIR,
        RESULTS_DIR
    ]

    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logger.info(f"Created directory: {directory}")


# =============================================================================
# ISOLATION MODEL LOADER
# =============================================================================

# Global variable to store loaded model
_isolation_model = None


def load_isolation_model():
    """
    Load the isolation forest model from the model file.

    Returns:
        model: The loaded isolation forest model, or None if loading fails.
    """
    global _isolation_model

    if _isolation_model is not None:
        return _isolation_model

    if not os.path.exists(ISOLATION_MODEL_FILE):
        logger.error(f"Isolation model not found at: {ISOLATION_MODEL_FILE}")
        logger.error("Please place your trained isolation_forest_model.pkl in the isolation_model/ folder")
        return None

    try:
        with open(ISOLATION_MODEL_FILE, 'rb') as f:
            _isolation_model = pickle.load(f)
        logger.info(f"Isolation model loaded successfully from: {ISOLATION_MODEL_FILE}")
        return _isolation_model
    except Exception as e:
        logger.error(f"Failed to load isolation model: {str(e)}")
        return None


def predict_anomaly(model, row_data):
    """
    Use the isolation model to predict if a row is anomaly or normal.

    Args:
        model: The loaded isolation forest model
        row_data: numpy array or list of feature values (excluding ignored columns)

    Returns:
        int: 1 for normal (benign), -1 for anomaly (malicious)
    """
    try:
        # Reshape for single prediction
        features = np.array(row_data).reshape(1, -1)
        prediction = model.predict(features)
        return prediction[0]
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        # Default to anomaly on error for safety
        return ANOMALY_LABEL


# =============================================================================
# RESULTS FILE HANDLING
# =============================================================================

def initialize_results_files(columns):
    """
    Initialize the results CSV files with headers if they don't exist.

    Args:
        columns: List of column names for the results files
    """
    # Add serial_number at the beginning and label at the end
    header_columns = ['serial_number'] + columns + ['label']

    for results_file, label in [(BENIGN_RESULTS_FILE, 'benign'), (MALICIOUS_RESULTS_FILE, 'malicious')]:
        if not os.path.exists(results_file):
            # Create empty CSV with headers
            df_header = pd.DataFrame(columns=header_columns)
            df_header.to_csv(results_file, index=False)
            logger.info(f"Created {label} results file: {results_file}")


def append_to_results(row_data, label, serial_number, columns):
    """
    Append a row to the appropriate results CSV file.

    Args:
        row_data: Dictionary of column values
        label: 'benign' or 'malicious'
        serial_number: Unique serial number for this row
        columns: List of original column names
    """
    # Determine which file to write to
    if label == 'benign':
        results_file = BENIGN_RESULTS_FILE
    else:
        results_file = MALICIOUS_RESULTS_FILE

    # Build the row with serial number at start and label at end
    output_row = {'serial_number': serial_number}
    for col in columns:
        output_row[col] = row_data.get(col, '')
    output_row['label'] = label

    # Append to CSV
    df_row = pd.DataFrame([output_row])

    # Append without header if file exists and has content
    file_exists = os.path.exists(results_file) and os.path.getsize(results_file) > 0
    df_row.to_csv(results_file, mode='a', header=not file_exists, index=False)


# =============================================================================
# SERIAL NUMBER GENERATOR
# =============================================================================

# Global serial number counter (will be loaded from file or start fresh)
_serial_counter = 0
SERIAL_COUNTER_FILE = os.path.join(LOGS_DIR, ".serial_counter")


def load_serial_counter():
    """Load the serial counter from file or initialize to 0."""
    global _serial_counter

    if os.path.exists(SERIAL_COUNTER_FILE):
        try:
            with open(SERIAL_COUNTER_FILE, 'r') as f:
                _serial_counter = int(f.read().strip())
                logger.info(f"Loaded serial counter: {_serial_counter}")
        except Exception:
            _serial_counter = 0
    else:
        _serial_counter = 0


def save_serial_counter():
    """Save the current serial counter to file."""
    global _serial_counter
    try:
        with open(SERIAL_COUNTER_FILE, 'w') as f:
            f.write(str(_serial_counter))
    except Exception as e:
        logger.error(f"Failed to save serial counter: {str(e)}")


def get_next_serial_number():
    """Get the next unique serial number."""
    global _serial_counter
    _serial_counter += 1
    save_serial_counter()
    return _serial_counter


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


def get_model_features(row, columns):
    """
    Extract features for the model, excluding ignored columns.

    Args:
        row: Pandas Series representing one row
        columns: List of all column names

    Returns:
        list: Feature values for model prediction
    """
    features = []
    for col in columns:
        if col not in COLUMNS_TO_IGNORE:
            value = row[col]
            # Convert to numeric if possible, otherwise skip or use 0
            try:
                features.append(float(value))
            except (ValueError, TypeError):
                # Non-numeric columns that aren't in ignore list
                # You might want to handle these differently
                features.append(0)
    return features


def process_csv_file(file_path):
    """
    Process a CSV file row by row through the isolation model.

    This function:
    1. Reads and validates the CSV
    2. Assigns a unique serial number to each row
    3. Sends each row (minus ignored columns) to the isolation model
    4. Appends results to benign_results.csv or malicious_results.csv
    5. All original columns (including ignored ones) are preserved in output

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
    columns = list(df.columns)

    logger.info(f"CSV validated successfully: {file_name}")
    logger.info(f"Rows detected: {row_count}")
    logger.info(f"Columns detected: {column_count}")
    logger.info(f"Column names: {columns}")
    logger.info(f"Columns to ignore for model: {COLUMNS_TO_IGNORE}")

    # Load isolation model
    model = load_isolation_model()
    if model is None:
        logger.error("Cannot process without isolation model. Please add model to isolation_model/ folder.")
        return False

    # Initialize results files with proper headers
    initialize_results_files(columns)

    # Process each row
    benign_count = 0
    malicious_count = 0

    logger.info(f"Processing {row_count} rows through isolation model...")

    for index, row in df.iterrows():
        # Get unique serial number for this row
        serial_number = get_next_serial_number()

        # Get features for model (excluding ignored columns)
        features = get_model_features(row, columns)

        # Predict using isolation model
        prediction = predict_anomaly(model, features)

        # Convert row to dictionary for output
        row_dict = row.to_dict()

        # Determine label and append to appropriate file
        if prediction == NORMAL_LABEL:
            label = 'benign'
            benign_count += 1
        else:
            label = 'malicious'
            malicious_count += 1

        # Append to results file (includes all columns + serial number + label)
        append_to_results(row_dict, label, serial_number, columns)

        # Log progress every 1000 rows
        if (index + 1) % 1000 == 0:
            logger.info(f"Processed {index + 1}/{row_count} rows...")

    # Final summary
    logger.info(f"Processing complete for {file_name}")
    logger.info(f"Total rows processed: {row_count}")
    logger.info(f"Benign (normal) rows: {benign_count}")
    logger.info(f"Malicious (anomaly) rows: {malicious_count}")
    logger.info(f"Results saved to:")
    logger.info(f"  - Benign: {BENIGN_RESULTS_FILE}")
    logger.info(f"  - Malicious: {MALICIOUS_RESULTS_FILE}")

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

    # Load serial counter
    load_serial_counter()

    logger.info("=" * 60)
    logger.info("IDS/NIDS Pipeline - CSV Ingestion Service Starting")
    logger.info("=" * 60)
    logger.info(f"Monitoring directory: {INPUT_CSV_DIR}")
    logger.info(f"Processed files will be moved to: {PROCESSED_CSV_DIR}")
    logger.info(f"Isolation model location: {ISOLATION_MODEL_FILE}")
    logger.info(f"Results directory: {RESULTS_DIR}")
    logger.info(f"Columns to ignore: {COLUMNS_TO_IGNORE}")
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
    load_serial_counter()

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
    3. For each CSV:
       - Assign unique serial numbers to each row
       - Send rows (minus ignored columns) to isolation model
       - Output results to benign_results.csv or malicious_results.csv
       - Move processed CSV to processed_csv/
    4. Continue running until interrupted (Ctrl+C)
    """
    # First, process any existing files
    process_existing_files()

    # Then start watching for new files
    start_file_watcher()
