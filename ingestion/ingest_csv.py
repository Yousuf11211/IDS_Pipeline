"""
CSV Ingestion Service for IDS/NIDS Pipeline.

This module implements a file-watching service that automatically detects
new CSV files in the input directory, processes them row by row through
an isolation model for anomaly detection, and outputs results to separate
CSV files for benign and malicious traffic.

Flow:
1. Watch input_csv/ folder for new CSV files
2. Add detected CSVs to a processing queue (FIFO)
3. Process each CSV one by one from the queue
4. For each row: assign serial number, send to isolation model
5. Append result to benign_results.csv or malicious_results.csv (LIVE updates)
6. Move processed CSV to processed_csv/ folder
"""

import os
import sys
import time
import shutil
import logging
import joblib
import threading
from queue import Queue
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
    NORMAL_LABEL,
    CHUNK_SIZE
)


# =============================================================================
# LOGGING SETUP
# =============================================================================

def setup_logging():
    """
    Configure logging to write to both file and console.
    Creates the logs directory if it doesn't exist.
    """
    os.makedirs(LOGS_DIR, exist_ok=True)

    logger = logging.getLogger("ingestion")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


# Initialize logger
logger = setup_logging()

# Global queue for CSV files to be processed (FIFO - First In, First Out)
file_queue = Queue()

# Flag to control the queue processor thread
queue_processor_running = True


# =============================================================================
# DIRECTORY SETUP
# =============================================================================

def ensure_directories_exist():
    """Create required directories if they don't exist."""
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

_isolation_model = None


def load_isolation_model():
    """Load the isolation forest model from the model file using joblib."""
    global _isolation_model

    if _isolation_model is not None:
        return _isolation_model

    if not os.path.exists(ISOLATION_MODEL_FILE):
        logger.error(f"Isolation model not found at: {ISOLATION_MODEL_FILE}")
        logger.error("Please place your trained isolation.joblib in the isolation_model/ folder")
        return None

    try:
        _isolation_model = joblib.load(ISOLATION_MODEL_FILE)
        logger.info(f"Isolation model loaded successfully from: {ISOLATION_MODEL_FILE}")
        return _isolation_model
    except Exception as e:
        logger.error(f"Failed to load isolation model: {str(e)}")
        return None


def predict_anomaly(model, row_data):
    """Use the isolation model to predict if a row is anomaly or normal."""
    try:
        features = np.array(row_data).reshape(1, -1)
        prediction = model.predict(features)
        return prediction[0]
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return ANOMALY_LABEL


# =============================================================================
# RESULTS FILE HANDLING
# =============================================================================

def initialize_results_files(columns):
    """Initialize the results CSV files with headers if they don't exist."""
    header_columns = ['serial_number'] + columns + ['label']

    for results_file, label in [(BENIGN_RESULTS_FILE, 'benign'), (MALICIOUS_RESULTS_FILE, 'malicious')]:
        if not os.path.exists(results_file):
            df_header = pd.DataFrame(columns=header_columns)
            df_header.to_csv(results_file, index=False)
            logger.info(f"Created {label} results file: {results_file}")


def append_to_results(row_data, label, serial_number, columns):
    """
    Append a row to the appropriate results CSV file.
    Writes immediately (no buffering) for live updates.
    """
    if label == 'benign':
        results_file = BENIGN_RESULTS_FILE
    else:
        results_file = MALICIOUS_RESULTS_FILE

    output_row = {'serial_number': serial_number}
    for col in columns:
        output_row[col] = row_data.get(col, '')
    output_row['label'] = label

    df_row = pd.DataFrame([output_row])
    file_exists = os.path.exists(results_file) and os.path.getsize(results_file) > 0

    # Write with flush for immediate live update
    with open(results_file, 'a', newline='', encoding='utf-8') as f:
        df_row.to_csv(f, header=not file_exists, index=False)
        f.flush()


# =============================================================================
# SERIAL NUMBER GENERATOR
# =============================================================================

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
    """Validate that a CSV file is readable and not empty (without loading entire file)."""
    try:
        if not os.path.exists(file_path):
            return False, None, "File does not exist"

        if os.path.getsize(file_path) == 0:
            return False, None, "File is empty (0 bytes)"

        # Only read first few rows to validate and get columns
        df_sample = pd.read_csv(file_path, nrows=5)

        if df_sample.empty:
            return False, None, "CSV file has no data rows"

        # Return column names instead of full dataframe
        return True, list(df_sample.columns), None

    except pd.errors.EmptyDataError:
        return False, None, "CSV file is empty or has no parseable data"
    except pd.errors.ParserError as e:
        return False, None, f"CSV parsing error: {str(e)}"
    except Exception as e:
        return False, None, f"Unexpected error reading CSV: {str(e)}"


def count_csv_rows(file_path):
    """Count total rows in CSV without loading into memory."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Subtract 1 for header row
            return sum(1 for _ in f) - 1
    except Exception:
        return 0


def get_model_features(row, columns):
    """Extract features for the model, excluding ignored columns."""
    features = []
    for col in columns:
        if col not in COLUMNS_TO_IGNORE:
            value = row[col]
            try:
                features.append(float(value))
            except (ValueError, TypeError):
                features.append(0)
    return features


def process_csv_file(file_path):
    """
    Process a CSV file in chunks through the isolation model.
    Only loads CHUNK_SIZE rows into memory at a time.
    Shows LIVE progress updates for each row processed.
    """
    file_name = os.path.basename(file_path)
    logger.info(f"Starting processing of CSV file: {file_name}")

    is_valid, columns, error_message = validate_csv_file(file_path)

    if not is_valid:
        logger.error(f"Validation failed for {file_name}: {error_message}")
        return False

    # Count total rows without loading entire file
    row_count = count_csv_rows(file_path)
    column_count = len(columns)

    logger.info(f"CSV validated successfully: {file_name}")
    logger.info(f"Rows detected: {row_count}")
    logger.info(f"Columns detected: {column_count}")
    logger.info(f"Column names: {columns}")
    logger.info(f"Columns to ignore for model: {COLUMNS_TO_IGNORE}")
    logger.info(f"Processing in chunks of {CHUNK_SIZE} rows (memory efficient)")

    model = load_isolation_model()
    if model is None:
        logger.error("Cannot process without isolation model. Please add model to isolation_model/ folder.")
        return False

    initialize_results_files(columns)

    benign_count = 0
    malicious_count = 0
    processed_rows = 0

    logger.info(f"Processing {row_count} rows through isolation model...")
    print()  # Empty line for cleaner output

    # Process CSV in chunks - only CHUNK_SIZE rows in memory at a time
    for chunk in pd.read_csv(file_path, chunksize=CHUNK_SIZE):
        for index, row in chunk.iterrows():
            serial_number = get_next_serial_number()
            features = get_model_features(row, columns)
            prediction = predict_anomaly(model, features)
            row_dict = row.to_dict()

            if prediction == NORMAL_LABEL:
                label = 'benign'
                benign_count += 1
            else:
                label = 'malicious'
                malicious_count += 1

            append_to_results(row_dict, label, serial_number, columns)
            processed_rows += 1

            # LIVE progress update - overwrites same line for real-time feedback
            progress = (processed_rows / row_count) * 100 if row_count > 0 else 100
            sys.stdout.write(f"\r[LIVE] Row {processed_rows}/{row_count} ({progress:.1f}%) | Serial: {serial_number} | Result: {label.upper():10} | Benign: {benign_count} | Malicious: {malicious_count}")
            sys.stdout.flush()

    print()  # New line after progress complete

    logger.info(f"Processing complete for {file_name}")
    logger.info(f"Total rows processed: {processed_rows}")
    logger.info(f"Benign (normal) rows: {benign_count}")
    logger.info(f"Malicious (anomaly) rows: {malicious_count}")
    logger.info(f"Results saved to:")
    logger.info(f"  - Benign: {BENIGN_RESULTS_FILE}")
    logger.info(f"  - Malicious: {MALICIOUS_RESULTS_FILE}")

    return True


def move_to_processed(file_path):
    """Move a successfully processed CSV file to the processed_csv directory."""
    file_name = os.path.basename(file_path)
    destination = os.path.join(PROCESSED_CSV_DIR, file_name)

    try:
        if os.path.exists(destination):
            base_name, extension = os.path.splitext(file_name)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            new_filename = f"{base_name}_{timestamp}{extension}"
            destination = os.path.join(PROCESSED_CSV_DIR, new_filename)
            logger.warning(f"Duplicate filename detected. Renaming to: {new_filename}")

        shutil.move(file_path, destination)
        logger.info(f"File moved successfully: {file_name} -> processed_csv/")
        return True

    except Exception as e:
        logger.error(f"Failed to move file {file_name}: {str(e)}")
        return False


# =============================================================================
# QUEUE PROCESSOR
# =============================================================================

def queue_processor():
    """
    Worker thread that processes files from the queue one by one.
    Ensures files are processed sequentially in FIFO order.
    """
    global queue_processor_running

    logger.info("Queue processor started - waiting for files...")

    while queue_processor_running:
        try:
            try:
                file_path = file_queue.get(timeout=1.0)
            except:
                continue

            file_name = os.path.basename(file_path)
            queue_size = file_queue.qsize()

            logger.info(f"Processing from queue: {file_name} (remaining in queue: {queue_size})")

            if not os.path.exists(file_path):
                logger.warning(f"File no longer exists, skipping: {file_name}")
                file_queue.task_done()
                continue

            try:
                success = process_csv_file(file_path)

                if success:
                    move_to_processed(file_path)
                else:
                    logger.error(f"Processing failed for: {file_name}")

            except Exception as e:
                logger.error(f"Unexpected error processing {file_name}: {str(e)}")

            file_queue.task_done()

        except Exception as e:
            logger.error(f"Queue processor error: {str(e)}")

    logger.info("Queue processor stopped.")


# =============================================================================
# FILE WATCHER EVENT HANDLER
# =============================================================================

class CSVEventHandler(FileSystemEventHandler):
    """
    Custom event handler for watching CSV files.
    Adds detected CSV files to a queue for sequential processing.
    """

    def __init__(self):
        super().__init__()
        self.queued_files = set()

    def on_created(self, event):
        """Handle file creation events - adds files to the processing queue."""
        if event.is_directory:
            return

        file_path = event.src_path
        file_name = os.path.basename(file_path)

        if not file_name.lower().endswith(WATCH_EXTENSION):
            return

        if file_path in self.queued_files:
            return

        logger.info(f"CSV file detected: {file_name}")

        time.sleep(FILE_STABILITY_DELAY)

        if not os.path.exists(file_path):
            logger.warning(f"File no longer exists: {file_name}")
            return

        self.queued_files.add(file_path)
        file_queue.put(file_path)

        queue_size = file_queue.qsize()
        logger.info(f"Added to queue: {file_name} (queue size: {queue_size})")


# =============================================================================
# MAIN SERVICE FUNCTIONS
# =============================================================================

def start_file_watcher():
    """
    Start the file watching service with queue-based processing.
    Files are processed in FIFO order (First In, First Out).
    """
    global queue_processor_running

    ensure_directories_exist()
    load_serial_counter()

    logger.info("=" * 60)
    logger.info("IDS/NIDS Pipeline - CSV Ingestion Service Starting")
    logger.info("=" * 60)
    logger.info(f"Monitoring directory: {INPUT_CSV_DIR}")
    logger.info(f"Processed files will be moved to: {PROCESSED_CSV_DIR}")
    logger.info(f"Isolation model location: {ISOLATION_MODEL_FILE}")
    logger.info(f"Results directory: {RESULTS_DIR}")
    logger.info(f"Columns to ignore: {COLUMNS_TO_IGNORE}")
    logger.info("Queue-based processing: Files processed one at a time (FIFO)")
    logger.info("-" * 60)

    # Start the queue processor thread
    queue_processor_running = True
    processor_thread = threading.Thread(target=queue_processor, daemon=True)
    processor_thread.start()

    # Create event handler and observer
    event_handler = CSVEventHandler()
    observer = Observer()
    observer.schedule(event_handler, INPUT_CSV_DIR, recursive=False)
    observer.start()

    logger.info("File watcher started. Waiting for CSV files...")
    logger.info("-" * 60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutdown signal received. Stopping ingestion service...")
        queue_processor_running = False
        observer.stop()

    observer.join()
    processor_thread.join(timeout=5.0)
    logger.info("Ingestion service stopped.")


def process_existing_files():
    """Process any existing CSV files in the input directory by adding them to the queue."""
    ensure_directories_exist()
    load_serial_counter()

    logger.info("Checking for existing CSV files in input directory...")

    existing_files = sorted([
        f for f in os.listdir(INPUT_CSV_DIR)
        if f.lower().endswith(WATCH_EXTENSION)
    ])

    if not existing_files:
        logger.info("No existing CSV files found.")
        return

    logger.info(f"Found {len(existing_files)} existing CSV file(s). Adding to queue...")

    for file_name in existing_files:
        file_path = os.path.join(INPUT_CSV_DIR, file_name)
        file_queue.put(file_path)
        logger.info(f"Queued existing file: {file_name}")

    logger.info(f"All {len(existing_files)} existing files added to queue.")


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
    3. For each CSV (processed one by one from queue):
       - Assign unique serial numbers to each row
       - Send rows (minus ignored columns) to isolation model
       - Output results to benign_results.csv or malicious_results.csv
       - Show LIVE progress updates
       - Move processed CSV to processed_csv/
    4. Continue running until interrupted (Ctrl+C)
    """
    process_existing_files()
    start_file_watcher()
