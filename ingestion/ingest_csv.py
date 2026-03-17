"""
CSV Ingestion Service for IDS/NIDS Pipeline with Two-Stage Classification.

This module implements a file-watching service with a two-stage ML pipeline:
1. Isolation Model: Detects if traffic is benign or potentially malicious
2. Random Forest Model: Classifies the specific attack type for malicious traffic

Flow:
1. Watch input_csv/ folder for new CSV files
2. Add detected CSVs to a file queue (FIFO)
3. For each CSV:
   - Add rows to a row queue (batch of ISOLATION_BATCH_SIZE rows)
   - First model (Isolation): Classify as benign or not benign
   - If benign: Print result to console
   - If not benign: Send to second model (Random Forest) for attack classification
   - Print all results to console
4. Move processed CSV to processed_csv/ folder
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
    RANDOM_FOREST_DIR,
    RANDOM_FOREST_MODEL_FILE,
    LABEL_MAPPING_FILE,
    RESULTS_DIR,
    BENIGN_RESULTS_FILE,
    MALICIOUS_RESULTS_FILE,
    COLUMNS_TO_IGNORE,
    ANOMALY_LABEL,
    NORMAL_LABEL,
    ISOLATION_BATCH_SIZE,
    ROW_QUEUE_MAX_SIZE,
    TEST_ROW_LIMIT,
    CHUNK_SIZE,
    MOVE_PROCESSED_FILES
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

# Global queues
file_queue = Queue()  # Queue for CSV files to be processed
row_queue = Queue(maxsize=ROW_QUEUE_MAX_SIZE)  # Queue for rows to be processed by isolation model
attack_queue = Queue()  # Queue for rows to be classified by random forest

# Flag to control the queue processor threads
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
        RANDOM_FOREST_DIR,
        RESULTS_DIR
    ]

    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logger.info(f"Created directory: {directory}")


# =============================================================================
# MODEL LOADERS
# =============================================================================

_isolation_model = None
_random_forest_model = None
_label_mapping = None


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


def load_random_forest_model():
    """Load the random forest model and label mapping."""
    global _random_forest_model, _label_mapping

    if _random_forest_model is not None:
        return _random_forest_model, _label_mapping

    if not os.path.exists(RANDOM_FOREST_MODEL_FILE):
        logger.error(f"Random forest model not found at: {RANDOM_FOREST_MODEL_FILE}")
        logger.error("Please place your trained RF model in the random_forest/ folder")
        return None, None

    try:
        _random_forest_model = joblib.load(RANDOM_FOREST_MODEL_FILE)
        logger.info(f"Random forest model loaded successfully from: {RANDOM_FOREST_MODEL_FILE}")

        # Load label mapping
        _label_mapping = load_label_mapping()

        return _random_forest_model, _label_mapping
    except Exception as e:
        logger.error(f"Failed to load random forest model: {str(e)}")
        return None, None


def load_label_mapping():
    """Load the attack label mapping from the text file."""
    mapping = {}

    if not os.path.exists(LABEL_MAPPING_FILE):
        logger.warning(f"Label mapping file not found at: {LABEL_MAPPING_FILE}")
        return mapping

    try:
        with open(LABEL_MAPPING_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if ':' in line and not line.startswith('='):
                    parts = line.split(':')
                    if len(parts) == 2:
                        label_name = parts[0].strip()
                        label_value = parts[1].strip()
                        try:
                            mapping[int(label_value)] = label_name
                        except ValueError:
                            continue
        logger.info(f"Loaded {len(mapping)} attack labels from mapping file")
        return mapping
    except Exception as e:
        logger.error(f"Failed to load label mapping: {str(e)}")
        return mapping


# =============================================================================
# PREDICTION FUNCTIONS
# =============================================================================

def get_model_features(row_dict, columns):
    """Extract features for the model, excluding ignored columns."""
    features = []
    for col in columns:
        if col not in COLUMNS_TO_IGNORE:
            value = row_dict.get(col, 0)
            try:
                features.append(float(value))
            except (ValueError, TypeError):
                features.append(0)
    return features


def predict_with_isolation_model(model, features):
    """
    Use the isolation model to predict if a row is benign or potentially malicious.
    Returns: 1 for benign, -1 for anomaly/potentially malicious
    """
    try:
        features_array = np.array(features).reshape(1, -1)
        prediction = model.predict(features_array)
        return prediction[0]
    except Exception as e:
        logger.error(f"Isolation model prediction error: {str(e)}")
        return ANOMALY_LABEL  # Default to anomaly on error


def predict_with_random_forest(model, features, label_mapping):
    """
    Use the random forest model to classify the specific attack type.
    Returns: (predicted_class_index, attack_name)
    """
    try:
        features_array = np.array(features).reshape(1, -1)
        prediction = model.predict(features_array)
        predicted_class = int(prediction[0])
        attack_name = label_mapping.get(predicted_class, f"Unknown_Attack_{predicted_class}")
        return predicted_class, attack_name
    except Exception as e:
        logger.error(f"Random forest prediction error: {str(e)}")
        return -1, "Prediction_Error"


# =============================================================================
# RESULTS SAVING
# =============================================================================

def save_results_to_csv(data_list, output_file):
    """
    Append processed results to the specified output CSV file.
    Creates the file with header if it doesn't exist.
    """
    if not data_list:
        return

    try:
        df = pd.DataFrame(data_list)
        
        # Check if file exists to determine if we need to write header
        file_exists = os.path.exists(output_file)
        
        # Append mode 'a', include header only if file is new
        df.to_csv(output_file, mode='a', header=not file_exists, index=False)
        logger.info(f"Appended {len(data_list)} rows to: {output_file}")
    except Exception as e:
        logger.error(f"Failed to save results to {output_file}: {str(e)}")


# =============================================================================
# CSV VALIDATION
# =============================================================================

def validate_csv_file(file_path):
    """Validate that a CSV file is readable and not empty."""
    try:
        if not os.path.exists(file_path):
            return False, None, "File does not exist"

        if os.path.getsize(file_path) == 0:
            return False, None, "File is empty (0 bytes)"

        # Read first few rows to validate and get columns
        df_sample = pd.read_csv(file_path, nrows=5)

        if df_sample.empty:
            return False, None, "CSV file has no data rows"

        return True, list(df_sample.columns), None

    except pd.errors.EmptyDataError:
        return False, None, "CSV file is empty or has no parseable data"
    except pd.errors.ParserError as e:
        return False, None, f"CSV parsing error: {str(e)}"
    except Exception as e:
        return False, None, f"Unexpected error reading CSV: {str(e)}"


# =============================================================================
# MAIN PROCESSING FUNCTION
# =============================================================================

def process_csv_file(file_path):
    """
    Process a CSV file through the two-stage classification pipeline.

    Stage 1: Isolation Model - Benign vs Not Benign
    Stage 2: Random Forest - Attack Classification (only for not benign)

    For testing, only processes TEST_ROW_LIMIT rows.
    """
    file_name = os.path.basename(file_path)
    logger.info(f"Starting processing of CSV file: {file_name}")

    # Validate CSV
    is_valid, columns, error_message = validate_csv_file(file_path)
    if not is_valid:
        logger.error(f"Validation failed for {file_name}: {error_message}")
        return False

    logger.info(f"CSV validated successfully: {file_name}")
    logger.info(f"Columns detected: {len(columns)}")
    logger.info(f"Columns to ignore for model: {COLUMNS_TO_IGNORE}")

    # Load models
    isolation_model = load_isolation_model()
    if isolation_model is None:
        logger.error("Cannot process without isolation model")
        return False

    rf_model, label_mapping = load_random_forest_model()
    if rf_model is None:
        logger.error("Cannot process without random forest model")
        return False

    print("\n" + "=" * 80)
    print("TWO-STAGE CLASSIFICATION PIPELINE - RESULTS")
    print("=" * 80)
    print(f"{'Row #':<8} {'Serial #':<10} {'Stage 1 (Isolation)':<25} {'Stage 2 (Attack Type)':<30}")
    print("-" * 80)

    serial_number = 0
    benign_count = 0
    attack_counts = {}

    # Lists to accumulate results for batch writing
    benign_rows = []
    malicious_rows = []

    # Process only TEST_ROW_LIMIT rows for testing
    rows_processed = 0

    with pd.read_csv(file_path, chunksize=CHUNK_SIZE) as reader:
        for chunk in reader:
            for index, row in chunk.iterrows():
                if TEST_ROW_LIMIT is not None and rows_processed >= TEST_ROW_LIMIT:
                    break

                serial_number += 1
                row_dict = row.to_dict()

                # Get features (excluding ignored columns)
                features = get_model_features(row_dict, columns)

                # Stage 1: Isolation Model
                isolation_result = predict_with_isolation_model(isolation_model, features)

                if isolation_result == NORMAL_LABEL:
                    # Benign - no need for stage 2
                    stage1_label = "BENIGN"
                    stage2_label = "N/A"
                    benign_count += 1
                    
                    # Add labels to row for results
                    row_dict['classification_stage1'] = stage1_label
                    row_dict['classification_stage2'] = stage2_label
                    row_dict['processed_timestamp'] = datetime.now().isoformat()
                    benign_rows.append(row_dict)
                else:
                    # Not benign - send to random forest for attack classification
                    stage1_label = "NOT BENIGN"
                    _, attack_name = predict_with_random_forest(rf_model, features, label_mapping)
                    stage2_label = attack_name
                    attack_counts[attack_name] = attack_counts.get(attack_name, 0) + 1
                    
                    # Add labels to row for results
                    row_dict['classification_stage1'] = stage1_label
                    row_dict['classification_stage2'] = stage2_label
                    row_dict['processed_timestamp'] = datetime.now().isoformat()
                    malicious_rows.append(row_dict)

                # Print result to console
                print(f"{rows_processed + 1:<8} {serial_number:<10} {stage1_label:<25} {stage2_label:<30}")

                rows_processed += 1

            if TEST_ROW_LIMIT is not None and rows_processed >= TEST_ROW_LIMIT:
                break

    # Save accumulated results to CSV files
    if benign_rows:
        save_results_to_csv(benign_rows, BENIGN_RESULTS_FILE)
    
    if malicious_rows:
        save_results_to_csv(malicious_rows, MALICIOUS_RESULTS_FILE)

    print("-" * 80)
    print("\nSUMMARY:")
    print(f"  Total rows processed: {rows_processed}")
    print(f"  Benign traffic: {benign_count}")
    print(f"  Potentially malicious: {rows_processed - benign_count}")

    if attack_counts:
        print("\n  Attack Type Breakdown:")
        for attack, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"    - {attack}: {count}")

    print("=" * 80 + "\n")

    logger.info(f"Processing complete for {file_name}")
    logger.info(f"Total rows processed: {rows_processed}")
    logger.info(f"Benign: {benign_count}, Potentially malicious: {rows_processed - benign_count}")

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
# FILE QUEUE PROCESSOR
# =============================================================================

def file_queue_processor():
    """
    Worker thread that processes files from the file queue one by one.
    """
    global queue_processor_running

    logger.info("File queue processor started - waiting for files...")

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
                    if MOVE_PROCESSED_FILES:
                        move_to_processed(file_path)
                    else:
                        logger.info(f"File moving disabled. File remains in input_csv/: {file_name}")
                else:
                    logger.error(f"Processing failed for: {file_name}")

            except Exception as e:
                logger.error(f"Unexpected error processing {file_name}: {str(e)}")

            file_queue.task_done()

        except Exception as e:
            logger.error(f"File queue processor error: {str(e)}")

    logger.info("File queue processor stopped.")


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
        logger.info(f"Added to file queue: {file_name} (queue size: {queue_size})")


# =============================================================================
# MAIN SERVICE FUNCTIONS
# =============================================================================

def start_file_watcher():
    """
    Start the file watching service with queue-based processing.
    """
    global queue_processor_running

    ensure_directories_exist()

    logger.info("=" * 60)
    logger.info("IDS/NIDS Pipeline - Two-Stage Classification Service Starting")
    logger.info("=" * 60)
    logger.info(f"Monitoring directory: {INPUT_CSV_DIR}")
    logger.info(f"Processed files directory: {PROCESSED_CSV_DIR}")
    logger.info(f"Move files after processing: {MOVE_PROCESSED_FILES}")
    logger.info(f"Stage 1 Model (Isolation): {ISOLATION_MODEL_FILE}")
    logger.info(f"Stage 2 Model (Random Forest): {RANDOM_FOREST_MODEL_FILE}")
    logger.info(f"Columns to ignore: {COLUMNS_TO_IGNORE}")
    logger.info(f"Test mode: Processing only {TEST_ROW_LIMIT} rows per file")
    logger.info("-" * 60)

    # Start the file queue processor thread
    queue_processor_running = True
    processor_thread = threading.Thread(target=file_queue_processor, daemon=True)
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
    """Process any existing CSV files in the input directory."""
    ensure_directories_exist()

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
    Main entry point for the two-stage classification ingestion service.
    
    Usage:
        python ingest_csv.py
        
    The service will:
    1. Process any existing CSV files in input_csv/
    2. Start monitoring for new CSV files
    3. For each CSV:
       - Stage 1: Send rows to Isolation Model (benign detection)
       - Stage 2: For non-benign rows, send to Random Forest (attack classification)
       - Print all results to console
       - Move processed CSV to processed_csv/
    4. Continue running until interrupted (Ctrl+C)
    
    Test Mode: Currently processes only 10 rows per file for testing.
    Change TEST_ROW_LIMIT in settings.py to None for full processing.
    """
    process_existing_files()
    start_file_watcher()
