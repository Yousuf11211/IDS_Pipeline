"""
Configuration settings for the IDS/NIDS Pipeline Ingestion Service.

This module contains placeholder configuration values for database connection
and other settings. Database integration is intentionally disabled in this phase.
"""

import os

# =============================================================================
# BASE PATHS
# =============================================================================

# Get the base directory of the pipeline
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Folder paths for CSV processing
INPUT_CSV_DIR = os.path.join(BASE_DIR, "input_csv")
PROCESSED_CSV_DIR = os.path.join(BASE_DIR, "processed_csv")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# =============================================================================
# DATABASE CONFIGURATION (PLACEHOLDERS - NOT CONNECTED)
# =============================================================================

# TODO: These variables are intentionally left empty.
# Database integration will be implemented in a future phase.
# Column mappings will be implemented later once the schema is finalized.

DB_SERVER = ""      # TODO: Set SQL Server hostname/IP when DB is ready
DB_DATABASE = ""    # TODO: Set database name when DB is ready
DB_USERNAME = ""    # TODO: Set database username when DB is ready
DB_PASSWORD = ""    # TODO: Set database password when DB is ready
DB_DRIVER = ""      # TODO: Set ODBC driver (e.g., "ODBC Driver 17 for SQL Server")

# TODO: Connection string will be constructed here once DB integration is enabled
# Example connection string format:
# CONNECTION_STRING = f"mssql+pyodbc://{DB_USERNAME}:{DB_PASSWORD}@{DB_SERVER}/{DB_DATABASE}?driver={DB_DRIVER}"

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

LOG_FILE = os.path.join(LOGS_DIR, "ingestion.log")
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_LEVEL = "INFO"

# =============================================================================
# FILE WATCHING CONFIGURATION
# =============================================================================

# Time (in seconds) to wait before processing a new file
# This helps ensure the file is completely written before reading
FILE_STABILITY_DELAY = 1.0

# File extension to watch for
WATCH_EXTENSION = ".csv"

# =============================================================================
# ISOLATION MODEL CONFIGURATION (First Model - Benign Detection)
# =============================================================================

# Folder for isolation model
ISOLATION_MODEL_DIR = os.path.join(BASE_DIR, "isolation_model")
ISOLATION_MODEL_FILE = os.path.join(ISOLATION_MODEL_DIR, "isolation.joblib")

# =============================================================================
# RANDOM FOREST MODEL CONFIGURATION (Second Model - Attack Classification)
# =============================================================================

# Folder for random forest model
RANDOM_FOREST_DIR = os.path.join(BASE_DIR, "random_forest")
RANDOM_FOREST_MODEL_FILE = os.path.join(RANDOM_FOREST_DIR, "Attacks_part_1_inf_handled_rf_model.joblib")
LABEL_MAPPING_FILE = os.path.join(RANDOM_FOREST_DIR, "Attacks_part_1_inf_handled_label_mapping.txt")

# =============================================================================
# RESULTS CONFIGURATION
# =============================================================================

# Folder for results
RESULTS_DIR = os.path.join(BASE_DIR, "results")
BENIGN_RESULTS_FILE = os.path.join(RESULTS_DIR, "benign_results.csv")
MALICIOUS_RESULTS_FILE = os.path.join(RESULTS_DIR, "malicious_results.csv")

# =============================================================================
# COLUMNS TO IGNORE FOR MODEL PREDICTION
# =============================================================================
# List of column names to exclude when sending data to the models
# These columns will still appear in the final results CSV
# Add column names here that should not be used for anomaly detection

COLUMNS_TO_IGNORE = [
    # Columns that were not used to train the model
    "timestamp",
    "src_ip",
    "label",
]

# =============================================================================
# MODEL CONFIGURATION
# =============================================================================

# Threshold for anomaly detection (-1 = anomaly/malicious, 1 = normal/benign)
# The isolation model outputs -1 for anomalies and 1 for normal instances
ANOMALY_LABEL = -1
NORMAL_LABEL = 1

# =============================================================================
# QUEUE AND BATCH CONFIGURATION
# =============================================================================

# Batch size for processing rows through the first model (isolation)
ISOLATION_BATCH_SIZE = 100

# Queue size limit for rows waiting to be processed
ROW_QUEUE_MAX_SIZE = 1000

# For testing: limit number of rows to process (set to None for no limit)
TEST_ROW_LIMIT = 10

# Chunk size for reading CSV files
CHUNK_SIZE = 100

# =============================================================================
# FILE HANDLING CONFIGURATION
# =============================================================================

# Whether to move processed CSV files to the processed_csv folder
# Set to True for production behavior
MOVE_PROCESSED_FILES = True

# =============================================================================
# PIPELINE MODE + CHUNK PROCESSING CONFIGURATION (DUAL FLOW)
# =============================================================================

# Switch between:
# - "RAW_DB_FLOW": CSV -> raw_data DB -> anomaly model -> split to normal/anomalies DB
# - "ANOMALY_TEST_FLOW": CSV -> anomaly model -> multi-class model -> console output
PIPELINE_MODE = "ANOMALY_TEST_FLOW"

# Input folder containing CSV files for pipeline processing
INPUT_FOLDER = INPUT_CSV_DIR

# If True, process all rows in each CSV.
# If False, process only MAX_ROWS_PER_FILE rows per CSV.
PROCESS_ALL_FILES = True
MAX_ROWS_PER_FILE = 100000

# Database table names used by RAW_DB_FLOW
RAW_DATA_TABLE = "raw_data"
NORMAL_TRAFFIC_TABLE = "normal_traffic"
ANOMALIES_TABLE = "anomalies"
