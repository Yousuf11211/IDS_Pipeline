# IDS/NIDS Pipeline - CSV Ingestion Service

## 📋 Project Overview

This project implements a **file-watching ingestion service** for an Intrusion Detection System (IDS) / Network Intrusion Detection System (NIDS) pipeline. The service automatically detects when CSV files are dropped into a designated input directory, validates the data, and prepares it for future database insertion.

### Current Phase: Ingestion Only

> ⚠️ **Important Note**: Database integration is intentionally disabled in this phase. The service performs file monitoring, validation, and logging only. Actual database connections and data insertion will be implemented in a future phase.

## 📂 Folder Structure

```
pipeline/
├── input_csv/              # Drop CSV files here for processing
├── processed_csv/          # Successfully processed CSVs are moved here
├── ingestion/
│   ├── __init__.py
│   └── ingest_csv.py       # Main ingestion service
├── config/
│   ├── __init__.py
│   └── settings.py         # Configuration settings (DB vars empty)
├── logs/
│   └── ingestion.log       # Log file for all ingestion events
├── requirements.txt        # Python dependencies
├── README.md               # This file
└── .gitignore              # Git ignore rules
```

### Directory Descriptions

| Directory | Purpose |
|-----------|---------|
| `input_csv/` | **Input folder** - Place CSV files here to trigger automatic ingestion |
| `processed_csv/` | **Archive folder** - Successfully processed files are moved here |
| `ingestion/` | **Service code** - Contains the main ingestion service script |
| `config/` | **Configuration** - Settings and placeholder DB variables |
| `logs/` | **Logging** - Contains `ingestion.log` with all service events |

## 🔄 How Ingestion Works

### Step-by-Step Process

1. **Service Start**
   - The ingestion service starts and creates required directories if they don't exist
   - Any existing CSV files in `input_csv/` are processed first
   - The file watcher begins monitoring the `input_csv/` directory

2. **CSV Detection**
   - When a new `.csv` file is dropped into `input_csv/`, it is automatically detected
   - The service waits briefly (1 second) to ensure the file is completely written

3. **Validation**
   - The CSV file is checked for:
     - File existence and readability
     - Non-zero file size
     - Parseable CSV content
     - At least one data row

4. **Processing**
   - The file is read using Pandas
   - Row count and column information are logged
   - Data is marked as "ready for future DB insertion"
   - **Note**: No actual database connection or insertion occurs

5. **Post-Processing**
   - Successfully processed files are moved to `processed_csv/`
   - If a file with the same name exists, a timestamp is appended
   - Failed files remain in `input_csv/` for retry/investigation

6. **Logging**
   - All events are logged to `logs/ingestion.log` and console
   - Includes: file detection, validation results, row counts, errors, file moves

## 🚀 How to Run the Ingestion Service

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

### Installation

1. **Navigate to the pipeline directory:**
   ```bash
   cd pipeline
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # Linux/macOS
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Running the Service

```bash
# From the pipeline directory
python ingestion/ingest_csv.py
```

The service will:
1. Process any existing CSV files in `input_csv/`
2. Start monitoring for new files
3. Continue running until stopped with `Ctrl+C`

### Example Output

```
2026-01-29 10:00:00 - INFO - ============================================================
2026-01-29 10:00:00 - INFO - IDS/NIDS Pipeline - CSV Ingestion Service Starting
2026-01-29 10:00:00 - INFO - ============================================================
2026-01-29 10:00:00 - INFO - Monitoring directory: /path/to/input_csv
2026-01-29 10:00:00 - INFO - Processed files will be moved to: /path/to/processed_csv
2026-01-29 10:00:00 - INFO - Waiting for CSV files...
2026-01-29 10:00:00 - INFO - ------------------------------------------------------------
2026-01-29 10:00:15 - INFO - CSV file detected: network_data.csv
2026-01-29 10:00:16 - INFO - Starting processing of CSV file: network_data.csv
2026-01-29 10:00:16 - INFO - CSV validated successfully: network_data.csv
2026-01-29 10:00:16 - INFO - Rows detected: 1000
2026-01-29 10:00:16 - INFO - Columns detected: 15
2026-01-29 10:00:16 - INFO - Data from network_data.csv is prepared and ready for future DB insertion
2026-01-29 10:00:16 - INFO - File moved successfully: network_data.csv -> processed_csv/
```

## ⚙️ Configuration

Configuration settings are located in `config/settings.py`:

| Setting | Description | Default |
|---------|-------------|---------|
| `INPUT_CSV_DIR` | Directory to monitor for CSV files | `./input_csv` |
| `PROCESSED_CSV_DIR` | Directory for processed files | `./processed_csv` |
| `FILE_STABILITY_DELAY` | Wait time before processing (seconds) | `1.0` |
| `LOG_FILE` | Path to log file | `./logs/ingestion.log` |

### Database Configuration (Future Phase)

The following database variables are defined but intentionally left empty:

```python
DB_SERVER = ""      # TODO: Set when DB is ready
DB_DATABASE = ""    # TODO: Set when DB is ready
DB_USERNAME = ""    # TODO: Set when DB is ready
DB_PASSWORD = ""    # TODO: Set when DB is ready
```

## 🚫 What This Phase Does NOT Include

The following features are **explicitly not implemented** in this phase:

- ❌ Database connections or inserts
- ❌ SQLAlchemy engine or ORM
- ❌ Column/schema mapping
- ❌ Data transformations
- ❌ Machine learning model calls
- ❌ Dashboard updates

These features will be added in future phases.

## 📝 Logging

All events are logged to `logs/ingestion.log` with the following format:

```
TIMESTAMP - LEVEL - MESSAGE
```

### Log Levels

| Level | Description |
|-------|-------------|
| INFO | Normal operations (file detected, processed, moved) |
| WARNING | Non-critical issues (duplicate filenames) |
| ERROR | Processing failures or exceptions |

## 🔧 Troubleshooting

### Service doesn't detect new files
- Ensure the file has a `.csv` extension
- Check that the file is placed in `input_csv/` (not a subdirectory)
- Verify the service is running (check console output)

### CSV validation fails
- Ensure the CSV file is not empty
- Check that the file is a valid CSV format
- Look at `logs/ingestion.log` for specific error messages

### File not moved after processing
- Check for write permissions on `processed_csv/`
- Review error messages in the log file

## 📄 License

This project is part of the IDS/NIDS Pipeline initiative.

---

**Version**: 1.0.0 (Phase 1 - Ingestion Only)  
**Last Updated**: January 2026
