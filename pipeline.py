"""
Dual-mode IDS pipeline with chunked CSV processing.

Modes:
1) RAW_DB_FLOW:
   CSV -> raw_data DB -> anomaly model -> split -> normal_traffic DB / anomalies DB
2) ANOMALY_TEST_FLOW:
   CSV -> anomaly model -> update detection in-memory -> multi-class model -> console output
"""

import json
import logging
import os
from typing import Iterable, List, Optional, Tuple

import pandas as pd

from config.settings import (
    ANOMALIES_TABLE,
    CHUNK_SIZE,
    INPUT_FOLDER,
    MAX_ROWS_PER_FILE,
    NORMAL_TRAFFIC_TABLE,
    PIPELINE_MODE,
    PROCESS_ALL_FILES,
    RAW_DATA_TABLE,
)
from db_connection import close_connection, get_mysql_connection


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ids_pipeline")


def anomaly_model(chunk: pd.DataFrame) -> pd.Series:
    """Placeholder anomaly model: returns 1 (normal) or -1 (anomaly)."""
    numeric = chunk.select_dtypes(include=["number"])
    if numeric.empty:
        return pd.Series([1] * len(chunk), index=chunk.index)
    score = numeric.fillna(0).sum(axis=1)
    return score.apply(lambda value: -1 if int(value) % 7 == 0 else 1)


def multi_class_model(anomaly_chunk: pd.DataFrame) -> pd.Series:
    """Placeholder multi-class model: returns attack labels."""
    if anomaly_chunk.empty:
        return pd.Series(dtype="object", index=anomaly_chunk.index)
    return anomaly_chunk["row_id"].apply(
        lambda row_id: "ATTACK_DOS" if int(row_id) % 2 == 0 else "ATTACK_PROBE"
    )


def get_csv_files(input_folder: str) -> List[str]:
    if not os.path.isdir(input_folder):
        logger.warning("Input folder does not exist: %s", input_folder)
        return []
    files = [
        os.path.join(input_folder, name)
        for name in os.listdir(input_folder)
        if name.lower().endswith(".csv")
    ]
    return sorted(files)


def read_file_in_chunks(file_path: str) -> Iterable[pd.DataFrame]:
    nrows = None if PROCESS_ALL_FILES else MAX_ROWS_PER_FILE
    return pd.read_csv(file_path, chunksize=CHUNK_SIZE, nrows=nrows)


def enrich_chunk(chunk: pd.DataFrame, file_id: str, row_start: int) -> Tuple[pd.DataFrame, int]:
    chunk = chunk.copy()
    row_end = row_start + len(chunk)
    chunk.insert(0, "file_id", file_id)
    chunk.insert(1, "row_id", range(row_start, row_end))
    if "detection" not in chunk.columns:
        chunk["detection"] = None
    return chunk, row_end


def ensure_tables(connection) -> None:
    ddl = """
    CREATE TABLE IF NOT EXISTS `{table_name}` (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        file_id VARCHAR(255) NOT NULL,
        row_id BIGINT NOT NULL,
        detection VARCHAR(128) NULL,
        payload LONGTEXT NOT NULL,
        ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_file_row (file_id, row_id)
    ) ENGINE=InnoDB
    """
    cursor = connection.cursor()
    for table in (RAW_DATA_TABLE, NORMAL_TRAFFIC_TABLE, ANOMALIES_TABLE):
        cursor.execute(ddl.format(table_name=table))
    connection.commit()
    cursor.close()


def insert_chunk(connection, table_name: str, chunk: pd.DataFrame) -> None:
    sql = (
        f"INSERT INTO `{table_name}` (file_id, row_id, detection, payload) "
        "VALUES (%s, %s, %s, %s)"
    )
    cursor = connection.cursor()
    payload_rows = []
    for row in chunk.where(pd.notnull(chunk), None).to_dict(orient="records"):
        file_id = row.get("file_id")
        row_id = row.get("row_id")
        detection = row.get("detection")
        payload = json.dumps(row, default=str)
        payload_rows.append((file_id, row_id, detection, payload))
    if payload_rows:
        cursor.executemany(sql, payload_rows)
        connection.commit()
    cursor.close()


def process_file_raw_db_flow(file_path: str, connection) -> None:
    file_name = os.path.basename(file_path)
    file_id = os.path.splitext(file_name)[0]
    row_counter = 1
    logger.info("RAW_DB_FLOW processing file: %s", file_name)

    for chunk_idx, chunk in enumerate(read_file_in_chunks(file_path), start=1):
        try:
            enriched_chunk, row_counter = enrich_chunk(chunk, file_id, row_counter)
            insert_chunk(connection, RAW_DATA_TABLE, enriched_chunk)

            anomaly_flags = anomaly_model(enriched_chunk)
            enriched_chunk["_anomaly_flag"] = anomaly_flags

            normal_chunk = enriched_chunk[enriched_chunk["_anomaly_flag"] == 1].drop(
                columns=["_anomaly_flag"]
            )
            anomalies_chunk = enriched_chunk[enriched_chunk["_anomaly_flag"] == -1].drop(
                columns=["_anomaly_flag"]
            )

            insert_chunk(connection, NORMAL_TRAFFIC_TABLE, normal_chunk)
            insert_chunk(connection, ANOMALIES_TABLE, anomalies_chunk)
            logger.info("Processed chunk %s for %s", chunk_idx, file_name)
        except Exception:
            logger.exception(
                "Chunk %s failed in RAW_DB_FLOW for file %s. Continuing...",
                chunk_idx,
                file_name,
            )


def process_file_anomaly_test_flow(file_path: str) -> None:
    file_name = os.path.basename(file_path)
    file_id = os.path.splitext(file_name)[0]
    row_counter = 1
    logger.info("ANOMALY_TEST_FLOW processing file: %s", file_name)

    for chunk_idx, chunk in enumerate(read_file_in_chunks(file_path), start=1):
        try:
            enriched_chunk, row_counter = enrich_chunk(chunk, file_id, row_counter)
            anomaly_flags = anomaly_model(enriched_chunk)
            enriched_chunk["_anomaly_flag"] = anomaly_flags

            anomaly_indices = enriched_chunk[enriched_chunk["_anomaly_flag"] == -1].index
            if len(anomaly_indices) > 0:
                labels = multi_class_model(enriched_chunk.loc[anomaly_indices])
                enriched_chunk.loc[anomaly_indices, "detection"] = labels

            output_chunk = enriched_chunk.drop(columns=["_anomaly_flag"])
            print(f"\n[{file_name}] chunk={chunk_idx}")
            print(output_chunk.head().to_string(index=False))
        except Exception:
            logger.exception(
                "Chunk %s failed in ANOMALY_TEST_FLOW for file %s. Continuing...",
                chunk_idx,
                file_name,
            )


def run_pipeline() -> None:
    files = get_csv_files(INPUT_FOLDER)
    if not files:
        logger.info("No CSV files found in input folder: %s", INPUT_FOLDER)
        return

    if PIPELINE_MODE == "RAW_DB_FLOW":
        connection: Optional[object] = None
        try:
            connection = get_mysql_connection()
            ensure_tables(connection)
            for file_path in files:
                process_file_raw_db_flow(file_path, connection)
        finally:
            close_connection(connection)
    elif PIPELINE_MODE == "ANOMALY_TEST_FLOW":
        for file_path in files:
            process_file_anomaly_test_flow(file_path)
    else:
        raise ValueError(
            "Invalid PIPELINE_MODE. Use 'RAW_DB_FLOW' or 'ANOMALY_TEST_FLOW'."
        )


if __name__ == "__main__":
    run_pipeline()
