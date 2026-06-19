from __future__ import annotations

import os
import queue
import re
import threading
import time
import json
from typing import Any

import pymysql
from flask import Flask, jsonify, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash


DEFAULT_DATABASE = "airfoil_engineering_db"

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-only-change-this-secret")

_AUTH_SCHEMA_READY = False
_SAVED_TRANSACTION_SCHEMA_READY = False
_LINEAGE_SCHEMA_READY = False
_IMPORT_SCHEMA_READY = False
_AUDIT_SCHEMA_READY = False
_AIRFOIL_SCHEMA_READY = False
_SOFT_DELETE_SCHEMA_READY = False
_ANOMALY_TRIGGER_SCHEMA_READY = False
_PERFORMANCE_TRIGGER_SCHEMA_READY = False
_CORE_TRIGGER_SCHEMA_READY = False
_STORED_PROCEDURE_SCHEMA_READY = False
PASSWORD_HASH_METHOD = os.getenv("PASSWORD_HASH_METHOD", "pbkdf2:sha256:60000")
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "8"))
_DB_POOL: queue.LifoQueue[pymysql.connections.Connection] = queue.LifoQueue(maxsize=DB_POOL_SIZE)


def db_config() -> dict[str, Any]:
    return {
        "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
        "port": int(os.getenv("MYSQL_PORT", "3306")),
        "user": os.getenv("MYSQL_USER", "root"),
        "password": os.getenv("MYSQL_PASSWORD", ""),
        "database": os.getenv("MYSQL_DATABASE", DEFAULT_DATABASE),
        "charset": "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
    }


def make_password_hash(password: str) -> str:
    return generate_password_hash(password, method=PASSWORD_HASH_METHOD)


def get_db_connection() -> pymysql.connections.Connection:
    try:
        conn = _DB_POOL.get_nowait()
        conn.ping(reconnect=True)
        return conn
    except queue.Empty:
        return pymysql.connect(**db_config(), autocommit=False)


def release_db_connection(conn: pymysql.connections.Connection) -> None:
    try:
        conn.rollback()
        _DB_POOL.put_nowait(conn)
    except queue.Full:
        conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass


def query_all(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())
    finally:
        release_db_connection(conn)


def query_result_sets(sql: str, params: tuple[Any, ...] = ()) -> list[list[dict[str, Any]]]:
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            result_sets = [list(cur.fetchall())]
            while cur.nextset():
                if cur.description:
                    result_sets.append(list(cur.fetchall()))
        return result_sets
    finally:
        release_db_connection(conn)


def execute_write(sql: str, params: tuple[Any, ...] = ()) -> int:
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            affected = cur.execute(sql, params)
        conn.commit()
        return int(affected)
    finally:
        release_db_connection(conn)


def execute_write_return_id(sql: str, params: tuple[Any, ...] = ()) -> int:
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            new_id = cur.lastrowid
        conn.commit()
        return int(new_id)
    finally:
        release_db_connection(conn)


def log_user_action(
    user_id: int,
    natural_language: str | None,
    sql_text: str,
    is_valid: int,
    execution_time_ms: int = 0,
) -> None:
    execute_write(
        """
        INSERT INTO query_logs
            (user_id, natural_language, sql_text, is_ai_generated, is_valid, execution_time_ms)
        VALUES (%s, %s, %s, 0, %s, %s)
        """,
        (user_id, natural_language, sql_text, is_valid, execution_time_ms),
    )


def mark_lineage_modified(
    table_name: str,
    record_pk: str,
    airfoil_id: str | None,
    source_version: str,
    user: dict[str, Any],
) -> None:
    execute_write(
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, previous_record_version_id, is_modified,
             last_modified_at, modified_by_user_id, modified_by_username, modified_count, last_operation)
        VALUES
            (%s, %s, %s, %s, 1, 0, 1, CURRENT_TIMESTAMP, %s, %s, 1, 'UPDATE')
        ON DUPLICATE KEY UPDATE
            airfoil_id = VALUES(airfoil_id),
            source_version = VALUES(source_version),
            previous_record_version_id = record_version_id,
            record_version_id = record_version_id + 1,
            is_modified = 1,
            last_modified_at = CURRENT_TIMESTAMP,
            modified_by_user_id = VALUES(modified_by_user_id),
            modified_by_username = VALUES(modified_by_username),
            modified_count = modified_count + 1,
            last_operation = 'UPDATE'
        """,
        (table_name, record_pk, airfoil_id, source_version, user["user_id"], user["username"]),
    )


def mark_lineage_deleted(
    table_name: str,
    record_pk: str,
    airfoil_id: str | None,
    source_version: str,
    user: dict[str, Any],
) -> None:
    ensure_lineage_schema()
    execute_write(
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, previous_record_version_id, is_modified,
             last_modified_at, modified_by_user_id, modified_by_username, modified_count, last_operation)
        VALUES
            (%s, %s, %s, %s, 1, 0, 1, CURRENT_TIMESTAMP, %s, %s, 1, 'DELETE')
        ON DUPLICATE KEY UPDATE
            airfoil_id = VALUES(airfoil_id),
            source_version = VALUES(source_version),
            previous_record_version_id = record_version_id,
            record_version_id = record_version_id + 1,
            is_modified = 1,
            last_modified_at = CURRENT_TIMESTAMP,
            modified_by_user_id = VALUES(modified_by_user_id),
            modified_by_username = VALUES(modified_by_username),
            modified_count = modified_count + 1,
            last_operation = 'DELETE'
        """,
        (table_name, record_pk, airfoil_id, source_version, user["user_id"], user["username"]),
    )


def mark_lineage_restored(
    table_name: str,
    record_pk: str,
    airfoil_id: str | None,
    source_version: str,
    user: dict[str, Any],
) -> None:
    ensure_lineage_schema()
    execute_write(
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, previous_record_version_id, is_modified,
             last_modified_at, modified_by_user_id, modified_by_username, modified_count, last_operation)
        VALUES
            (%s, %s, %s, %s, 1, 0, 1, CURRENT_TIMESTAMP, %s, %s, 1, 'RESTORE')
        ON DUPLICATE KEY UPDATE
            airfoil_id = VALUES(airfoil_id),
            source_version = VALUES(source_version),
            previous_record_version_id = record_version_id,
            record_version_id = record_version_id + 1,
            is_modified = 1,
            last_modified_at = CURRENT_TIMESTAMP,
            modified_by_user_id = VALUES(modified_by_user_id),
            modified_by_username = VALUES(modified_by_username),
            modified_count = modified_count + 1,
            last_operation = 'RESTORE'
        """,
        (table_name, record_pk, airfoil_id, source_version, user["user_id"], user["username"]),
    )


def mark_lineage_insert(
    table_name: str,
    record_pk: str,
    airfoil_id: str | None,
    source_version: str,
) -> None:
    ensure_lineage_schema()
    execute_write(
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
        VALUES (%s, %s, %s, %s, 0, 0, 'INSERT')
        ON DUPLICATE KEY UPDATE
            airfoil_id = VALUES(airfoil_id),
            source_version = VALUES(source_version),
            last_operation = IF(is_modified = 1, last_operation, 'INSERT')
        """,
        (table_name, record_pk, airfoil_id, source_version),
    )


def current_record_version_id(table_name: str, record_pk: str) -> int:
    ensure_lineage_schema()
    rows = query_all(
        """
        SELECT record_version_id
        FROM data_record_lineage
        WHERE table_name = %s AND record_pk = %s
        LIMIT 1
        """,
        (table_name, record_pk),
    )
    if not rows:
        return 0
    return int(rows[0].get("record_version_id") or 0)


def log_audit_change(
    table_name: str,
    operation_type: str,
    record_pk: str,
    previous_record_version_id: int | None,
    record_version_id: int,
    old_values: dict[str, Any] | None,
    new_values: dict[str, Any] | None,
) -> None:
    ensure_audit_schema()
    execute_write(
        """
        INSERT INTO audit_logs
            (table_name, operation_type, record_pk, previous_record_version_id, record_version_id, old_values, new_values)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            table_name,
            operation_type,
            record_pk,
            previous_record_version_id,
            record_version_id,
            None if old_values is None else json.dumps(old_values, ensure_ascii=False, default=str),
            None if new_values is None else json.dumps(new_values, ensure_ascii=False, default=str),
        ),
    )


def log_data_import(
    target_table: str,
    record_pk: str,
    entry_method: str,
    user: dict[str, Any] | None,
    airfoil_id: str | None = None,
    version_id: int | None = None,
    source_type: str | None = None,
    description: str | None = None,
) -> None:
    record_version_id = current_record_version_id(target_table, record_pk)
    execute_write(
        """
        INSERT INTO data_import_records
            (target_table, record_pk, airfoil_id, version_id, source_type,
             entry_method, created_by_user_id, created_by_username, description,
             previous_record_version_id, record_version_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NULL, %s)
        ON DUPLICATE KEY UPDATE
            airfoil_id = VALUES(airfoil_id),
            version_id = VALUES(version_id),
            source_type = VALUES(source_type),
            created_by_user_id = VALUES(created_by_user_id),
            created_by_username = VALUES(created_by_username),
            created_at = CURRENT_TIMESTAMP,
            description = VALUES(description),
            previous_record_version_id = VALUES(previous_record_version_id),
            record_version_id = VALUES(record_version_id)
        """,
        (
            target_table,
            record_pk,
            airfoil_id,
            version_id,
            source_type,
            entry_method,
            None if user is None else user.get("user_id"),
            "system" if user is None else user.get("username"),
            description,
            record_version_id,
        ),
    )


def infer_sql_import_target(sql: str) -> tuple[str, str] | None:
    match = re.match(r"\s*insert\s+into\s+`?([A-Za-z_][A-Za-z0-9_]*)`?", sql, re.IGNORECASE)
    if not match:
        return None
    table_name = match.group(1)
    if table_name not in {"data_sources", "airfoils", "data_versions"}:
        return None
    return table_name, f"sql_insert_{int(time.time() * 1000)}"


def ensure_auth_schema() -> None:
    global _AUTH_SCHEMA_READY
    if _AUTH_SCHEMA_READY:
        return

    rows = query_all(
        f"""
        SELECT COUNT(*) AS count
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = 'users'
          AND column_name = 'password_hash'
        """
    )
    if rows[0]["count"] == 0:
        execute_write("ALTER TABLE users ADD COLUMN password_hash VARCHAR(255) NULL AFTER username")

    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")
    admin_role = os.getenv("ADMIN_ROLE", "admin")
    if admin_username and admin_password:
        password_hash = make_password_hash(admin_password)
        existing = query_all("SELECT user_id FROM users WHERE username = %s", (admin_username,))
        if existing:
            execute_write(
                """
                UPDATE users
                SET password_hash = %s, role = %s, is_active = 1
                WHERE username = %s
                """,
                (password_hash, admin_role, admin_username),
            )
        else:
            execute_write(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                (admin_username, password_hash, admin_role),
            )

    _AUTH_SCHEMA_READY = True


def ensure_saved_transaction_schema() -> None:
    global _SAVED_TRANSACTION_SCHEMA_READY
    if _SAVED_TRANSACTION_SCHEMA_READY:
        return

    execute_write(
        """
        CREATE TABLE IF NOT EXISTS saved_transactions (
            saved_id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            title VARCHAR(128) NOT NULL,
            sql_text TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_saved_transactions_user_title (user_id, title),
            INDEX idx_saved_transactions_user (user_id),
            CONSTRAINT fk_saved_transactions_user
                FOREIGN KEY (user_id) REFERENCES users(user_id)
                ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )
    _SAVED_TRANSACTION_SCHEMA_READY = True


def ensure_lineage_schema() -> None:
    global _LINEAGE_SCHEMA_READY
    if _LINEAGE_SCHEMA_READY:
        return
    execute_write(
        """
        CREATE TABLE IF NOT EXISTS data_record_lineage (
            lineage_id INT AUTO_INCREMENT PRIMARY KEY,
            table_name VARCHAR(64) NOT NULL,
            record_pk VARCHAR(191) NOT NULL,
            airfoil_id VARCHAR(64),
            source_version VARCHAR(64) NOT NULL,
            record_version_id INT NOT NULL DEFAULT 0,
            previous_record_version_id INT NULL,
            written_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            is_modified TINYINT NOT NULL DEFAULT 0,
            last_modified_at TIMESTAMP NULL,
            modified_by_user_id INT NULL,
            modified_by_username VARCHAR(64) NULL,
            modified_count INT NOT NULL DEFAULT 0,
            last_operation VARCHAR(16) NOT NULL DEFAULT 'INSERT',
            UNIQUE KEY uq_data_record_lineage_record (table_name, record_pk),
            INDEX idx_data_record_lineage_table (table_name),
            INDEX idx_data_record_lineage_airfoil (airfoil_id),
            INDEX idx_data_record_lineage_version (table_name, record_pk, record_version_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )
    existing_columns = {
        row["column_name"]
        for row in query_all(
            """
            SELECT COLUMN_NAME AS column_name
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'data_record_lineage'
            """
        )
    }
    if "record_version_id" not in existing_columns:
        execute_write("ALTER TABLE data_record_lineage ADD COLUMN record_version_id INT NOT NULL DEFAULT 0 AFTER source_version")
    else:
        execute_write("ALTER TABLE data_record_lineage MODIFY COLUMN record_version_id INT NOT NULL DEFAULT 0")
    if "previous_record_version_id" not in existing_columns:
        execute_write("ALTER TABLE data_record_lineage ADD COLUMN previous_record_version_id INT NULL AFTER record_version_id")
    if "modified_by_user_id" not in existing_columns:
        execute_write("ALTER TABLE data_record_lineage ADD COLUMN modified_by_user_id INT NULL AFTER last_modified_at")
    if "modified_by_username" not in existing_columns:
        execute_write("ALTER TABLE data_record_lineage ADD COLUMN modified_by_username VARCHAR(64) NULL AFTER modified_by_user_id")
    execute_write("""
        UPDATE data_record_lineage
        SET record_version_id = 0,
            previous_record_version_id = NULL
        WHERE is_modified = 0
          AND modified_count = 0
          AND last_operation = 'INSERT'
    """)
    for sql in [
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
        SELECT 'data_sources', source_type, NULL, 'source', 0, 0, 'INSERT'
        FROM data_sources
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
        SELECT 'airfoils', airfoil_id, airfoil_id, 'master', 0, 0, 'INSERT'
        FROM airfoils
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
        SELECT 'data_versions', CONCAT(airfoil_id, '#', version_id), airfoil_id, CONCAT('version ', version_id), 0, 0, 'INSERT'
        FROM data_versions
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
        SELECT 'coordinate_points', CONCAT(airfoil_id, '#', version_id, '#', point_order), airfoil_id, CONCAT('version ', version_id), 0, 0, 'INSERT'
        FROM coordinate_points
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
        SELECT 'performance_records', CAST(perf_id AS CHAR), airfoil_id, CONCAT('version ', version_id), 0, 0, 'INSERT'
        FROM performance_records
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
        SELECT 'anomaly_records', CAST(anomaly_id AS CHAR), airfoil_id, CONCAT('version ', version_id), 0, 0, 'INSERT'
        FROM anomaly_records
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
    ]:
        execute_write(sql)
    _LINEAGE_SCHEMA_READY = True


def sync_lineage_records() -> None:
    for sql in [
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
        SELECT 'data_sources', source_type, NULL, 'source', 0, 0, 'INSERT'
        FROM data_sources
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
        SELECT 'airfoils', airfoil_id, airfoil_id, 'master', 0, 0, 'INSERT'
        FROM airfoils
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
        SELECT 'data_versions', CONCAT(airfoil_id, '#', version_id), airfoil_id, CONCAT('version ', version_id), 0, 0, 'INSERT'
        FROM data_versions
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
        SELECT 'coordinate_points', CONCAT(airfoil_id, '#', version_id, '#', point_order), airfoil_id, CONCAT('version ', version_id), 0, 0, 'INSERT'
        FROM coordinate_points
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
        SELECT 'performance_records', CAST(perf_id AS CHAR), airfoil_id, CONCAT('version ', version_id), 0, 0, 'INSERT'
        FROM performance_records
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
        SELECT 'anomaly_records', CAST(anomaly_id AS CHAR), airfoil_id, CONCAT('version ', version_id), 0, 0, 'INSERT'
        FROM anomaly_records
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
    ]:
        execute_write(sql)


def ensure_import_schema() -> None:
    global _IMPORT_SCHEMA_READY
    if _IMPORT_SCHEMA_READY:
        return
    execute_write(
        """
        CREATE TABLE IF NOT EXISTS data_import_records (
            import_id INT AUTO_INCREMENT PRIMARY KEY,
            target_table VARCHAR(64) NOT NULL,
            record_pk VARCHAR(191) NOT NULL,
            airfoil_id VARCHAR(64) NULL,
            version_id INT NULL,
            source_type VARCHAR(64) NULL,
            entry_method VARCHAR(32) NOT NULL,
            created_by_user_id INT NULL,
            created_by_username VARCHAR(64) NULL,
            description TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_data_import_record_method (target_table, record_pk, entry_method),
            INDEX idx_data_import_target (target_table),
            INDEX idx_data_import_airfoil (airfoil_id),
            INDEX idx_data_import_user (created_by_user_id),
            CHECK (entry_method IN ('system', 'frontend', 'sql'))
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )
    import_columns = {
        row["column_name"]
        for row in query_all(
            """
            SELECT COLUMN_NAME AS column_name
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'data_import_records'
            """
        )
    }
    if "previous_record_version_id" not in import_columns:
        execute_write("ALTER TABLE data_import_records ADD COLUMN previous_record_version_id INT NULL AFTER description")
    if "record_version_id" not in import_columns:
        execute_write("ALTER TABLE data_import_records ADD COLUMN record_version_id INT NOT NULL DEFAULT 0 AFTER previous_record_version_id")
    else:
        execute_write("ALTER TABLE data_import_records MODIFY COLUMN record_version_id INT NOT NULL DEFAULT 0")
    for sql in [
        """
        INSERT INTO data_import_records
            (target_table, record_pk, source_type, entry_method, created_by_username, description)
        SELECT 'data_sources', source_type, source_type, 'system', 'system', description
        FROM data_sources
        ON DUPLICATE KEY UPDATE target_table = VALUES(target_table)
        """,
        """
        INSERT INTO data_import_records
            (target_table, record_pk, airfoil_id, source_type, entry_method, created_by_username, description)
        SELECT 'airfoils', airfoil_id, airfoil_id, source_type, 'system', 'system', CONCAT(name, ' / ', source_file)
        FROM airfoils
        ON DUPLICATE KEY UPDATE target_table = VALUES(target_table)
        """,
        """
        INSERT INTO data_import_records
            (target_table, record_pk, airfoil_id, version_id, entry_method, created_by_username, description)
        SELECT 'data_versions', CONCAT(airfoil_id, '#', version_id), airfoil_id, version_id, 'system', 'system', description
        FROM data_versions
        ON DUPLICATE KEY UPDATE target_table = VALUES(target_table)
        """,
    ]:
        execute_write(sql)
    _IMPORT_SCHEMA_READY = True


def ensure_audit_schema() -> None:
    global _AUDIT_SCHEMA_READY
    if _AUDIT_SCHEMA_READY:
        return
    audit_columns = {
        row["column_name"]
        for row in query_all(
            """
            SELECT COLUMN_NAME AS column_name
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'audit_logs'
            """
        )
    }
    if "previous_record_version_id" not in audit_columns:
        execute_write("ALTER TABLE audit_logs ADD COLUMN previous_record_version_id INT NULL AFTER record_pk")
    if "record_version_id" not in audit_columns:
        execute_write("ALTER TABLE audit_logs ADD COLUMN record_version_id INT NOT NULL DEFAULT 0 AFTER previous_record_version_id")
    else:
        execute_write("ALTER TABLE audit_logs MODIFY COLUMN record_version_id INT NOT NULL DEFAULT 0")
    _AUDIT_SCHEMA_READY = True


def ensure_airfoil_schema() -> None:
    global _AIRFOIL_SCHEMA_READY
    if _AIRFOIL_SCHEMA_READY:
        return
    indexes = query_all(
        """
        SELECT INDEX_NAME AS index_name,
               GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS columns,
               MIN(NON_UNIQUE) AS non_unique
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = 'airfoils'
        GROUP BY INDEX_NAME
        """
    )
    for row in indexes:
        columns = str(row.get("columns") or "")
        if row.get("index_name") == "uq_airfoils_source_file" and columns == "source_file" and int(row.get("non_unique") or 1) == 0:
            execute_write("ALTER TABLE airfoils DROP INDEX uq_airfoils_source_file")
    refreshed = query_all(
        """
        SELECT INDEX_NAME AS index_name,
               GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS columns,
               MIN(NON_UNIQUE) AS non_unique
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = 'airfoils'
        GROUP BY INDEX_NAME
        """
    )
    if not any(row.get("index_name") == "uq_airfoils_id_source_file" for row in refreshed):
        execute_write("ALTER TABLE airfoils ADD UNIQUE KEY uq_airfoils_id_source_file (airfoil_id, source_file)")
    _AIRFOIL_SCHEMA_READY = True


def sync_import_records() -> None:
    for sql in [
        """
        INSERT INTO data_import_records
            (target_table, record_pk, source_type, entry_method, created_by_username, description)
        SELECT 'data_sources', source_type, source_type, 'system', 'system', description
        FROM data_sources
        ON DUPLICATE KEY UPDATE target_table = VALUES(target_table)
        """,
        """
        INSERT INTO data_import_records
            (target_table, record_pk, airfoil_id, source_type, entry_method, created_by_username, description)
        SELECT 'airfoils', airfoil_id, airfoil_id, source_type, 'system', 'system', CONCAT(name, ' / ', source_file)
        FROM airfoils
        ON DUPLICATE KEY UPDATE target_table = VALUES(target_table)
        """,
        """
        INSERT INTO data_import_records
            (target_table, record_pk, airfoil_id, version_id, entry_method, created_by_username, description)
        SELECT 'data_versions', CONCAT(airfoil_id, '#', version_id), airfoil_id, version_id, 'system', 'system', description
        FROM data_versions
        ON DUPLICATE KEY UPDATE target_table = VALUES(target_table)
        """,
        """
        INSERT INTO data_import_records
            (target_table, record_pk, airfoil_id, version_id, entry_method, created_by_username, description)
        SELECT 'coordinate_points', CONCAT(airfoil_id, '#', version_id, '#', point_order), airfoil_id, version_id,
               'system', 'system', CONCAT('point_order=', point_order, '; point_source=', point_source)
        FROM coordinate_points
        ON DUPLICATE KEY UPDATE target_table = VALUES(target_table)
        """,
        """
        INSERT INTO data_import_records
            (target_table, record_pk, airfoil_id, version_id, source_type, entry_method, created_by_username, description)
        SELECT 'performance_records', CAST(perf_id AS CHAR), airfoil_id, version_id, source_type,
               'system', 'system', CONCAT('alpha=', alpha_deg, '; Re=', reynolds_number)
        FROM performance_records
        ON DUPLICATE KEY UPDATE target_table = VALUES(target_table)
        """,
        """
        INSERT INTO data_import_records
            (target_table, record_pk, airfoil_id, version_id, entry_method, created_by_username, description)
        SELECT 'anomaly_records', CAST(anomaly_id AS CHAR), airfoil_id, version_id,
               'system', 'system', CONCAT('perf_id=', perf_id, '; rule=', rule_type)
        FROM anomaly_records
        ON DUPLICATE KEY UPDATE target_table = VALUES(target_table)
        """,
    ]:
        execute_write(sql)
    execute_write(
        """
        DELETE system_rows
        FROM data_import_records AS system_rows
        JOIN (
            SELECT target_table, record_pk
            FROM (
                SELECT DISTINCT target_table, record_pk
                FROM data_import_records
                WHERE entry_method <> 'system'
            ) AS user_row_keys
        ) AS user_rows
          ON user_rows.target_table = system_rows.target_table
         AND user_rows.record_pk = system_rows.record_pk
        WHERE system_rows.entry_method = 'system'
        """
    )


SOFT_DELETE_TARGET_TABLES = {
    "data_sources",
    "airfoils",
    "data_versions",
    "coordinate_points",
    "performance_records",
    "anomaly_records",
}

BATCH_IMPORT_COLUMNS = {
    "data_sources": ["source_type", "description"],
    "airfoils": [
        "airfoil_id",
        "name",
        "source",
        "family",
        "is_generated",
        "source_type",
        "source_file",
        "has_augmented_coordinates",
        "original_point_count",
        "final_point_count",
    ],
    "data_versions": ["airfoil_id", "version_id", "version_type", "coordinate_source_type", "description"],
    "coordinate_points": [
        "airfoil_id",
        "version_id",
        "point_order",
        "x",
        "y",
        "surface",
        "point_source",
        "is_augmented",
        "original_order",
        "augmentation_method",
    ],
    "performance_records": [
        "perf_id",
        "airfoil_id",
        "version_id",
        "alpha_deg",
        "reynolds_number",
        "cl",
        "cd",
        "cm",
        "source_type",
        "is_anomaly",
    ],
}

BATCH_IMPORT_INT_COLUMNS = {
    "is_generated",
    "has_augmented_coordinates",
    "original_point_count",
    "final_point_count",
    "version_id",
    "point_order",
    "is_augmented",
    "original_order",
    "perf_id",
    "reynolds_number",
    "is_anomaly",
}

BATCH_IMPORT_FLOAT_COLUMNS = {"x", "y", "alpha_deg", "cl", "cd", "cm"}
MAX_BATCH_IMPORT_ROWS = 10000



def ensure_core_trigger_schema() -> None:
    global _CORE_TRIGGER_SCHEMA_READY
    if _CORE_TRIGGER_SCHEMA_READY:
        return
    trigger_sql = [
        "DROP TRIGGER IF EXISTS trg_lineage_airfoils_insert",
        "DROP TRIGGER IF EXISTS trg_lineage_airfoils_update",
        "DROP TRIGGER IF EXISTS trg_lineage_data_versions_insert",
        "DROP TRIGGER IF EXISTS trg_lineage_data_versions_update",
        "DROP TRIGGER IF EXISTS trg_lineage_coordinates_insert",
        "DROP TRIGGER IF EXISTS trg_lineage_coordinates_update",
        """
        CREATE TRIGGER trg_lineage_airfoils_insert
        AFTER INSERT ON airfoils
        FOR EACH ROW
        BEGIN
            INSERT INTO data_record_lineage
                (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
            VALUES
                ('airfoils', NEW.airfoil_id, NEW.airfoil_id, 'master', 0, 0, 'INSERT')
            ON DUPLICATE KEY UPDATE
                airfoil_id = NEW.airfoil_id,
                source_version = 'master',
                last_operation = IF(is_modified = 1, last_operation, 'INSERT');
        END
        """,
        """
        CREATE TRIGGER trg_lineage_airfoils_update
        AFTER UPDATE ON airfoils
        FOR EACH ROW
        BEGIN
            INSERT INTO data_record_lineage
                (table_name, record_pk, airfoil_id, source_version, record_version_id, previous_record_version_id,
                 is_modified, last_modified_at, modified_count, last_operation)
            VALUES
                ('airfoils', NEW.airfoil_id, NEW.airfoil_id, 'master', 1, 0, 1, CURRENT_TIMESTAMP, 1, 'UPDATE')
            ON DUPLICATE KEY UPDATE
                airfoil_id = NEW.airfoil_id,
                source_version = 'master',
                previous_record_version_id = record_version_id,
                record_version_id = record_version_id + 1,
                is_modified = 1,
                last_modified_at = CURRENT_TIMESTAMP,
                modified_count = modified_count + 1,
                last_operation = 'UPDATE';
        END
        """,
        """
        CREATE TRIGGER trg_lineage_data_versions_insert
        AFTER INSERT ON data_versions
        FOR EACH ROW
        BEGIN
            INSERT INTO data_record_lineage
                (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
            VALUES
                ('data_versions', CONCAT(NEW.airfoil_id, '#', NEW.version_id), NEW.airfoil_id, CONCAT('version ', NEW.version_id), 0, 0, 'INSERT')
            ON DUPLICATE KEY UPDATE
                airfoil_id = NEW.airfoil_id,
                source_version = CONCAT('version ', NEW.version_id),
                last_operation = IF(is_modified = 1, last_operation, 'INSERT');
        END
        """,
        """
        CREATE TRIGGER trg_lineage_data_versions_update
        AFTER UPDATE ON data_versions
        FOR EACH ROW
        BEGIN
            INSERT INTO data_record_lineage
                (table_name, record_pk, airfoil_id, source_version, record_version_id, previous_record_version_id,
                 is_modified, last_modified_at, modified_count, last_operation)
            VALUES
                ('data_versions', CONCAT(NEW.airfoil_id, '#', NEW.version_id), NEW.airfoil_id, CONCAT('version ', NEW.version_id),
                 1, 0, 1, CURRENT_TIMESTAMP, 1, 'UPDATE')
            ON DUPLICATE KEY UPDATE
                airfoil_id = NEW.airfoil_id,
                source_version = CONCAT('version ', NEW.version_id),
                previous_record_version_id = record_version_id,
                record_version_id = record_version_id + 1,
                is_modified = 1,
                last_modified_at = CURRENT_TIMESTAMP,
                modified_count = modified_count + 1,
                last_operation = 'UPDATE';
        END
        """,
        """
        CREATE TRIGGER trg_lineage_coordinates_insert
        AFTER INSERT ON coordinate_points
        FOR EACH ROW
        BEGIN
            INSERT INTO data_record_lineage
                (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
            VALUES
                ('coordinate_points', CONCAT(NEW.airfoil_id, '#', NEW.version_id, '#', NEW.point_order), NEW.airfoil_id,
                 CONCAT('version ', NEW.version_id), 0, 0, 'INSERT')
            ON DUPLICATE KEY UPDATE
                airfoil_id = NEW.airfoil_id,
                source_version = CONCAT('version ', NEW.version_id),
                last_operation = IF(is_modified = 1, last_operation, 'INSERT');
        END
        """,
        """
        CREATE TRIGGER trg_lineage_coordinates_update
        AFTER UPDATE ON coordinate_points
        FOR EACH ROW
        BEGIN
            INSERT INTO data_record_lineage
                (table_name, record_pk, airfoil_id, source_version, record_version_id, previous_record_version_id,
                 is_modified, last_modified_at, modified_count, last_operation)
            VALUES
                ('coordinate_points', CONCAT(NEW.airfoil_id, '#', NEW.version_id, '#', NEW.point_order), NEW.airfoil_id,
                 CONCAT('version ', NEW.version_id), 1, 0, 1, CURRENT_TIMESTAMP, 1, 'UPDATE')
            ON DUPLICATE KEY UPDATE
                airfoil_id = NEW.airfoil_id,
                source_version = CONCAT('version ', NEW.version_id),
                previous_record_version_id = record_version_id,
                record_version_id = record_version_id + 1,
                is_modified = 1,
                last_modified_at = CURRENT_TIMESTAMP,
                modified_count = modified_count + 1,
                last_operation = 'UPDATE';
        END
        """,
    ]
    for sql in trigger_sql:
        execute_write(sql)
    _CORE_TRIGGER_SCHEMA_READY = True


def ensure_stored_procedure_schema() -> None:
    global _STORED_PROCEDURE_SCHEMA_READY
    if _STORED_PROCEDURE_SCHEMA_READY:
        return
    try:
        from import_mysql import STORED_PROCEDURES_SQL
    except ModuleNotFoundError:
        from backend.import_mysql import STORED_PROCEDURES_SQL

    for name in [
        "sp_airfoil_performance_summary",
        "sp_compare_airfoils_by_re",
        "sp_validate_performance_import_batch",
        "sp_import_performance_batch",
    ]:
        execute_write(f"DROP PROCEDURE IF EXISTS {name}")
    for sql in STORED_PROCEDURES_SQL:
        execute_write(sql)
    _STORED_PROCEDURE_SCHEMA_READY = True


def ensure_anomaly_trigger_schema() -> None:
    global _ANOMALY_TRIGGER_SCHEMA_READY
    if _ANOMALY_TRIGGER_SCHEMA_READY:
        return
    trigger_sql = [
        "DROP TRIGGER IF EXISTS trg_anomaly_requires_flag_insert",
        "DROP TRIGGER IF EXISTS trg_anomaly_requires_flag_update",
        "DROP TRIGGER IF EXISTS trg_lineage_anomalies_insert",
        "DROP TRIGGER IF EXISTS trg_lineage_anomalies_update",
        """
        CREATE TRIGGER trg_anomaly_requires_flag_insert
        BEFORE INSERT ON anomaly_records
        FOR EACH ROW
        BEGIN
            IF (
                SELECT is_anomaly
                FROM performance_records
                WHERE perf_id = NEW.perf_id
                  AND airfoil_id = NEW.airfoil_id
                  AND version_id = NEW.version_id
            ) <> 1 THEN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'anomaly_records can only reference performance_records with is_anomaly = 1';
            END IF;
        END
        """,
        """
        CREATE TRIGGER trg_anomaly_requires_flag_update
        BEFORE UPDATE ON anomaly_records
        FOR EACH ROW
        BEGIN
            IF (
                SELECT is_anomaly
                FROM performance_records
                WHERE perf_id = NEW.perf_id
                  AND airfoil_id = NEW.airfoil_id
                  AND version_id = NEW.version_id
            ) <> 1 THEN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'anomaly_records can only reference performance_records with is_anomaly = 1';
            END IF;
        END
        """,
        """
        CREATE TRIGGER trg_lineage_anomalies_insert
        AFTER INSERT ON anomaly_records
        FOR EACH ROW
        BEGIN
            INSERT INTO data_record_lineage
                (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
            VALUES
                ('anomaly_records', CAST(NEW.anomaly_id AS CHAR), NEW.airfoil_id, CONCAT('version ', NEW.version_id), 0, 0, 'INSERT')
            ON DUPLICATE KEY UPDATE
                airfoil_id = NEW.airfoil_id,
                source_version = CONCAT('version ', NEW.version_id),
                last_operation = 'INSERT';
        END
        """,
        """
        CREATE TRIGGER trg_lineage_anomalies_update
        AFTER UPDATE ON anomaly_records
        FOR EACH ROW
        BEGIN
            INSERT INTO data_record_lineage
                (table_name, record_pk, airfoil_id, source_version, record_version_id, previous_record_version_id, is_modified, last_modified_at, modified_count, last_operation)
            VALUES
                ('anomaly_records', CAST(NEW.anomaly_id AS CHAR), NEW.airfoil_id, CONCAT('version ', NEW.version_id), 1, 0, 1, CURRENT_TIMESTAMP, 1, 'UPDATE')
            ON DUPLICATE KEY UPDATE
                airfoil_id = NEW.airfoil_id,
                source_version = CONCAT('version ', NEW.version_id),
                previous_record_version_id = record_version_id,
                record_version_id = record_version_id + 1,
                is_modified = 1,
                last_modified_at = CURRENT_TIMESTAMP,
                modified_count = modified_count + 1,
                last_operation = 'UPDATE';
        END
        """,
    ]
    for sql in trigger_sql:
        execute_write(sql)
    _ANOMALY_TRIGGER_SCHEMA_READY = True


def ensure_performance_trigger_schema() -> None:
    global _PERFORMANCE_TRIGGER_SCHEMA_READY
    if _PERFORMANCE_TRIGGER_SCHEMA_READY:
        return
    trigger_sql = [
        "DROP TRIGGER IF EXISTS trg_lineage_performance_insert",
        "DROP TRIGGER IF EXISTS trg_lineage_performance_update",
        "DROP TRIGGER IF EXISTS trg_audit_performance_update",
        """
        CREATE TRIGGER trg_lineage_performance_insert
        AFTER INSERT ON performance_records
        FOR EACH ROW
        BEGIN
            INSERT INTO data_record_lineage
                (table_name, record_pk, airfoil_id, source_version, record_version_id, is_modified, last_operation)
            VALUES
                ('performance_records', CAST(NEW.perf_id AS CHAR), NEW.airfoil_id, CONCAT('version ', NEW.version_id), 0, 0, 'INSERT')
            ON DUPLICATE KEY UPDATE
                airfoil_id = NEW.airfoil_id,
                source_version = CONCAT('version ', NEW.version_id),
                last_operation = IF(is_modified = 1, last_operation, 'INSERT');
        END
        """,
        """
        CREATE TRIGGER trg_lineage_performance_update
        AFTER UPDATE ON performance_records
        FOR EACH ROW
        BEGIN
            INSERT INTO data_record_lineage
                (table_name, record_pk, airfoil_id, source_version, record_version_id, previous_record_version_id,
                 is_modified, last_modified_at, modified_count, last_operation)
            VALUES
                ('performance_records', CAST(NEW.perf_id AS CHAR), NEW.airfoil_id, CONCAT('version ', NEW.version_id),
                 1, 0, 1, CURRENT_TIMESTAMP, 1, 'UPDATE')
            ON DUPLICATE KEY UPDATE
                airfoil_id = NEW.airfoil_id,
                source_version = CONCAT('version ', NEW.version_id),
                previous_record_version_id = record_version_id,
                record_version_id = record_version_id + 1,
                is_modified = 1,
                last_modified_at = CURRENT_TIMESTAMP,
                modified_count = modified_count + 1,
                last_operation = 'UPDATE';
        END
        """,
        """
        CREATE TRIGGER trg_audit_performance_update
        AFTER UPDATE ON performance_records
        FOR EACH ROW
        FOLLOWS trg_lineage_performance_update
        BEGIN
            INSERT INTO audit_logs
                (table_name, operation_type, record_pk, previous_record_version_id, record_version_id, old_values, new_values)
            VALUES
                (
                    'performance_records',
                    'UPDATE',
                    CAST(OLD.perf_id AS CHAR),
                    COALESCE(
                        (
                            SELECT previous_record_version_id
                            FROM data_record_lineage
                            WHERE table_name = 'performance_records'
                              AND record_pk = CAST(OLD.perf_id AS CHAR)
                            LIMIT 1
                        ),
                        0
                    ),
                    COALESCE(
                        (
                            SELECT record_version_id
                            FROM data_record_lineage
                            WHERE table_name = 'performance_records'
                              AND record_pk = CAST(OLD.perf_id AS CHAR)
                            LIMIT 1
                        ),
                        1
                    ),
                    JSON_OBJECT(
                        'cl', OLD.cl,
                        'cd', OLD.cd,
                        'cm', OLD.cm,
                        'is_anomaly', OLD.is_anomaly
                    ),
                    JSON_OBJECT(
                        'cl', NEW.cl,
                        'cd', NEW.cd,
                        'cm', NEW.cm,
                        'is_anomaly', NEW.is_anomaly
                    )
                );
        END
        """,
    ]
    for sql in trigger_sql:
        execute_write(sql)
    _PERFORMANCE_TRIGGER_SCHEMA_READY = True


def ensure_soft_delete_schema() -> None:
    global _SOFT_DELETE_SCHEMA_READY
    if _SOFT_DELETE_SCHEMA_READY:
        return
    execute_write(
        """
        CREATE TABLE IF NOT EXISTS soft_delete_records (
            delete_id INT AUTO_INCREMENT PRIMARY KEY,
            table_name VARCHAR(64) NOT NULL,
            record_pk VARCHAR(191) NOT NULL,
            record_version_id INT NOT NULL DEFAULT 0,
            airfoil_id VARCHAR(64) NULL,
            version_id INT NULL,
            row_snapshot JSON NOT NULL,
            delete_reason TEXT NULL,
            deleted_by_user_id INT NULL,
            deleted_by_username VARCHAR(64) NULL,
            deleted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            restored_by_user_id INT NULL,
            restored_by_username VARCHAR(64) NULL,
            restored_at TIMESTAMP NULL,
            is_active TINYINT NOT NULL DEFAULT 1,
            INDEX idx_soft_delete_record (table_name, record_pk, is_active),
            INDEX idx_soft_delete_table (table_name),
            INDEX idx_soft_delete_airfoil (airfoil_id),
            INDEX idx_soft_delete_user (deleted_by_user_id),
            CHECK (is_active IN (0, 1))
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )
    existing_columns = {
        row["column_name"]
        for row in query_all(
            """
            SELECT COLUMN_NAME AS column_name
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'soft_delete_records'
            """
        )
    }
    if "record_version_id" not in existing_columns:
        execute_write("ALTER TABLE soft_delete_records ADD COLUMN record_version_id INT NOT NULL DEFAULT 0 AFTER record_pk")
    else:
        execute_write("ALTER TABLE soft_delete_records MODIFY COLUMN record_version_id INT NOT NULL DEFAULT 0")
    if "restored_by_user_id" not in existing_columns:
        execute_write("ALTER TABLE soft_delete_records ADD COLUMN restored_by_user_id INT NULL AFTER deleted_at")
    if "restored_by_username" not in existing_columns:
        execute_write("ALTER TABLE soft_delete_records ADD COLUMN restored_by_username VARCHAR(64) NULL AFTER restored_by_user_id")
    if "restored_at" not in existing_columns:
        execute_write("ALTER TABLE soft_delete_records ADD COLUMN restored_at TIMESTAMP NULL AFTER restored_by_username")
    existing_indexes = query_all(
        """
        SELECT INDEX_NAME AS index_name, NON_UNIQUE AS non_unique
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = 'soft_delete_records'
        GROUP BY INDEX_NAME, NON_UNIQUE
        """
    )
    if any(row["index_name"] == "uq_soft_delete_active_record" and int(row["non_unique"]) == 0 for row in existing_indexes):
        execute_write("ALTER TABLE soft_delete_records DROP INDEX uq_soft_delete_active_record")
    refreshed_indexes = query_all(
        """
        SELECT INDEX_NAME AS index_name
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = 'soft_delete_records'
          AND INDEX_NAME = 'idx_soft_delete_record'
        LIMIT 1
        """
    )
    if not refreshed_indexes:
        execute_write("ALTER TABLE soft_delete_records ADD INDEX idx_soft_delete_record (table_name, record_pk, is_active)")
    _SOFT_DELETE_SCHEMA_READY = True


def record_pk_sql(table_name: str, qualifier: str | None = None) -> str:
    prefix = f"`{qualifier}`." if qualifier else ""
    if table_name == "data_sources":
        return f"{prefix}`source_type`"
    if table_name == "airfoils":
        return f"{prefix}`airfoil_id`"
    if table_name == "data_versions":
        return f"CONCAT({prefix}`airfoil_id`, '#', {prefix}`version_id`)"
    if table_name == "coordinate_points":
        return f"CONCAT({prefix}`airfoil_id`, '#', {prefix}`version_id`, '#', {prefix}`point_order`)"
    if table_name == "performance_records":
        return f"CAST({prefix}`perf_id` AS CHAR)"
    if table_name == "anomaly_records":
        return f"CAST({prefix}`anomaly_id` AS CHAR)"
    raise ValueError(f"soft delete is not configured for {table_name}")


def record_pk_from_row(table_name: str, row: dict[str, Any]) -> str:
    if table_name == "data_sources":
        return str(row["source_type"])
    if table_name == "airfoils":
        return str(row["airfoil_id"])
    if table_name == "data_versions":
        return f"{row['airfoil_id']}#{row['version_id']}"
    if table_name == "coordinate_points":
        return f"{row['airfoil_id']}#{row['version_id']}#{row['point_order']}"
    if table_name == "performance_records":
        return str(row["perf_id"])
    if table_name == "anomaly_records":
        return str(row["anomaly_id"])
    raise ValueError(f"soft delete is not configured for {table_name}")


def row_identity_where(table_name: str, row: dict[str, Any]) -> tuple[str, tuple[Any, ...]]:
    if table_name == "data_sources":
        return "`source_type` = %s", (row.get("source_type"),)
    if table_name == "airfoils":
        return "`airfoil_id` = %s", (row.get("airfoil_id"),)
    if table_name == "data_versions":
        return "`airfoil_id` = %s AND `version_id` = %s", (row.get("airfoil_id"), row.get("version_id"))
    if table_name == "coordinate_points":
        return "`airfoil_id` = %s AND `version_id` = %s AND `point_order` = %s", (row.get("airfoil_id"), row.get("version_id"), row.get("point_order"))
    if table_name == "performance_records":
        return "`perf_id` = %s", (row.get("perf_id"),)
    if table_name == "anomaly_records":
        return "`anomaly_id` = %s", (row.get("anomaly_id"),)
    raise ValueError(f"soft delete is not configured for {table_name}")


def soft_delete_filter_sql(table_name: str, qualifier: str | None = None) -> str:
    if table_name not in SOFT_DELETE_TARGET_TABLES:
        return "1 = 1"
    outer_qualifier = qualifier or table_name
    return (
        "NOT EXISTS ("
        "SELECT 1 FROM soft_delete_records sd "
        f"WHERE sd.table_name = '{table_name}' "
        f"AND sd.record_pk = {record_pk_sql(table_name, outer_qualifier)} "
        "AND sd.is_active = 1)"
    )


@app.before_request
def before_request() -> None:
    ensure_auth_schema()
    ensure_saved_transaction_schema()
    ensure_lineage_schema()
    ensure_import_schema()
    ensure_audit_schema()
    ensure_airfoil_schema()
    ensure_soft_delete_schema()
    ensure_core_trigger_schema()
    ensure_performance_trigger_schema()
    ensure_anomaly_trigger_schema()
    ensure_stored_procedure_schema()


def current_user() -> dict[str, Any] | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    if session.get("username") and session.get("role"):
        return {
            "user_id": int(user_id),
            "username": session["username"],
            "role": session["role"],
            "is_active": 1,
            "created_at": session.get("created_at"),
        }
    rows = query_all(
        """
        SELECT user_id, username, role, is_active, created_at
        FROM users
        WHERE user_id = %s AND is_active = 1
        """,
        (user_id,),
    )
    if not rows:
        session.clear()
        return None
    session["username"] = rows[0]["username"]
    session["role"] = rows[0]["role"]
    session["created_at"] = str(rows[0].get("created_at", ""))
    return rows[0]


def current_role() -> str | None:
    user = current_user()
    return user["role"] if user else None


def is_manager(role: str | None) -> bool:
    return role in {"engineer", "admin"}


def is_analyst_or_manager(role: str | None) -> bool:
    return role in {"analyst", "engineer", "admin"}


def is_admin(role: str | None) -> bool:
    return role == "admin"


def valid_username(username: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_\u4e00-\u9fa5]{2,32}", username))


def is_safe_select(sql: str) -> bool:
    stripped = sql.strip()
    if not stripped or ";" in stripped.rstrip(";"):
        return False
    normalized = stripped.rstrip(";").lstrip().lower()
    return normalized.startswith("select") or normalized.startswith("explain select")


def is_allowed_editor_sql(sql: str) -> bool:
    stripped = sql.strip()
    if not stripped or ";" in stripped.rstrip(";"):
        return False
    normalized = re.sub(r"\s+", " ", stripped.rstrip(";").lstrip().lower())
    forbidden = (
        "drop database",
        "drop table",
        "truncate",
        "alter user",
        "create user",
        "grant ",
        "revoke ",
        "shutdown",
        "load_file",
        "into outfile",
        "set password",
    )
    if any(token in normalized for token in forbidden):
        return False
    return normalized.startswith(
        (
            "select ",
            "explain select ",
            "insert ",
            "update ",
            "delete ",
            "create index ",
            "drop index ",
            "call ",
        )
    )


def split_sql_statements(sql_text: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for char in sql_text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and quote:
            current.append(char)
            escaped = True
            continue
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
            current.append(char)
            continue
        if char == ";":
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current = []
            continue
        current.append(char)
    tail = "".join(current).strip()
    if tail:
        statements.append(tail)
    return statements


def is_allowed_transaction_sql(sql: str) -> bool:
    normalized = re.sub(r"\s+", " ", sql.strip().lower())
    forbidden = (
        "create ",
        "drop ",
        "alter ",
        "truncate",
        "grant ",
        "revoke ",
        "start transaction",
        "begin",
        "commit",
        "rollback",
        "lock ",
        "unlock ",
        "load_file",
        "into outfile",
        " users",
        " query_logs",
    )
    if any(token in f" {normalized}" for token in forbidden):
        return False
    return normalized.startswith(("select ", "insert ", "update ", "delete "))


INDEX_ALLOWED_TABLES = {
    "airfoils",
    "data_versions",
    "coordinate_points",
    "performance_records",
    "anomaly_records",
    "data_sources",
    "users",
    "query_logs",
}


ADMIN_VIEW_TABLES = {
    "data_sources",
    "airfoils",
    "data_versions",
    "coordinate_points",
    "performance_records",
    "anomaly_records",
    "audit_logs",
    "data_record_lineage",
    "data_import_records",
    "soft_delete_records",
    "performance_import_staging",
    "saved_transactions",
    "v_airfoil_overview",
    "v_performance_with_ld",
    "v_anomaly_details",
}

MAIN_TABLE_KEY_FILTERS = {
    "data_sources": ["source_type"],
    "airfoils": ["airfoil_id"],
    "data_versions": ["airfoil_id", "version_id"],
    "coordinate_points": ["airfoil_id", "version_id", "point_order"],
    "performance_records": ["perf_id", "airfoil_id", "version_id"],
    "anomaly_records": ["anomaly_id", "perf_id", "airfoil_id", "version_id"],
    "audit_logs": ["audit_id", "table_name", "record_pk", "previous_record_version_id", "record_version_id"],
    "data_record_lineage": ["lineage_id", "table_name", "record_pk", "airfoil_id", "previous_record_version_id", "record_version_id"],
    "data_import_records": ["import_id", "target_table", "record_pk", "airfoil_id", "previous_record_version_id", "record_version_id"],
    "soft_delete_records": ["delete_id", "table_name", "record_pk", "airfoil_id"],
    "performance_import_staging": ["staging_id", "batch_id", "perf_id"],
    "saved_transactions": ["saved_id", "user_id"],
    "v_airfoil_overview": ["airfoil_id"],
    "v_performance_with_ld": ["perf_id", "airfoil_id", "version_id"],
    "v_anomaly_details": ["anomaly_id", "perf_id", "airfoil_id", "version_id"],
}


def valid_identifier(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", value))


def table_columns(table_name: str) -> list[str]:
    if table_name not in INDEX_ALLOWED_TABLES:
        return []
    rows = query_all(
        """
        SELECT COLUMN_NAME AS column_name
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = %s
        ORDER BY ordinal_position
        """,
        (table_name,),
    )
    return [row.get("column_name") or row.get("COLUMN_NAME") for row in rows]


@app.get("/")
def index() -> str:
    return render_template_string(INDEX_HTML)


@app.get("/api/summary")
def summary() -> Any:
    tables = [
        "data_sources",
        "airfoils",
        "data_versions",
        "coordinate_points",
        "performance_records",
        "anomaly_records",
    ]
    return jsonify(
        {
            table: query_all(
                f"SELECT COUNT(*) AS count FROM {table} WHERE {soft_delete_filter_sql(table)}"
            )[0]["count"]
            for table in tables
        }
    )


@app.get("/api/airfoils")
def airfoils() -> Any:
    rows = query_all(
        f"""
        SELECT
            a.airfoil_id,
            a.name,
            a.family,
            a.source_type,
            a.original_point_count,
            a.final_point_count,
            a.has_augmented_coordinates,
            COUNT(DISTINCT p.perf_id) AS performance_count,
            COUNT(DISTINCT ar.anomaly_id) AS anomaly_count
        FROM airfoils a
        LEFT JOIN performance_records p ON p.airfoil_id = a.airfoil_id
            AND {soft_delete_filter_sql("performance_records", "p")}
        LEFT JOIN anomaly_records ar ON ar.perf_id = p.perf_id
            AND {soft_delete_filter_sql("anomaly_records", "ar")}
        WHERE {soft_delete_filter_sql("airfoils", "a")}
        GROUP BY
            a.airfoil_id, a.name, a.family, a.source_type,
            a.original_point_count, a.final_point_count, a.has_augmented_coordinates
        ORDER BY a.airfoil_id
        """
    )
    return jsonify(rows)


@app.get("/api/airfoils/<airfoil_id>")
def airfoil_detail(airfoil_id: str) -> Any:
    rows = query_all(
        f"""
        SELECT airfoil_id, name, source, family, is_generated, source_type, source_file,
               has_augmented_coordinates, original_point_count, final_point_count
        FROM airfoils
        WHERE airfoil_id = %s AND {soft_delete_filter_sql("airfoils")}
        """,
        (airfoil_id,),
    )
    if not rows:
        return jsonify({"error": "airfoil not found"}), 404
    versions = query_all(
        f"""
        SELECT airfoil_id, version_id, version_type, coordinate_source_type, description
        FROM data_versions
        WHERE airfoil_id = %s AND {soft_delete_filter_sql("data_versions")}
        ORDER BY version_id
        """,
        (airfoil_id,),
    )
    return jsonify({"airfoil": rows[0], "versions": versions})


@app.get("/api/coordinates")
def coordinates() -> Any:
    rows = query_all(
        f"""
        SELECT point_order, x, y, surface, point_source, is_augmented
        FROM coordinate_points
        WHERE airfoil_id = %s AND version_id = %s AND {soft_delete_filter_sql("coordinate_points")}
        ORDER BY point_order
        """,
        (request.args.get("airfoil_id", ""), int(request.args.get("version_id", "1"))),
    )
    return jsonify(rows)


@app.get("/api/performance")
def performance() -> Any:
    airfoil_id = request.args.get("airfoil_id", "")
    version_id = int(request.args.get("version_id", "1"))
    reynolds_number = request.args.get("reynolds_number")
    params: list[Any] = [airfoil_id, version_id]
    where = "airfoil_id = %s AND version_id = %s"
    if reynolds_number:
        where += " AND reynolds_number = %s"
        params.append(int(reynolds_number))

    rows = query_all(
        f"""
        SELECT perf_id, alpha_deg, reynolds_number, cl, cd, cm, is_anomaly
        FROM performance_records
        WHERE {where} AND {soft_delete_filter_sql("performance_records")}
        ORDER BY reynolds_number, alpha_deg
        """,
        tuple(params),
    )
    return jsonify(rows)


@app.get("/api/performance_compare")
def performance_compare() -> Any:
    reynolds_number = int(request.args.get("reynolds_number", "50000"))
    metric = request.args.get("metric", "max_cl")
    limit = min(max(int(request.args.get("limit", "80")), 1), 200)
    metric_sql = {
        "max_cl": "MAX(p.cl)",
        "min_cd": "MIN(p.cd)",
        "max_ld": "MAX(p.cl / NULLIF(p.cd, 0))",
        "avg_cl": "AVG(p.cl)",
    }.get(metric, "MAX(p.cl)")
    order_dir = "ASC" if metric == "min_cd" else "DESC"
    rows = query_all(
        f"""
        SELECT p.airfoil_id, a.name, ROUND({metric_sql}, 6) AS value
        FROM performance_records p
        JOIN airfoils a ON a.airfoil_id = p.airfoil_id
        WHERE p.reynolds_number = %s
          AND {soft_delete_filter_sql("airfoils", "a")}
          AND {soft_delete_filter_sql("performance_records", "p")}
        GROUP BY p.airfoil_id, a.name
        HAVING value IS NOT NULL
        ORDER BY value {order_dir}
        LIMIT %s
        """,
        (reynolds_number, limit),
    )
    return jsonify(rows)


@app.get("/api/condition_search")
def condition_search() -> Any:
    user = current_user()
    if not user or not is_analyst_or_manager(user["role"]):
        return jsonify({"error": "analyst/engineer/admin permission required"}), 403

    start = time.perf_counter()
    where = [
        soft_delete_filter_sql("airfoils", "a"),
        soft_delete_filter_sql("data_versions", "dv"),
        soft_delete_filter_sql("performance_records", "p"),
    ]
    params: list[Any] = []

    reynolds_number = request.args.get("reynolds_number", "").strip()
    alpha_deg = request.args.get("alpha_deg", "").strip()
    cl_min = request.args.get("cl_min", "").strip()
    cl_max = request.args.get("cl_max", "").strip()
    cd_min = request.args.get("cd_min", "").strip()
    cd_max = request.args.get("cd_max", "").strip()
    ld_min = request.args.get("ld_min", "").strip()
    anomaly_only = request.args.get("anomaly_only", "0").strip()
    include_anomaly = request.args.get("include_anomaly", "0").strip()
    limit = request.args.get("limit", "100").strip()

    try:
        row_limit = min(max(int(limit or "100"), 1), 500)
        if reynolds_number:
            where.append("p.reynolds_number = %s")
            params.append(int(reynolds_number))
        if alpha_deg:
            where.append("p.alpha_deg = %s")
            params.append(float(alpha_deg))
        if cl_min:
            where.append("p.cl >= %s")
            params.append(float(cl_min))
        if cl_max:
            where.append("p.cl <= %s")
            params.append(float(cl_max))
        if cd_min:
            where.append("p.cd >= %s")
            params.append(float(cd_min))
        if cd_max:
            where.append("p.cd <= %s")
            params.append(float(cd_max))
        if ld_min:
            where.append("(p.cd <> 0 AND p.cl / p.cd >= %s)")
            params.append(float(ld_min))
    except ValueError:
        return jsonify({"error": "numeric filters must be valid numbers"}), 400

    if anomaly_only == "1":
        where.append("p.is_anomaly = 1")
    elif include_anomaly != "1":
        where.append("p.is_anomaly = 0")

    params.append(row_limit)
    rows = query_all(
        f"""
        SELECT
            p.airfoil_id,
            a.name AS airfoil_name,
            p.version_id,
            dv.version_type,
            dv.coordinate_source_type,
            p.perf_id,
            p.alpha_deg,
            p.reynolds_number,
            p.cl,
            p.cd,
            p.cm,
            ROUND(p.cl / NULLIF(p.cd, 0), 6) AS lift_drag_ratio,
            p.is_anomaly
        FROM performance_records p
        JOIN airfoils a ON a.airfoil_id = p.airfoil_id
        JOIN data_versions dv
          ON dv.airfoil_id = p.airfoil_id
         AND dv.version_id = p.version_id
        WHERE {" AND ".join(where)}
        ORDER BY p.cl DESC, lift_drag_ratio DESC, p.cd ASC, p.airfoil_id, p.version_id
        LIMIT %s
        """,
        tuple(params),
    )
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    log_user_action(
        user["user_id"],
        "condition search for matching airfoils and versions",
        "SELECT performance_records JOIN airfoils JOIN data_versions WHERE operating conditions",
        1,
        elapsed_ms,
    )
    return jsonify({"elapsed_ms": elapsed_ms, "rows": rows, "row_count": len(rows)})


@app.get("/api/version_compare")
def version_compare() -> Any:
    reynolds_number = int(request.args.get("reynolds_number", "50000"))
    limit = min(max(int(request.args.get("limit", "200")), 1), 500)
    rows = query_all(
        f"""
        SELECT
            dv.airfoil_id,
            a.name,
            dv.version_id,
            dv.version_type,
            ROUND(MAX(p.cl / NULLIF(p.cd, 0)), 6) AS value
        FROM data_versions dv
        JOIN airfoils a ON a.airfoil_id = dv.airfoil_id
        JOIN performance_records p
          ON p.airfoil_id = dv.airfoil_id
         AND p.version_id = dv.version_id
        WHERE p.reynolds_number = %s
        GROUP BY dv.airfoil_id, a.name, dv.version_id, dv.version_type
        HAVING value IS NOT NULL
        ORDER BY value DESC, dv.airfoil_id, dv.version_id
        LIMIT %s
        """,
        (reynolds_number, limit),
    )
    return jsonify(rows)


@app.get("/api/anomalies")
def anomalies() -> Any:
    rows = query_all(
        f"""
        SELECT ar.anomaly_id, ar.perf_id, ar.rule_type, ar.detail,
               p.alpha_deg, p.reynolds_number, p.cl, p.cd, p.cm
        FROM anomaly_records ar
        JOIN performance_records p ON p.perf_id = ar.perf_id
        WHERE ar.airfoil_id = %s AND ar.version_id = %s
          AND {soft_delete_filter_sql("anomaly_records", "ar")}
          AND {soft_delete_filter_sql("performance_records", "p")}
        ORDER BY ar.anomaly_id
        """,
        (request.args.get("airfoil_id", ""), int(request.args.get("version_id", "1"))),
    )
    return jsonify(rows)


@app.get("/api/auth/me")
def auth_me() -> Any:
    user = current_user()
    return jsonify({"authenticated": bool(user), "user": user})


@app.post("/api/auth/register")
def auth_register() -> Any:
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))

    if not valid_username(username):
        return jsonify({"error": "username must be 2-32 letters, numbers, underscores, or Chinese characters"}), 400
    if len(password) < 6:
        return jsonify({"error": "password must be at least 6 characters"}), 400

    role = "viewer"
    try:
        user_id = execute_write_return_id(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
            (username, make_password_hash(password), role),
        )
    except pymysql.err.IntegrityError:
        return jsonify({"error": "username already exists"}), 409

    log_user_action(
        user_id,
        f"Registered read-only user {username}",
        f"INSERT INTO users (username, role) VALUES ('{username}', 'viewer')",
        1,
    )
    session["user_id"] = user_id
    session["username"] = username
    session["role"] = role
    return jsonify({"user_id": user_id, "username": username, "role": role})


@app.post("/api/auth/login")
def auth_login() -> Any:
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    rows = query_all(
        """
        SELECT user_id, username, password_hash, role, is_active
        FROM users
        WHERE username = %s
        """,
        (username,),
    )
    if not rows or rows[0]["is_active"] != 1:
        return jsonify({"error": "username or password is wrong"}), 401
    user = rows[0]
    if not user.get("password_hash") or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "username or password is wrong"}), 401

    session["user_id"] = user["user_id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    if not str(user["password_hash"]).startswith(PASSWORD_HASH_METHOD + "$"):
        execute_write(
            "UPDATE users SET password_hash = %s WHERE user_id = %s",
            (make_password_hash(password), user["user_id"]),
        )
    log_user_action(user["user_id"], f"User {username} logged in", "LOGIN", 1)
    return jsonify({"user_id": user["user_id"], "username": user["username"], "role": user["role"]})


@app.post("/api/auth/logout")
def auth_logout() -> Any:
    user = current_user()
    if user:
        log_user_action(user["user_id"], f"User {user['username']} logged out", "LOGOUT", 1)
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/admin/users")
def admin_users() -> Any:
    role = current_role()
    if not is_manager(role):
        return jsonify({"error": "manager permission required"}), 403
    rows = query_all(
        """
        SELECT user_id, username, role, is_active, created_at
        FROM users
        ORDER BY user_id
        """
    )
    return jsonify(rows)


@app.post("/api/admin/users/create")
def admin_create_user() -> Any:
    user = current_user()
    if not user or not is_admin(user["role"]):
        return jsonify({"error": "admin permission required"}), 403

    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    role = str(payload.get("role", "viewer")).strip()
    if role not in {"viewer", "analyst", "engineer", "admin"}:
        return jsonify({"error": "invalid role"}), 400
    if not valid_username(username):
        return jsonify({"error": "invalid username"}), 400
    if len(password) < 6:
        return jsonify({"error": "password must be at least 6 characters"}), 400

    try:
        new_user_id = execute_write_return_id(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
            (username, make_password_hash(password), role),
        )
    except pymysql.err.IntegrityError:
        log_user_action(
            user["user_id"],
            f"Rejected admin user creation: duplicate {username}",
            f"INSERT INTO users (username, role) VALUES ('{username}', '{role}')",
            0,
        )
        return jsonify({"error": "username already exists"}), 409

    log_user_action(
        user["user_id"],
        f"Admin created user {username}",
        f"INSERT INTO users (username, role) VALUES ('{username}', '{role}')",
        1,
    )
    return jsonify({"user_id": new_user_id, "username": username, "role": role})


@app.get("/api/admin/query_logs")
def admin_query_logs() -> Any:
    role = current_role()
    if not is_manager(role):
        return jsonify({"error": "manager permission required"}), 403
    rows = query_all(
        """
        SELECT q.log_id, q.user_id, u.username, q.natural_language, q.sql_text,
               q.is_valid, q.execution_time_ms, q.executed_at
        FROM query_logs q
        JOIN users u ON u.user_id = q.user_id
        ORDER BY q.log_id DESC
        LIMIT 50
        """
    )
    return jsonify(rows)


@app.get("/api/admin/main_table")
def admin_main_table() -> Any:
    role = current_role()
    if not is_analyst_or_manager(role):
        return jsonify({"error": "analyst/engineer/admin permission required"}), 403
    table_name = request.args.get("table", "airfoils")
    limit_arg = request.args.get("limit", "100")
    if table_name not in ADMIN_VIEW_TABLES:
        return jsonify({"error": "table is not allowed"}), 400
    if role != "admin" and table_name in {"users", "query_logs", "audit_logs", "data_record_lineage", "data_import_records", "soft_delete_records", "saved_transactions", "performance_import_staging"}:
        return jsonify({"error": "non-admin users can view engineering data and views only"}), 403
    if table_name == "data_record_lineage":
        ensure_lineage_schema()
        sync_lineage_records()
    elif table_name == "data_import_records":
        ensure_import_schema()
        sync_import_records()
    elif table_name == "soft_delete_records":
        ensure_soft_delete_schema()

    columns = [
        row["column_name"]
        for row in query_all(
            """
            SELECT COLUMN_NAME AS column_name
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = %s
            ORDER BY ordinal_position
            """,
            (table_name,),
        )
    ]
    if not columns:
        return jsonify({"error": "table has no visible columns"}), 400

    include_options = request.args.get("include_options", "0") == "1"
    include_deleted = request.args.get("include_deleted", "0") == "1" and role == "admin"
    filter_columns = [column for column in MAIN_TABLE_KEY_FILTERS.get(table_name, []) if column in columns]
    filter_options: dict[str, list[Any]] = {}
    if include_options:
        option_soft_filter = (
            f" AND {soft_delete_filter_sql(table_name)}"
            if table_name in SOFT_DELETE_TARGET_TABLES and not include_deleted
            else ""
        )
        for column in filter_columns:
            filter_options[column] = [
                row["value"]
                for row in query_all(
                    f"""
                    SELECT value
                    FROM (
                        SELECT DISTINCT `{column}` AS value
                        FROM `{table_name}`
                        WHERE `{column}` IS NOT NULL
                        {option_soft_filter}
                    ) AS distinct_values
                    ORDER BY CAST(value AS CHAR)
                    LIMIT 300
                    """
                )
            ]

    where_parts: list[str] = []
    params: list[Any] = []
    filters: dict[str, str] = {}
    for column in filter_columns:
        value = request.args.get(f"filter_{column}", "").strip()
        if value:
            filters[column] = value
            if table_name == "data_record_lineage" and column == "previous_record_version_id" and value.lower() in {"null", "none", "空"}:
                where_parts.append("`previous_record_version_id` IS NULL")
            else:
                where_parts.append(f"CAST(`{column}` AS CHAR) = %s")
                params.append(value)
    if table_name in SOFT_DELETE_TARGET_TABLES and not include_deleted:
        where_parts.append(soft_delete_filter_sql(table_name))
    where_sql = " WHERE " + " AND ".join(where_parts) if where_parts else ""

    total = query_all(f"SELECT COUNT(*) AS count FROM `{table_name}`{where_sql}", tuple(params))[0]["count"]
    if limit_arg == "all":
        rows = query_all(f"SELECT * FROM `{table_name}`{where_sql}", tuple(params))
        limit: int | str = "all"
    else:
        limit = min(max(int(limit_arg), 1), 10000)
        rows = query_all(f"SELECT * FROM `{table_name}`{where_sql} LIMIT %s", tuple(params + [limit]))
    return jsonify(
        {
            "table": table_name,
            "total": total,
            "limit": limit,
            "columns": columns,
            "filter_columns": filter_columns,
            "filter_options": filter_options,
            "filters": filters,
            "include_deleted": include_deleted,
            "rows": rows,
        }
    )


def required_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if value in (None, ""):
        raise ValueError(f"{key} is required")
    return int(value)


def required_float(payload: dict[str, Any], key: str) -> float:
    value = payload.get(key)
    if value in (None, ""):
        raise ValueError(f"{key} is required")
    return float(value)


def friendly_mysql_error(exc: pymysql.MySQLError, table_name: str = "") -> str:
    code = exc.args[0] if exc.args else None
    message = str(exc)
    if code == 1062:
        duplicated = re.search(r"Duplicate entry '([^']+)' for key '([^']+)'", message)
        if duplicated:
            value, key_name = duplicated.groups()
            key_hint = key_name.split(".")[-1]
            if "source_file" in key_hint:
                return f"{table_name or '记录'} 创建失败：airfoil_id + source_file 组合重复（{value}）。同一翼型不能重复登记同一个源文件。"
            if "PRIMARY" in key_hint.upper() or "airfoil_id" in key_hint:
                return f"{table_name or '记录'} 创建失败：主键重复（{value}），数据库中已经存在这条记录。请换一个编号，或编辑已有记录。"
            if "version" in key_hint:
                return f"{table_name or '记录'} 创建失败：版本主键重复（{value}）。该翼型下已经存在这个 version_id，请换成更大的版本号。"
            if "coordinate" in key_hint or "point" in key_hint:
                return f"{table_name or '记录'} 创建失败：坐标点主键重复（{value}）。该翼型版本下已经存在这个 point_order，请换成下一点序号。"
            return f"{table_name or '记录'} 创建失败：唯一字段 {key_hint} 重复（{value}）。"
        return f"{table_name or '记录'} 创建失败：主键或唯一字段重复，数据库中已经存在相同记录。"
    if code == 1452:
        if table_name == "coordinate_points":
            return "coordinate_points 创建失败：引用的 airfoil_id + version_id 在 data_versions 中不存在，请先为该翼型创建对应数据版本。"
        if table_name == "data_versions":
            return "data_versions 创建失败：引用的 airfoil_id 在 airfoils 中不存在，请先创建翼型基本信息。"
        return f"{table_name or '记录'} 创建失败：外键引用不存在，请先创建被引用的主表记录。"
    if code == 3819:
        if table_name == "coordinate_points":
            if "coordinate_points_chk_2" in message:
                return "coordinate_points 创建失败：x 坐标必须在 -0.001 到 1.001 之间。"
            if "coordinate_points_chk_3" in message:
                return "coordinate_points 创建失败：surface 只能是 upper 或 lower。"
            if "coordinate_points_chk_4" in message:
                return "coordinate_points 创建失败：point_source 只能是 real 或 augmented。"
            if "coordinate_points_chk_5" in message:
                return "coordinate_points 创建失败：is_augmented 只能是 0 或 1。"
            if "coordinate_points_chk_6" in message:
                return "coordinate_points 创建失败：augmentation_method 只能是 original_coordinate 或 linear_interpolation。"
            if "coordinate_points_chk_7" in message:
                return "coordinate_points 创建失败：真实点必须为 real + is_augmented=0 + original_coordinate；增强点必须为 augmented + is_augmented=1 + linear_interpolation。"
        return f"{table_name or '记录'} 创建失败：违反了表的 CHECK 约束，请检查字段取值范围和枚举值。"
    return message


def airfoil_create_conflict_message(airfoil_id: str, source_file: str) -> str | None:
    rows = query_all(
        """
        SELECT a.airfoil_id, a.source_file, sd.delete_id, sd.is_active
        FROM airfoils a
        LEFT JOIN soft_delete_records sd
          ON sd.table_name = 'airfoils'
         AND sd.record_pk = a.airfoil_id
         AND sd.is_active = 1
        WHERE a.airfoil_id = %s
           OR (a.airfoil_id = %s AND a.source_file = %s)
        LIMIT 5
        """,
        (airfoil_id, airfoil_id, source_file),
    )
    for row in rows:
        if row.get("airfoil_id") == airfoil_id:
            if int(row.get("is_active") or 0) == 1:
                return f"airfoils 创建失败：airfoil_id={airfoil_id} 已被逻辑删除但仍保留在数据库中。请到 管理审计 -> 逻辑删除记录 中恢复，或换一个 airfoil_id。"
            return f"airfoils 创建失败：airfoil_id={airfoil_id} 已存在。airfoils 的主键是 airfoil_id，不能重复；请编辑已有记录或换编号。"
    for row in rows:
        if row.get("airfoil_id") == airfoil_id and row.get("source_file") == source_file:
            return f"airfoils 创建失败：airfoil_id={airfoil_id} 与 source_file={source_file} 的组合已存在。请编辑已有记录，或换一个 airfoil_id/source_file 组合。"
    return None


@app.errorhandler(pymysql.MySQLError)
def handle_mysql_error(exc: pymysql.MySQLError) -> Any:
    return jsonify({"error": friendly_mysql_error(exc), "mysql_error": str(exc)}), 500


@app.post("/api/performance_records/update")
def update_performance_record() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403

    payload = request.get_json(silent=True) or {}
    try:
        perf_id = required_int(payload, "perf_id")
        cl = required_float(payload, "cl")
        cd = required_float(payload, "cd")
        cm = required_float(payload, "cm")
        is_anomaly = int(payload.get("is_anomaly", 0))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    if is_anomaly not in {0, 1}:
        return jsonify({"error": "is_anomaly must be 0 or 1"}), 400

    start = time.perf_counter()
    try:
        affected = execute_write(
            """
            UPDATE performance_records
            SET cl = %s, cd = %s, cm = %s, is_anomaly = %s
            WHERE perf_id = %s
            """,
            (cl, cd, cm, is_anomaly, perf_id),
        )
    except pymysql.MySQLError as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        log_user_action(user["user_id"], f"Failed performance update {perf_id}", "UPDATE performance_records", 0, elapsed_ms)
        return jsonify({"error": str(exc)}), 400

    rows = query_all(
        """
        SELECT perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, is_anomaly
        FROM performance_records
        WHERE perf_id = %s
        """,
        (perf_id,),
    )
    if rows:
        mark_lineage_modified(
            "performance_records",
            str(perf_id),
            rows[0]["airfoil_id"],
            f"version {rows[0]['version_id']}",
            user,
        )
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    log_user_action(user["user_id"], f"Updated performance record {perf_id}", "UPDATE performance_records", 1 if affected else 0, elapsed_ms)
    return jsonify({"affected_rows": affected, "elapsed_ms": elapsed_ms, "rows": rows})


@app.post("/api/airfoils/update")
def update_airfoil_record() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403

    payload = request.get_json(silent=True) or {}
    airfoil_id = str(payload.get("airfoil_id", "")).strip()
    name = str(payload.get("name", "")).strip()
    source = str(payload.get("source", "")).strip()
    family = str(payload.get("family", "")).strip()
    source_type = str(payload.get("source_type", "")).strip()
    source_file = str(payload.get("source_file", "")).strip()
    try:
        is_generated = int(payload.get("is_generated", 0))
        has_augmented_coordinates = int(payload.get("has_augmented_coordinates", 0))
        original_point_count = int(payload.get("original_point_count", 1))
        final_point_count = int(payload.get("final_point_count", 1))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    if not airfoil_id or not name or not source or not family or not source_type or not source_file:
        return jsonify({"error": "airfoil_id, name, source, family, source_type, and source_file are required"}), 400
    if is_generated not in {0, 1} or has_augmented_coordinates not in {0, 1}:
        return jsonify({"error": "is_generated and has_augmented_coordinates must be 0 or 1"}), 400
    if original_point_count <= 0 or final_point_count < original_point_count:
        return jsonify({"error": "point counts must be positive and final_point_count >= original_point_count"}), 400

    start = time.perf_counter()
    old_rows = query_all("SELECT * FROM airfoils WHERE airfoil_id = %s", (airfoil_id,))
    try:
        affected = execute_write(
            """
            UPDATE airfoils
            SET name = %s,
                source = %s,
                family = %s,
                is_generated = %s,
                source_type = %s,
                source_file = %s,
                has_augmented_coordinates = %s,
                original_point_count = %s,
                final_point_count = %s
            WHERE airfoil_id = %s
            """,
            (
                name,
                source,
                family,
                is_generated,
                source_type,
                source_file,
                has_augmented_coordinates,
                original_point_count,
                final_point_count,
                airfoil_id,
            ),
        )
    except pymysql.MySQLError as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        log_user_action(user["user_id"], f"Failed airfoil update {airfoil_id}", "UPDATE airfoils", 0, elapsed_ms)
        return jsonify({"error": str(exc)}), 400

    rows = query_all("SELECT * FROM airfoils WHERE airfoil_id = %s", (airfoil_id,))
    mark_lineage_modified("airfoils", airfoil_id, airfoil_id, "master", user)
    if old_rows and rows and affected:
        version_rows = query_all(
            """
            SELECT previous_record_version_id, record_version_id
            FROM data_record_lineage
            WHERE table_name = 'airfoils' AND record_pk = %s
            LIMIT 1
            """,
            (airfoil_id,),
        )
        previous_version = None
        record_version = 0
        if version_rows:
            previous_version = version_rows[0].get("previous_record_version_id")
            record_version = int(version_rows[0].get("record_version_id") or 0)
        log_audit_change(
            "airfoils",
            "UPDATE",
            airfoil_id,
            previous_version,
            record_version,
            old_rows[0],
            rows[0],
        )
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    log_user_action(user["user_id"], f"Updated airfoil {airfoil_id}", "UPDATE airfoils", 1 if affected else 0, elapsed_ms)
    return jsonify({"affected_rows": affected, "elapsed_ms": elapsed_ms, "rows": rows})


@app.post("/api/anomaly_records/update")
def update_anomaly_record() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403

    payload = request.get_json(silent=True) or {}
    try:
        anomaly_id = required_int(payload, "anomaly_id")
        perf_id = required_int(payload, "perf_id")
        version_id = required_int(payload, "version_id")
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    airfoil_id = str(payload.get("airfoil_id", "")).strip()
    rule_type = str(payload.get("rule_type", "")).strip()
    detail = str(payload.get("detail", "")).strip()
    if not airfoil_id or not detail:
        return jsonify({"error": "airfoil_id and detail are required"}), 400
    if rule_type not in {"negative_cd", "extreme_cl", "extreme_ld_ratio"}:
        return jsonify({"error": "rule_type must be negative_cd, extreme_cl, or extreme_ld_ratio"}), 400

    start = time.perf_counter()
    try:
        affected = execute_write(
            """
            UPDATE anomaly_records
            SET perf_id = %s,
                airfoil_id = %s,
                version_id = %s,
                rule_type = %s,
                detail = %s
            WHERE anomaly_id = %s
            """,
            (perf_id, airfoil_id, version_id, rule_type, detail, anomaly_id),
        )
    except pymysql.MySQLError as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        log_user_action(user["user_id"], f"Failed anomaly update {anomaly_id}", "UPDATE anomaly_records", 0, elapsed_ms)
        return jsonify({"error": str(exc)}), 400

    rows = query_all("SELECT * FROM anomaly_records WHERE anomaly_id = %s", (anomaly_id,))
    if rows:
        mark_lineage_modified(
            "anomaly_records",
            str(anomaly_id),
            rows[0]["airfoil_id"],
            f"version {rows[0]['version_id']}",
            user,
        )
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    log_user_action(user["user_id"], f"Updated anomaly record {anomaly_id}", "UPDATE anomaly_records", 1 if affected else 0, elapsed_ms)
    return jsonify({"affected_rows": affected, "elapsed_ms": elapsed_ms, "rows": rows})


@app.post("/api/coordinate_points/update")
def update_coordinate_point() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403

    payload = request.get_json(silent=True) or {}
    try:
        airfoil_id = str(payload.get("airfoil_id", "")).strip()
        version_id = required_int(payload, "version_id")
        point_order = required_int(payload, "point_order")
        x_value = required_float(payload, "x")
        y_value = required_float(payload, "y")
        is_augmented = int(payload.get("is_augmented", 0))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    surface = str(payload.get("surface", "")).strip()
    point_source = str(payload.get("point_source", "")).strip()
    augmentation_method = str(payload.get("augmentation_method", "")).strip()
    original_order_raw = str(payload.get("original_order", "")).strip()
    try:
        original_order = None if original_order_raw == "" else int(original_order_raw)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    if not airfoil_id:
        return jsonify({"error": "airfoil_id is required"}), 400
    if surface not in {"upper", "lower"}:
        return jsonify({"error": "surface must be upper or lower"}), 400
    if point_source not in {"real", "augmented"}:
        return jsonify({"error": "point_source must be real or augmented"}), 400
    if is_augmented not in {0, 1}:
        return jsonify({"error": "is_augmented must be 0 or 1"}), 400
    if augmentation_method not in {"original_coordinate", "linear_interpolation"}:
        return jsonify({"error": "augmentation_method must be original_coordinate or linear_interpolation"}), 400
    if point_source == "real" and (is_augmented != 0 or augmentation_method != "original_coordinate"):
        return jsonify({"error": "real points must use is_augmented=0 and original_coordinate"}), 400
    if point_source == "augmented" and (is_augmented != 1 or augmentation_method != "linear_interpolation"):
        return jsonify({"error": "augmented points must use is_augmented=1 and linear_interpolation"}), 400

    start = time.perf_counter()
    try:
        affected = execute_write(
            """
            UPDATE coordinate_points
            SET x = %s,
                y = %s,
                surface = %s,
                point_source = %s,
                is_augmented = %s,
                original_order = %s,
                augmentation_method = %s
            WHERE airfoil_id = %s AND version_id = %s AND point_order = %s
            """,
            (
                x_value,
                y_value,
                surface,
                point_source,
                is_augmented,
                original_order,
                augmentation_method,
                airfoil_id,
                version_id,
                point_order,
            ),
        )
    except pymysql.MySQLError as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        log_user_action(user["user_id"], f"Failed coordinate point update {airfoil_id}#{version_id}#{point_order}", "UPDATE coordinate_points", 0, elapsed_ms)
        return jsonify({"error": str(exc)}), 400

    rows = query_all(
        """
        SELECT *
        FROM coordinate_points
        WHERE airfoil_id = %s AND version_id = %s AND point_order = %s
        """,
        (airfoil_id, version_id, point_order),
    )
    if rows:
        mark_lineage_modified(
            "coordinate_points",
            f"{airfoil_id}#{version_id}#{point_order}",
            airfoil_id,
            f"version {version_id}",
            user,
        )
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    log_user_action(user["user_id"], f"Updated coordinate point {airfoil_id}#{version_id}#{point_order}", "UPDATE coordinate_points", 1 if affected else 0, elapsed_ms)
    return jsonify({"affected_rows": affected, "elapsed_ms": elapsed_ms, "rows": rows})


@app.post("/api/data_sources/update")
def update_data_source() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403

    payload = request.get_json(silent=True) or {}
    source_type = str(payload.get("source_type", "")).strip()
    description = str(payload.get("description", "")).strip()
    if source_type not in {"uiuc_raw", "uiuc_raw_with_tracked_augmentation", "generated_synthetic", "injected_anomaly"}:
        return jsonify({"error": "invalid source_type"}), 400
    if not description:
        return jsonify({"error": "description is required"}), 400

    start = time.perf_counter()
    try:
        affected = execute_write(
            "UPDATE data_sources SET description = %s WHERE source_type = %s",
            (description, source_type),
        )
    except pymysql.MySQLError as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        log_user_action(user["user_id"], f"Failed data source update {source_type}", "UPDATE data_sources", 0, elapsed_ms)
        return jsonify({"error": str(exc)}), 400

    rows = query_all("SELECT * FROM data_sources WHERE source_type = %s", (source_type,))
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    log_user_action(user["user_id"], f"Updated data source {source_type}", "UPDATE data_sources", 1 if affected else 0, elapsed_ms)
    return jsonify({"affected_rows": affected, "elapsed_ms": elapsed_ms, "rows": rows})


@app.post("/api/data_versions/update")
def update_data_version() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403

    payload = request.get_json(silent=True) or {}
    airfoil_id = str(payload.get("airfoil_id", "")).strip()
    try:
        version_id = required_int(payload, "version_id")
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    version_type = str(payload.get("version_type", "")).strip()
    coordinate_source_type = str(payload.get("coordinate_source_type", "")).strip()
    description = str(payload.get("description", "")).strip()
    if not airfoil_id:
        return jsonify({"error": "airfoil_id is required"}), 400
    if version_type not in {"imported_raw", "augmented_from_raw"}:
        return jsonify({"error": "invalid version_type"}), 400
    if coordinate_source_type not in {"real_only", "mixed_real_and_augmented"}:
        return jsonify({"error": "invalid coordinate_source_type"}), 400

    start = time.perf_counter()
    try:
        affected = execute_write(
            """
            UPDATE data_versions
            SET version_type = %s,
                coordinate_source_type = %s,
                description = %s
            WHERE airfoil_id = %s AND version_id = %s
            """,
            (version_type, coordinate_source_type, description, airfoil_id, version_id),
        )
    except pymysql.MySQLError as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        log_user_action(user["user_id"], f"Failed data version update {airfoil_id}#{version_id}", "UPDATE data_versions", 0, elapsed_ms)
        return jsonify({"error": str(exc)}), 400

    rows = query_all("SELECT * FROM data_versions WHERE airfoil_id = %s AND version_id = %s", (airfoil_id, version_id))
    if rows:
        mark_lineage_modified("data_versions", f"{airfoil_id}#{version_id}", airfoil_id, f"version {version_id}", user)
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    log_user_action(user["user_id"], f"Updated data version {airfoil_id}#{version_id}", "UPDATE data_versions", 1 if affected else 0, elapsed_ms)
    return jsonify({"affected_rows": affected, "elapsed_ms": elapsed_ms, "rows": rows})


def batch_import_value(table_name: str, column: str, value: Any) -> Any:
    if value == "":
        if table_name == "coordinate_points" and column == "original_order":
            return None
        if table_name in {"data_versions", "anomaly_records"} and column in {"description", "detail"}:
            return None
    if column in BATCH_IMPORT_INT_COLUMNS:
        if value in (None, ""):
            raise ValueError(f"{column} is required")
        return int(value)
    if column in BATCH_IMPORT_FLOAT_COLUMNS:
        if value in (None, ""):
            raise ValueError(f"{column} is required")
        return float(value)
    return "" if value is None else str(value).strip()


def batch_record_identity(table_name: str, row: dict[str, Any]) -> tuple[str, str | None, int | None, str | None, str]:
    if table_name == "data_sources":
        pk = str(row["source_type"])
        return pk, None, None, pk, "source"
    if table_name == "airfoils":
        pk = str(row["airfoil_id"])
        return pk, pk, None, str(row.get("source_type") or ""), "master"
    if table_name == "data_versions":
        airfoil_id = str(row["airfoil_id"])
        version_id = int(row["version_id"])
        return f"{airfoil_id}#{version_id}", airfoil_id, version_id, None, f"version {version_id}"
    if table_name == "coordinate_points":
        airfoil_id = str(row["airfoil_id"])
        version_id = int(row["version_id"])
        return f"{airfoil_id}#{version_id}#{int(row['point_order'])}", airfoil_id, version_id, None, f"version {version_id}"
    if table_name == "performance_records":
        version_id = int(row["version_id"])
        return str(row["perf_id"]), str(row["airfoil_id"]), version_id, str(row.get("source_type") or ""), f"version {version_id}"
    if table_name == "anomaly_records":
        version_id = int(row["version_id"])
        return str(row["anomaly_id"]), str(row["airfoil_id"]), version_id, None, f"version {version_id}"
    raise ValueError("unsupported table")


def validate_batch_payload(payload: dict[str, Any]) -> tuple[str, str, list[str], list[dict[str, Any]]]:
    table_name = str(payload.get("table", "")).strip()
    batch_id = str(payload.get("batch_id", "")).strip()
    headers = payload.get("headers", [])
    rows = payload.get("rows", [])
    if table_name not in BATCH_IMPORT_COLUMNS:
        raise ValueError("target table is not supported for batch import")
    if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", batch_id):
        raise ValueError("batch_id must be 1-64 letters, numbers, underscores, or dashes")
    expected = BATCH_IMPORT_COLUMNS[table_name]
    if headers != expected:
        raise ValueError(
            "CSV/TSV header does not match the selected table order. "
            f"Expected: {', '.join(expected)}; got: {', '.join(str(x) for x in headers)}"
        )
    if not isinstance(rows, list) or not rows or len(rows) > MAX_BATCH_IMPORT_ROWS:
        raise ValueError("rows must contain 1-10000 records")
    return table_name, batch_id, expected, rows


def remap_batch_integer_primary_keys(table_name: str, id_column: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not rows:
        return []
    max_rows = query_all(f"SELECT COALESCE(MAX(`{id_column}`), 0) AS max_id FROM `{table_name}`")
    next_id = int(max_rows[0].get("max_id") or 0) + 1
    mappings: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        original_id = int(row[id_column])
        new_id = next_id + index
        row[id_column] = new_id
        mappings.append({
            "row_no": index + 2,
            "input_id": original_id,
            "stored_id": new_id,
            "note": f"{id_column} is treated as a file-local id and remapped to avoid primary-key conflicts",
        })
    return mappings


def detect_and_insert_anomalies_for_performance(perf_ids: list[int], user: dict[str, Any], batch_id: str) -> list[dict[str, Any]]:
    if not perf_ids:
        return []
    placeholders = ", ".join(["%s"] * len(perf_ids))
    candidates = query_all(
        f"""
        SELECT
            p.perf_id,
            p.airfoil_id,
            p.version_id,
            p.alpha_deg,
            p.reynolds_number,
            p.cl,
            p.cd,
            p.cm,
            CASE
                WHEN p.cd < 0 THEN 'negative_cd'
                WHEN ABS(p.cl) > 2 THEN 'extreme_cl'
                WHEN p.cd <> 0 AND ABS(p.cl / p.cd) > 100 THEN 'extreme_ld_ratio'
                ELSE NULL
            END AS rule_type
        FROM performance_records p
        LEFT JOIN anomaly_records ar ON ar.perf_id = p.perf_id
        WHERE p.perf_id IN ({placeholders})
          AND ar.perf_id IS NULL
          AND (
                p.cd < 0
                OR ABS(p.cl) > 2
                OR (p.cd <> 0 AND ABS(p.cl / p.cd) > 100)
          )
        ORDER BY p.perf_id
        """,
        tuple(perf_ids),
    )
    candidates = [row for row in candidates if row.get("rule_type")]
    if not candidates:
        return []

    conn = get_db_connection()
    inserted_rows: list[dict[str, Any]] = []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COALESCE(MAX(anomaly_id), 0) AS max_id FROM anomaly_records")
            next_id = int((cur.fetchone() or {}).get("max_id") or 0) + 1
            candidate_ids = tuple(int(row["perf_id"]) for row in candidates)
            candidate_placeholders = ", ".join(["%s"] * len(candidate_ids))
            cur.execute(
                f"UPDATE performance_records SET is_anomaly = 1 WHERE perf_id IN ({candidate_placeholders})",
                candidate_ids,
            )
            for index, row in enumerate(candidates):
                anomaly_id = next_id + index
                cl = float(row["cl"])
                cd = float(row["cd"])
                ratio = None if cd == 0 else cl / cd
                detail = (
                    f"Auto detected after batch import {batch_id}: "
                    f"rule={row['rule_type']}; alpha={row['alpha_deg']}; "
                    f"Re={row['reynolds_number']}; cl={row['cl']}; cd={row['cd']}; "
                    f"cl_cd_ratio={'' if ratio is None else round(ratio, 6)}"
                )
                cur.execute(
                    """
                    INSERT INTO anomaly_records
                        (anomaly_id, perf_id, airfoil_id, version_id, rule_type, detail)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        anomaly_id,
                        row["perf_id"],
                        row["airfoil_id"],
                        row["version_id"],
                        row["rule_type"],
                        detail,
                    ),
                )
                inserted_rows.append(
                    {
                        "anomaly_id": anomaly_id,
                        "perf_id": row["perf_id"],
                        "airfoil_id": row["airfoil_id"],
                        "version_id": row["version_id"],
                        "rule_type": row["rule_type"],
                        "detail": detail,
                    }
                )
        conn.commit()
    except pymysql.MySQLError:
        conn.rollback()
        raise
    finally:
        release_db_connection(conn)

    for row in inserted_rows:
        record_pk = str(row["anomaly_id"])
        source_version = f"version {row['version_id']}"
        log_data_import(
            "anomaly_records",
            record_pk,
            "system",
            user,
            airfoil_id=str(row["airfoil_id"]),
            version_id=int(row["version_id"]),
            source_type="auto_anomaly_detection",
            description=f"batch_id={batch_id}; perf_id={row['perf_id']}; rule={row['rule_type']}",
        )
        mark_lineage_insert("anomaly_records", record_pk, str(row["airfoil_id"]), source_version)
    return inserted_rows


def import_generic_batch(table_name: str, batch_id: str, columns: list[str], rows: list[dict[str, Any]], user: dict[str, Any]) -> dict[str, Any]:
    parsed_rows: list[dict[str, Any]] = []
    for row_no, row in enumerate(rows, start=2):
        if not isinstance(row, dict):
            raise ValueError(f"line {row_no}: row must be an object")
        if set(row.keys()) != set(columns):
            raise ValueError(f"line {row_no}: columns do not match selected table")
        parsed = {column: batch_import_value(table_name, column, row.get(column, "")) for column in columns}
        parsed_rows.append(parsed)

    primary_key_remaps: list[dict[str, Any]] = []
    if table_name == "anomaly_records":
        primary_key_remaps = remap_batch_integer_primary_keys("anomaly_records", "anomaly_id", parsed_rows)
    values: list[tuple[Any, ...]] = [tuple(parsed[column] for column in columns) for parsed in parsed_rows]

    start = time.perf_counter()
    column_sql = ", ".join(f"`{column}`" for column in columns)
    placeholders = ", ".join(["%s"] * len(columns))
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.executemany(f"INSERT INTO `{table_name}` ({column_sql}) VALUES ({placeholders})", values)
        conn.commit()
    except pymysql.MySQLError as exc:
        conn.rollback()
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        log_user_action(user["user_id"], f"Failed batch import {batch_id} into {table_name}", f"INSERT INTO {table_name}", 0, elapsed_ms)
        raise ValueError(friendly_mysql_error(exc, table_name)) from exc
    finally:
        release_db_connection(conn)

    inserted_rows: list[dict[str, Any]] = []
    for parsed in parsed_rows:
        record_pk, airfoil_id, version_id, source_type, source_version = batch_record_identity(table_name, parsed)
        log_data_import(
            table_name,
            record_pk,
            "frontend",
            user,
            airfoil_id=airfoil_id,
            version_id=version_id,
            source_type=source_type,
            description=f"batch_id={batch_id}; header_aligned_import",
        )
        mark_lineage_insert(table_name, record_pk, airfoil_id, source_version)
        inserted_rows.append({"table_name": table_name, "record_pk": record_pk, **parsed})

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    log_user_action(user["user_id"], f"Batch import {batch_id} into {table_name}", f"INSERT INTO {table_name}", 1, elapsed_ms)
    return {
        "batch_id": batch_id,
        "target_table": table_name,
        "elapsed_ms": elapsed_ms,
        "sections": [
            {"title": "Header validation", "rows": [{"target_table": table_name, "expected_header": ", ".join(columns), "status": "matched"}]},
            {"title": "Primary key remap", "rows": primary_key_remaps},
            {"title": "Imported rows", "rows": inserted_rows},
        ],
    }


def import_performance_batch(user: dict[str, Any], payload: dict[str, Any]) -> Any:
    batch_id = str(payload.get("batch_id", "")).strip()
    rows = payload.get("rows", [])
    if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", batch_id):
        return jsonify({"error": "batch_id must be 1-64 letters, numbers, underscores, or dashes"}), 400
    if not isinstance(rows, list) or not rows or len(rows) > MAX_BATCH_IMPORT_ROWS:
        return jsonify({"error": "rows must contain 1-10000 records"}), 400

    parsed_dicts: list[dict[str, Any]] = []
    try:
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("each row must be an object")
            if set(row.keys()) != set(BATCH_IMPORT_COLUMNS["performance_records"]):
                raise ValueError("performance_records columns do not match the required header")
            parsed_dicts.append({
                "perf_id": required_int(row, "perf_id"),
                "airfoil_id": str(row.get("airfoil_id", "")).strip(),
                "version_id": required_int(row, "version_id"),
                "alpha_deg": required_float(row, "alpha_deg"),
                "reynolds_number": required_int(row, "reynolds_number"),
                "cl": required_float(row, "cl"),
                "cd": required_float(row, "cd"),
                "cm": required_float(row, "cm"),
                "source_type": str(row.get("source_type", "generated_synthetic")).strip() or "generated_synthetic",
                "is_anomaly": required_int(row, "is_anomaly"),
            })
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    primary_key_remaps = remap_batch_integer_primary_keys("performance_records", "perf_id", parsed_dicts)
    parsed_rows: list[tuple[Any, ...]] = [
        (
            batch_id,
            row["perf_id"],
            row["airfoil_id"],
            row["version_id"],
            row["alpha_deg"],
            row["reynolds_number"],
            row["cl"],
            row["cd"],
            row["cm"],
            row["source_type"],
            row["is_anomaly"],
        )
        for row in parsed_dicts
    ]
    perf_ids: list[int] = [int(row["perf_id"]) for row in parsed_dicts]

    start = time.perf_counter()
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM performance_import_staging WHERE batch_id COLLATE utf8mb4_unicode_ci = %s COLLATE utf8mb4_unicode_ci",
                (batch_id,),
            )
            cur.executemany(
                """
                INSERT INTO performance_import_staging
                    (batch_id, perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                parsed_rows,
            )
        conn.commit()
    except pymysql.MySQLError as exc:
        conn.rollback()
        release_db_connection(conn)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        log_user_action(user["user_id"], f"Failed staging batch {batch_id}", "INSERT INTO performance_import_staging", 0, elapsed_ms)
        return jsonify({"error": friendly_mysql_error(exc, "performance_import_staging")}), 400
    finally:
        if conn.open:
            conn.close()

    try:
        result_sets = query_result_sets("CALL sp_import_performance_batch(%s)", (batch_id,))
    except pymysql.MySQLError as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        log_user_action(user["user_id"], f"Failed import batch {batch_id}", "CALL sp_import_performance_batch", 0, elapsed_ms)
        return jsonify({"error": friendly_mysql_error(exc, "performance_records")}), 400

    placeholders = ", ".join(["%s"] * len(perf_ids))
    imported_rows = query_all(
        f"""
        SELECT perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm
        FROM performance_records
        WHERE perf_id IN ({placeholders})
        ORDER BY perf_id
        """,
        tuple(perf_ids),
    )
    staged_rows = query_all(
        """
        SELECT staging_id, perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, validation_error, imported
        FROM performance_import_staging
        WHERE batch_id COLLATE utf8mb4_unicode_ci = %s COLLATE utf8mb4_unicode_ci
        ORDER BY staging_id
        """,
        (batch_id,),
    )
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    status_rows = result_sets[0] if result_sets else []
    ok = bool(status_rows and status_rows[0].get("status") == "imported")
    detected_anomalies: list[dict[str, Any]] = []
    if ok:
        try:
            detected_anomalies = detect_and_insert_anomalies_for_performance(perf_ids, user, batch_id)
        except pymysql.MySQLError as exc:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            log_user_action(user["user_id"], f"Failed anomaly detection for batch {batch_id}", "INSERT INTO anomaly_records", 0, elapsed_ms)
            return jsonify({"error": friendly_mysql_error(exc, "anomaly_records")}), 400

        imported_rows = query_all(
            f"""
            SELECT perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, is_anomaly
            FROM performance_records
            WHERE perf_id IN ({placeholders})
            ORDER BY perf_id
            """,
            tuple(perf_ids),
        )
    for row in imported_rows:
        record_pk, airfoil_id, version_id, source_type, source_version = batch_record_identity("performance_records", row)
        log_data_import(
            "performance_records",
            record_pk,
            "frontend",
            user,
            airfoil_id=airfoil_id,
            version_id=version_id,
            source_type=source_type,
            description=f"batch_id={batch_id}; staging_procedure_import",
        )
        mark_lineage_insert("performance_records", record_pk, airfoil_id, source_version)
    log_user_action(user["user_id"], f"Performance batch import {batch_id}", "CALL sp_import_performance_batch", 1 if ok else 0, elapsed_ms)
    return jsonify(
        {
            "batch_id": batch_id,
            "target_table": "performance_records",
            "elapsed_ms": elapsed_ms,
            "sections": [
                {"title": "Header validation", "rows": [{"target_table": "performance_records", "expected_header": ", ".join(BATCH_IMPORT_COLUMNS["performance_records"]), "status": "matched"}]},
                {"title": "Primary key remap", "rows": primary_key_remaps},
                {"title": "Procedure status", "rows": status_rows},
                {"title": "Rejected rows", "rows": result_sets[1] if len(result_sets) > 1 else []},
                {"title": "Staging rows", "rows": staged_rows},
                {"title": "Imported rows", "rows": imported_rows},
                {"title": "Auto anomaly detection", "rows": detected_anomalies},
            ],
        }
    )


@app.post("/api/batch_import/run")
def run_batch_import() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403
    payload = request.get_json(silent=True) or {}
    try:
        table_name, batch_id, columns, rows = validate_batch_payload(payload)
        if table_name == "performance_records":
            return import_performance_batch(user, payload)
        return jsonify(import_generic_batch(table_name, batch_id, columns, rows, user))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/performance_import/run")
def run_performance_import() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403

    payload = request.get_json(silent=True) or {}
    batch_id = str(payload.get("batch_id", "")).strip()
    rows = payload.get("rows", [])
    if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", batch_id):
        return jsonify({"error": "batch_id must be 1-64 letters, numbers, underscores, or dashes"}), 400
    if not isinstance(rows, list) or not rows or len(rows) > MAX_BATCH_IMPORT_ROWS:
        return jsonify({"error": "rows must contain 1-10000 records"}), 400

    parsed_rows: list[tuple[Any, ...]] = []
    perf_ids: list[int] = []
    try:
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("each row must be an object")
            perf_id = required_int(row, "perf_id")
            parsed_rows.append(
                (
                    batch_id,
                    perf_id,
                    str(row.get("airfoil_id", "")).strip(),
                    required_int(row, "version_id"),
                    required_float(row, "alpha_deg"),
                    required_int(row, "reynolds_number"),
                    required_float(row, "cl"),
                    required_float(row, "cd"),
                    required_float(row, "cm"),
                    str(row.get("source_type", "generated_synthetic")).strip() or "generated_synthetic",
                    required_int(row, "is_anomaly"),
                )
            )
            perf_ids.append(perf_id)
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    start = time.perf_counter()
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM performance_import_staging WHERE batch_id COLLATE utf8mb4_unicode_ci = %s COLLATE utf8mb4_unicode_ci",
                (batch_id,),
            )
            cur.executemany(
                """
                INSERT INTO performance_import_staging
                    (batch_id, perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                parsed_rows,
            )
        conn.commit()
    except pymysql.MySQLError as exc:
        conn.rollback()
        release_db_connection(conn)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        log_user_action(user["user_id"], f"Failed staging batch {batch_id}", "INSERT INTO performance_import_staging", 0, elapsed_ms)
        return jsonify({"error": str(exc)}), 400
    finally:
        if conn.open:
            conn.close()

    try:
        result_sets = query_result_sets("CALL sp_import_performance_batch(%s)", (batch_id,))
    except pymysql.MySQLError as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        log_user_action(user["user_id"], f"Failed import batch {batch_id}", "CALL sp_import_performance_batch", 0, elapsed_ms)
        return jsonify({"error": str(exc)}), 400

    placeholders = ", ".join(["%s"] * len(perf_ids))
    imported_rows = query_all(
        f"""
        SELECT perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm
        FROM performance_records
        WHERE perf_id IN ({placeholders})
        ORDER BY perf_id
        """,
        tuple(perf_ids),
    )
    staged_rows = query_all(
        """
        SELECT staging_id, perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, validation_error, imported
        FROM performance_import_staging
        WHERE batch_id COLLATE utf8mb4_unicode_ci = %s COLLATE utf8mb4_unicode_ci
        ORDER BY staging_id
        """,
        (batch_id,),
    )
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    status_rows = result_sets[0] if result_sets else []
    ok = bool(status_rows and status_rows[0].get("status") == "imported")
    detected_anomalies: list[dict[str, Any]] = []
    if ok:
        try:
            detected_anomalies = detect_and_insert_anomalies_for_performance(perf_ids, user, batch_id)
        except pymysql.MySQLError as exc:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            log_user_action(user["user_id"], f"Failed anomaly detection for batch {batch_id}", "INSERT INTO anomaly_records", 0, elapsed_ms)
            return jsonify({"error": friendly_mysql_error(exc, "anomaly_records")}), 400

        imported_rows = query_all(
            f"""
            SELECT perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, is_anomaly
            FROM performance_records
            WHERE perf_id IN ({placeholders})
            ORDER BY perf_id
            """,
            tuple(perf_ids),
        )
    log_user_action(user["user_id"], f"Performance batch import {batch_id}", "CALL sp_import_performance_batch", 1 if ok else 0, elapsed_ms)
    return jsonify(
        {
            "batch_id": batch_id,
            "elapsed_ms": elapsed_ms,
            "sections": [
                {"title": "Procedure status", "rows": status_rows},
                {"title": "Rejected rows", "rows": result_sets[1] if len(result_sets) > 1 else []},
                {"title": "Staging rows", "rows": staged_rows},
                {"title": "Imported rows", "rows": imported_rows},
                {"title": "Auto anomaly detection", "rows": detected_anomalies},
            ],
        }
    )


@app.post("/api/data_governance/run")
def run_data_governance() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403

    payload = request.get_json(silent=True) or {}
    scenario = str(payload.get("scenario", "")).strip()
    airfoil_filter = str(payload.get("airfoil_id", "")).strip()
    perf_id_filter = int(payload.get("perf_id", 0) or 0)
    limit_count = min(max(int(payload.get("limit", 80) or 80), 1), 500)
    start = time.perf_counter()
    sections: list[dict[str, Any]] = []

    if scenario == "record":
        perf_where = []
        perf_params: list[Any] = []
        if airfoil_filter:
            perf_where.append("p.airfoil_id = %s")
            perf_params.append(airfoil_filter)
        if perf_id_filter > 0:
            perf_where.append("p.perf_id = %s")
            perf_params.append(perf_id_filter)
        perf_where_sql = "WHERE " + " AND ".join(perf_where) if perf_where else ""
        perf_params.append(limit_count)

        airfoil_where_sql = "WHERE a.airfoil_id = %s" if airfoil_filter else ""
        airfoil_params: list[Any] = [airfoil_filter] if airfoil_filter else []
        airfoil_params.append(limit_count)

        sections = [
            {
                "title": "记录级治理：performance_records",
                "note": "每条 performance_records 都展示所属版本、来源、异常状态、异常规则和审计次数。",
                "rows": query_all(
                    f"""
                    SELECT
                        p.perf_id,
                        p.airfoil_id,
                        a.name AS airfoil_name,
                        p.version_id,
                        dv.version_type,
                        dv.coordinate_source_type,
                        p.source_type AS performance_source,
                        p.alpha_deg,
                        p.reynolds_number,
                        p.cl,
                        p.cd,
                        p.cm,
                        p.is_anomaly,
                        ar.anomaly_id,
                        ar.rule_type,
                        COALESCE(audit.audit_count, 0) AS audit_count
                    FROM performance_records p
                    JOIN airfoils a
                        ON a.airfoil_id = p.airfoil_id
                    JOIN data_versions dv
                        ON dv.airfoil_id = p.airfoil_id
                       AND dv.version_id = p.version_id
                    LEFT JOIN anomaly_records ar
                        ON ar.perf_id = p.perf_id
                    LEFT JOIN (
                        SELECT record_pk, COUNT(*) AS audit_count
                        FROM audit_logs
                        WHERE table_name = 'performance_records'
                        GROUP BY record_pk
                    ) audit
                        ON audit.record_pk = CAST(p.perf_id AS CHAR)
                    {perf_where_sql}
                    ORDER BY p.is_anomaly DESC, p.perf_id
                    LIMIT %s
                    """,
                    tuple(perf_params),
                ),
            },
            {
                "title": "记录级治理：airfoils",
                "note": "每条 airfoils 主记录都展示真实来源、增强状态、版本数量、性能记录数量和异常数量。",
                "rows": query_all(
                    f"""
                    SELECT
                        a.airfoil_id,
                        a.name,
                        a.source_type,
                        ds.description AS source_description,
                        a.source_file,
                        a.has_augmented_coordinates,
                        a.original_point_count,
                        a.final_point_count,
                        COUNT(DISTINCT dv.version_id) AS version_count,
                        COUNT(DISTINCT p.perf_id) AS performance_count,
                        COUNT(DISTINCT ar.anomaly_id) AS anomaly_count
                    FROM airfoils a
                    JOIN data_sources ds
                        ON ds.source_type = a.source_type
                    LEFT JOIN data_versions dv
                        ON dv.airfoil_id = a.airfoil_id
                    LEFT JOIN performance_records p
                        ON p.airfoil_id = a.airfoil_id
                    LEFT JOIN anomaly_records ar
                        ON ar.perf_id = p.perf_id
                    GROUP BY
                        a.airfoil_id,
                        a.name,
                        a.source_type,
                        ds.description,
                        a.source_file,
                        a.has_augmented_coordinates,
                        a.original_point_count,
                        a.final_point_count
                    {airfoil_where_sql}
                    ORDER BY anomaly_count DESC, a.airfoil_id
                    LIMIT %s
                    """,
                    tuple(airfoil_params),
                ),
            },
        ]
    elif scenario == "anomaly":
        sections = [
            {
                "title": "异常规则分布：anomaly_records",
                "note": "异常记录已经单独写入 anomaly_records，并通过触发器保证只能引用 is_anomaly = 1 的性能记录。",
                "rows": query_all(
                    """
                    SELECT rule_type, COUNT(*) AS anomaly_count
                    FROM anomaly_records
                    GROUP BY rule_type
                    ORDER BY anomaly_count DESC, rule_type
                    """
                ),
            },
            {
                "title": "异常详情样例：v_anomaly_details",
                "note": "该视图由 anomaly_records 关联 performance_records 与 airfoils 得到，用于查看异常记录对应的翼型和性能值。",
                "rows": query_all(
                    """
                    SELECT anomaly_id, airfoil_id, airfoil_name, rule_type, alpha_deg,
                           reynolds_number, cl, cd, ROUND(lift_drag_ratio, 6) AS lift_drag_ratio
                    FROM v_anomaly_details
                    ORDER BY anomaly_id
                    LIMIT 20
                    """
                ),
            },
        ]
    elif scenario == "version":
        sections = [
            {
                "title": "版本追踪：data_versions JOIN airfoils",
                "note": "data_versions 记录每条几何数据来自哪个版本，以及是否由原始数据增强得到。",
                "rows": query_all(
                    """
                    SELECT dv.airfoil_id, a.name, dv.version_id, dv.version_type,
                           dv.coordinate_source_type, dv.description
                    FROM data_versions dv
                    JOIN airfoils a ON a.airfoil_id = dv.airfoil_id
                    ORDER BY dv.airfoil_id, dv.version_id
                    LIMIT 30
                    """
                ),
            },
            {
                "title": "版本汇总：data_versions",
                "note": "按 version_type 与 coordinate_source_type 汇总 data_versions 中的版本记录。",
                "rows": query_all(
                    """
                    SELECT version_type, coordinate_source_type, COUNT(*) AS version_count
                    FROM data_versions
                    GROUP BY version_type, coordinate_source_type
                    ORDER BY version_count DESC
                    """
                ),
            },
        ]
    elif scenario == "source":
        sections = [
            {
                "title": "数据来源说明：data_sources",
                "note": "data_sources 区分真实 UIUC 坐标、增强坐标、合成性能数据、注入异常数据。",
                "rows": query_all(
                    """
                    SELECT source_type, description
                    FROM data_sources
                    ORDER BY source_type
                    """
                ),
            },
            {
                "title": "来源使用情况：airfoils",
                "note": "统计 airfoils 中各 source_type 的使用数量。",
                "rows": query_all(
                    """
                    SELECT source_type, COUNT(*) AS airfoil_count
                    FROM airfoils
                    GROUP BY source_type
                    ORDER BY airfoil_count DESC, source_type
                    """
                ),
            },
        ]
    elif scenario == "delete":
        sections = [
            {
                "title": "删除策略说明：核心关系策略",
                "note": "核心工程数据不建议直接物理删除；依赖数据通过外键约束维护一致性，审计和查询日志用于保留操作证据。",
                "rows": [
                    {"data_type": "airfoils / data_versions / coordinate_points", "strategy": "核心工程数据，演示环境依赖外键 CASCADE；生产环境建议逻辑删除。"},
                    {"data_type": "performance_records", "strategy": "分析数据不建议直接删除；修改会触发 audit_logs 记录。"},
                    {"data_type": "anomaly_records", "strategy": "异常标记可修正；必须引用 is_anomaly = 1 的性能记录。"},
                    {"data_type": "query_logs / audit_logs", "strategy": "治理证据与审计记录，不建议删除。"},
                    {"data_type": "saved_transactions", "strategy": "用户私有事务脚本，允许用户删除自己的保存项。"},
                ],
            },
            {
                "title": "外键删除规则：information_schema.referential_constraints",
                "rows": query_all(
                    """
                    SELECT table_name, constraint_name, referenced_table_name, delete_rule
                    FROM information_schema.referential_constraints
                    WHERE constraint_schema = DATABASE()
                    ORDER BY table_name, constraint_name
                    """
                ),
            },
        ]
    else:
        return jsonify({"error": "unknown scenario"}), 400

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    log_user_action(user["user_id"], f"Ran data governance scenario {scenario}", f"DATA_GOVERNANCE {scenario}", 1, elapsed_ms)
    return jsonify({"scenario": scenario, "elapsed_ms": elapsed_ms, "sections": sections})


@app.get("/query_logs/<int:log_id>/sql")
def query_log_sql_page(log_id: int) -> Any:
    role = current_role()
    if not is_manager(role):
        return "manager permission required", 403
    rows = query_all(
        """
        SELECT q.log_id, q.user_id, u.username, q.natural_language, q.sql_text,
               q.is_valid, q.execution_time_ms, q.executed_at
        FROM query_logs q
        JOIN users u ON u.user_id = q.user_id
        WHERE q.log_id = %s
        """,
        (log_id,),
    )
    if not rows:
        return "query log not found", 404
    row = rows[0]
    return render_template_string(
        """
        <!doctype html>
        <html lang="zh-CN">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>QueryLog {{ row.log_id }}</title>
          <style>
            body { margin:0; padding:24px; font-family:"Segoe UI",Arial,"Microsoft YaHei",sans-serif; color:#172033; background:#f7f8fb; }
            .card { max-width:1100px; margin:0 auto; background:#fff; border:1px solid #d8dde8; border-radius:8px; padding:18px; box-shadow:0 8px 22px rgba(26,34,55,.08); }
            h1 { margin:0 0 12px; font-size:20px; }
            .meta { display:flex; flex-wrap:wrap; gap:8px 18px; color:#62708a; font-size:13px; margin-bottom:14px; }
            pre { margin:0; white-space:pre-wrap; word-break:break-word; border:1px solid #d8dde8; border-radius:6px; background:#fbfcff; padding:14px; font-family:Consolas,monospace; font-size:13px; line-height:1.5; }
          </style>
        </head>
        <body>
          <div class="card">
            <h1>QueryLog #{{ row.log_id }}</h1>
            <div class="meta">
              <span>User: {{ row.username }}</span>
              <span>Valid: {{ row.is_valid }}</span>
              <span>Time: {{ row.execution_time_ms }} ms</span>
              <span>Executed: {{ row.executed_at }}</span>
            </div>
            <pre>{{ row.sql_text }}</pre>
          </div>
        </body>
        </html>
        """,
        row=row,
    )


@app.post("/api/query_logs/run")
def run_logged_query() -> Any:
    user = current_user()
    if not user:
        return jsonify({"error": "please login first"}), 401

    payload = request.get_json(silent=True) or {}
    sql = str(payload.get("sql", "")).strip()
    natural_language = str(payload.get("natural_language", "")).strip() or None
    role = user["role"]

    allowed = is_allowed_editor_sql(sql) if is_admin(role) else is_safe_select(sql)
    if not allowed:
        log_user_action(user["user_id"], natural_language, sql, 0)
        if is_admin(role):
            return jsonify({"error": "only safe single SQL statements are allowed"}), 400
        return jsonify({"error": "non-admin users can only run SELECT or EXPLAIN SELECT"}), 400

    start = time.perf_counter()
    rows: list[dict[str, Any]] = []
    explain_rows: list[dict[str, Any]] = []
    affected_rows: int | None = None
    error: str | None = None
    is_valid = 0
    conn = get_db_connection()
    try:
        normalized = sql.strip().lower()
        statement = sql.rstrip(";")
        with conn.cursor() as cur:
            if (
                normalized.startswith("select")
                or normalized.startswith("explain select")
                or normalized.startswith("call ")
            ):
                cur.execute(statement)
                rows = list(cur.fetchall())
                if normalized.startswith("select"):
                    cur.execute("EXPLAIN " + statement)
                    explain_rows = list(cur.fetchall())
            else:
                affected_rows = cur.execute(statement)
                rows = [{"affected_rows": affected_rows}]
                inferred_import = infer_sql_import_target(statement)
                if inferred_import and affected_rows:
                    table_name, record_pk = inferred_import
                    cur.execute(
                        """
                        INSERT INTO data_import_records
                            (target_table, record_pk, entry_method, created_by_user_id, created_by_username, description)
                        VALUES (%s, %s, 'sql', %s, %s, %s)
                        """,
                        (table_name, record_pk, user["user_id"], user["username"], statement[:1000]),
                    )
            is_valid = 1
    except Exception as exc:
        conn.rollback()
        error = str(exc)

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO query_logs
                    (user_id, natural_language, sql_text, is_ai_generated, is_valid, execution_time_ms)
                VALUES (%s, %s, %s, 0, %s, %s)
                """,
                (user["user_id"], natural_language, sql, is_valid, elapsed_ms),
            )
        conn.commit()
    finally:
        release_db_connection(conn)

    if error:
        return jsonify({"error": error, "elapsed_ms": elapsed_ms, "rows": []}), 400
    return jsonify(
        {
            "elapsed_ms": elapsed_ms,
            "row_count": len(rows),
            "affected_rows": affected_rows,
            "explain": explain_rows,
            "rows": rows[:100],
        }
    )


@app.post("/api/airfoils/create")
def create_airfoil() -> Any:
    user = current_user()
    if not user:
        return jsonify({"error": "please login first"}), 401
    if not is_manager(user["role"]):
        log_user_action(user["user_id"], "Rejected graphical airfoil creation", "INSERT INTO airfoils (...)", 0)
        return jsonify({"error": "engineer/admin permission required"}), 403

    payload = request.get_json(silent=True) or {}
    airfoil_id = str(payload.get("airfoil_id", "")).strip().lower()
    name = str(payload.get("name", "")).strip()
    family = str(payload.get("family", "Manual")).strip() or "Manual"
    source_type = str(payload.get("source_type", "uiuc_raw")).strip()
    source = str(payload.get("source", "Manual Input")).strip() or "Manual Input"
    source_file = str(payload.get("source_file", f"manual\\{airfoil_id}.dat")).strip()
    original_point_count = int(payload.get("original_point_count") or 1)
    final_point_count = int(payload.get("final_point_count") or original_point_count)

    if not re.fullmatch(r"[a-z0-9_]{2,64}", airfoil_id):
        log_user_action(user["user_id"], "Rejected graphical airfoil creation: invalid airfoil_id", "INSERT INTO airfoils (...)", 0)
        return jsonify({"error": "invalid airfoil_id"}), 400
    if not name:
        log_user_action(user["user_id"], "Rejected graphical airfoil creation: empty name", "INSERT INTO airfoils (...)", 0)
        return jsonify({"error": "name is required"}), 400
    if final_point_count < original_point_count:
        return jsonify({"error": "final_point_count must be >= original_point_count"}), 400

    try:
        execute_write(
            """
            INSERT INTO airfoils
                (airfoil_id, name, source, family, is_generated, source_type, source_file,
                 has_augmented_coordinates, original_point_count, final_point_count)
            VALUES (%s, %s, %s, %s, 0, %s, %s, 0, %s, %s)
            """,
            (airfoil_id, name, source, family, source_type, source_file, original_point_count, final_point_count),
        )
    except pymysql.err.IntegrityError as exc:
        log_user_action(user["user_id"], f"Rejected graphical airfoil creation: {airfoil_id}", f"INSERT INTO airfoils (...) VALUES ('{airfoil_id}', ...)", 0)
        return jsonify({"error": str(exc)}), 409

    log_user_action(user["user_id"], f"Graphically created airfoil {airfoil_id}", f"INSERT INTO airfoils (...) VALUES ('{airfoil_id}', ...)", 1)
    log_data_import(
        "airfoils",
        airfoil_id,
        "frontend",
        user,
        airfoil_id=airfoil_id,
        source_type=source_type,
        description=f"{name}; {source_file}",
    )
    return jsonify({"ok": True, "airfoil_id": airfoil_id})


@app.post("/api/main_records/create")
def create_main_record() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403
    payload = request.get_json(silent=True) or {}
    table_name = str(payload.get("table", "")).strip()
    data = payload.get("data", {})
    if not isinstance(data, dict):
        return jsonify({"error": "data must be an object"}), 400

    start = time.perf_counter()
    try:
        if table_name == "data_sources":
            source_type = str(data.get("source_type", "")).strip()
            description = str(data.get("description", "")).strip()
            if source_type not in {"uiuc_raw", "uiuc_raw_with_tracked_augmentation", "generated_synthetic", "injected_anomaly"}:
                return jsonify({"error": "invalid source_type"}), 400
            if not description:
                return jsonify({"error": "description is required"}), 400
            execute_write(
                "INSERT INTO data_sources (source_type, description) VALUES (%s, %s)",
                (source_type, description),
            )
            record_pk = source_type
            log_data_import("data_sources", record_pk, "frontend", user, source_type=source_type, description=description)
            mark_lineage_insert("data_sources", record_pk, None, "source")
        elif table_name == "airfoils":
            airfoil_id = str(data.get("airfoil_id", "")).strip().lower()
            name = str(data.get("name", "")).strip()
            source = str(data.get("source", "Frontend Input")).strip() or "Frontend Input"
            family = str(data.get("family", "Manual")).strip() or "Manual"
            source_type = str(data.get("source_type", "uiuc_raw")).strip()
            source_file = str(data.get("source_file", f"frontend\\{airfoil_id}.dat")).strip()
            original_point_count = int(data.get("original_point_count") or 1)
            final_point_count = int(data.get("final_point_count") or original_point_count)
            if not re.fullmatch(r"[a-z0-9_]{2,64}", airfoil_id):
                return jsonify({"error": "invalid airfoil_id"}), 400
            if not name:
                return jsonify({"error": "name is required"}), 400
            if final_point_count < original_point_count:
                return jsonify({"error": "final_point_count must be >= original_point_count"}), 400
            execute_write(
                """
                INSERT INTO airfoils
                    (airfoil_id, name, source, family, is_generated, source_type, source_file,
                     has_augmented_coordinates, original_point_count, final_point_count)
                VALUES (%s, %s, %s, %s, 0, %s, %s, 0, %s, %s)
                """,
                (airfoil_id, name, source, family, source_type, source_file, original_point_count, final_point_count),
            )
            record_pk = airfoil_id
            log_data_import("airfoils", record_pk, "frontend", user, airfoil_id=airfoil_id, source_type=source_type, description=f"{name}; {source_file}")
            mark_lineage_insert("airfoils", record_pk, airfoil_id, "master")
        elif table_name == "data_versions":
            airfoil_id = str(data.get("airfoil_id", "")).strip().lower()
            version_id = int(data.get("version_id") or 1)
            version_type = str(data.get("version_type", "imported_raw")).strip()
            coordinate_source_type = str(data.get("coordinate_source_type", "real_only")).strip()
            description = str(data.get("description", "")).strip() or "Frontend created data version"
            if version_type not in {"imported_raw", "augmented_from_raw"}:
                return jsonify({"error": "invalid version_type"}), 400
            if coordinate_source_type not in {"real_only", "mixed_real_and_augmented"}:
                return jsonify({"error": "invalid coordinate_source_type"}), 400
            execute_write(
                """
                INSERT INTO data_versions
                    (airfoil_id, version_id, version_type, coordinate_source_type, description)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (airfoil_id, version_id, version_type, coordinate_source_type, description),
            )
            record_pk = f"{airfoil_id}#{version_id}"
            log_data_import("data_versions", record_pk, "frontend", user, airfoil_id=airfoil_id, version_id=version_id, description=description)
            mark_lineage_insert("data_versions", record_pk, airfoil_id, f"version {version_id}")
        elif table_name == "coordinate_points":
            airfoil_id = str(data.get("airfoil_id", "")).strip().lower()
            version_id = int(data.get("version_id") or 1)
            point_order = int(data.get("point_order") or 1)
            x_value = float(data.get("x"))
            y_value = float(data.get("y"))
            surface = str(data.get("surface", "upper")).strip()
            point_source = str(data.get("point_source", "real")).strip()
            is_augmented = int(data.get("is_augmented") or 0)
            original_order_raw = str(data.get("original_order", "")).strip()
            original_order = None if original_order_raw == "" else int(original_order_raw)
            augmentation_method = str(data.get("augmentation_method", "original_coordinate")).strip()
            if surface not in {"upper", "lower"}:
                return jsonify({"error": "surface 只能选择 upper 或 lower"}), 400
            if point_source not in {"real", "augmented"}:
                return jsonify({"error": "point_source 只能选择 real 或 augmented"}), 400
            if is_augmented not in {0, 1}:
                return jsonify({"error": "is_augmented 只能填写 0 或 1"}), 400
            if augmentation_method not in {"original_coordinate", "linear_interpolation"}:
                return jsonify({"error": "augmentation_method 只能选择 original_coordinate 或 linear_interpolation"}), 400
            if point_order < 1:
                return jsonify({"error": "point_order 必须大于等于 1"}), 400
            if not (-0.001 <= x_value <= 1.001):
                return jsonify({"error": "x 坐标必须在 -0.001 到 1.001 之间"}), 400
            if point_source == "real" and (is_augmented != 0 or augmentation_method != "original_coordinate"):
                return jsonify({"error": "真实坐标点必须满足：point_source=real、is_augmented=0、augmentation_method=original_coordinate"}), 400
            if point_source == "augmented" and (is_augmented != 1 or augmentation_method != "linear_interpolation"):
                return jsonify({"error": "增强坐标点必须满足：point_source=augmented、is_augmented=1、augmentation_method=linear_interpolation"}), 400
            execute_write(
                """
                INSERT INTO coordinate_points
                    (airfoil_id, version_id, point_order, x, y, surface, point_source,
                     is_augmented, original_order, augmentation_method)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    airfoil_id,
                    version_id,
                    point_order,
                    x_value,
                    y_value,
                    surface,
                    point_source,
                    is_augmented,
                    original_order,
                    augmentation_method,
                ),
            )
            record_pk = f"{airfoil_id}#{version_id}#{point_order}"
            log_data_import(
                "coordinate_points",
                record_pk,
                "frontend",
                user,
                airfoil_id=airfoil_id,
                version_id=version_id,
                description=f"point_order={point_order}; x={x_value}; y={y_value}",
            )
            mark_lineage_insert("coordinate_points", record_pk, airfoil_id, f"version {version_id}")
        else:
            return jsonify({"error": "only data_sources, airfoils, data_versions, and coordinate_points can be added here"}), 400
    except pymysql.MySQLError as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        log_user_action(user["user_id"], f"Failed frontend create {table_name}", f"INSERT INTO {table_name}", 0, elapsed_ms)
        return jsonify({"error": friendly_mysql_error(exc, table_name), "mysql_error": str(exc)}), 400
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    log_user_action(user["user_id"], f"Frontend created {table_name}.{record_pk}", f"INSERT INTO {table_name}", 1, elapsed_ms)
    if table_name == "data_sources":
        rows = query_all("SELECT * FROM data_sources WHERE source_type = %s", (record_pk,))
    elif table_name == "airfoils":
        rows = query_all("SELECT * FROM airfoils WHERE airfoil_id = %s", (record_pk,))
    elif table_name == "data_versions":
        rows = query_all("SELECT * FROM data_versions WHERE airfoil_id = %s AND version_id = %s", (airfoil_id, version_id))
    else:
        rows = query_all(
            "SELECT * FROM coordinate_points WHERE airfoil_id = %s AND version_id = %s AND point_order = %s",
            (airfoil_id, version_id, point_order),
        )
    return jsonify({"ok": True, "table": table_name, "record_pk": record_pk, "elapsed_ms": elapsed_ms, "rows": rows})


@app.post("/api/main_records/delete")
def soft_delete_main_record() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403
    payload = request.get_json(silent=True) or {}
    table_name = str(payload.get("table", "")).strip()
    row = payload.get("row", {})
    reason = str(payload.get("reason", "")).strip()
    if table_name not in SOFT_DELETE_TARGET_TABLES:
        return jsonify({"error": "当前关系不支持逻辑删除"}), 400
    if not isinstance(row, dict):
        return jsonify({"error": "row must be an object"}), 400

    start = time.perf_counter()
    try:
        where_sql, params = row_identity_where(table_name, row)
        current_rows = query_all(
            f"""
            SELECT *
            FROM `{table_name}`
            WHERE {where_sql}
              AND {soft_delete_filter_sql(table_name)}
            LIMIT 1
            """,
            params,
        )
        if not current_rows:
            return jsonify({"error": "记录不存在，或已经被逻辑删除"}), 404
        current = current_rows[0]
        record_pk = record_pk_from_row(table_name, current)
        airfoil_id = current.get("airfoil_id")
        version_id = current.get("version_id")
        source_version = "source"
        if table_name == "airfoils":
            source_version = "master"
        elif version_id not in (None, ""):
            source_version = f"version {version_id}"
        delete_record_version_id = current_record_version_id(table_name, record_pk) + 1
        row_snapshot = json.dumps(current, ensure_ascii=False, default=str)
        active_delete = query_all(
            """
            SELECT delete_id
            FROM soft_delete_records
            WHERE table_name = %s AND record_pk = %s AND is_active = 1
            LIMIT 1
            """,
            (table_name, record_pk),
        )
        if active_delete:
            affected = execute_write(
                """
                UPDATE soft_delete_records
                SET airfoil_id = %s,
                    version_id = %s,
                    record_version_id = %s,
                    row_snapshot = %s,
                    delete_reason = %s,
                    deleted_by_user_id = %s,
                    deleted_by_username = %s,
                    deleted_at = CURRENT_TIMESTAMP,
                    restored_by_user_id = NULL,
                    restored_by_username = NULL,
                    restored_at = NULL
                WHERE delete_id = %s
                """,
                (
                    airfoil_id,
                    version_id,
                    delete_record_version_id,
                    row_snapshot,
                    reason or "frontend logical delete",
                    user["user_id"],
                    user["username"],
                    active_delete[0]["delete_id"],
                ),
            )
        else:
            affected = execute_write(
                """
                INSERT INTO soft_delete_records
                    (table_name, record_pk, record_version_id, airfoil_id, version_id, row_snapshot,
                     delete_reason, deleted_by_user_id, deleted_by_username, is_active)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 1)
                """,
                (
                    table_name,
                    record_pk,
                    delete_record_version_id,
                    airfoil_id,
                    version_id,
                    row_snapshot,
                    reason or "frontend logical delete",
                    user["user_id"],
                    user["username"],
                ),
            )
        execute_write(
            """
            INSERT INTO audit_logs
                (table_name, operation_type, record_pk, previous_record_version_id, record_version_id, old_values, new_values)
            VALUES (%s, 'DELETE', %s, %s, %s, %s, JSON_OBJECT(
                'logical_delete', TRUE,
                'is_active', 1,
                'delete_reason', %s,
                'deleted_by_user_id', %s,
                'deleted_by_username', %s
            ))
            """,
            (
                table_name,
                record_pk,
                delete_record_version_id - 1,
                delete_record_version_id,
                row_snapshot,
                reason or "frontend logical delete",
                user["user_id"],
                user["username"],
            ),
        )
        mark_lineage_deleted(table_name, record_pk, airfoil_id, source_version, user)
    except pymysql.MySQLError as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        log_user_action(user["user_id"], f"Failed logical delete {table_name}", f"SOFT DELETE {table_name}", 0, elapsed_ms)
        return jsonify({"error": friendly_mysql_error(exc, table_name), "mysql_error": str(exc)}), 400
    except (KeyError, TypeError, ValueError) as exc:
        return jsonify({"error": f"逻辑删除失败：缺少主键字段或字段格式错误：{exc}"}), 400

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    log_user_action(user["user_id"], f"Logical deleted {table_name}.{record_pk}", f"SOFT DELETE {table_name}", 1, elapsed_ms)
    return jsonify(
        {
            "ok": True,
            "table": table_name,
            "record_pk": record_pk,
            "record_version_id": delete_record_version_id,
            "affected_rows": affected,
            "elapsed_ms": elapsed_ms,
            "rows": current_rows,
        }
    )


@app.post("/api/main_records/restore")
def restore_main_record() -> Any:
    user = current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "admin permission required"}), 403
    payload = request.get_json(silent=True) or {}
    try:
        delete_id = required_int(payload, "delete_id")
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    start = time.perf_counter()
    rows = query_all(
        """
        SELECT delete_id, table_name, record_pk, airfoil_id, version_id, is_active
        FROM soft_delete_records
        WHERE delete_id = %s
        """,
        (delete_id,),
    )
    if not rows:
        return jsonify({"error": "逻辑删除记录不存在"}), 404
    record = rows[0]
    if int(record.get("is_active", 0)) != 1:
        return jsonify({"error": "该记录已经恢复，无需重复恢复"}), 400

    table_name = record["table_name"]
    record_pk = record["record_pk"]
    version_id = record.get("version_id")
    restore_previous_version_id = current_record_version_id(table_name, record_pk)
    restore_record_version_id = restore_previous_version_id + 1
    source_version = "source"
    if table_name == "airfoils":
        source_version = "master"
    elif version_id not in (None, ""):
        source_version = f"version {version_id}"

    try:
        affected = execute_write(
            """
            UPDATE soft_delete_records
            SET is_active = 0,
                restored_by_user_id = %s,
                restored_by_username = %s,
                restored_at = CURRENT_TIMESTAMP
            WHERE delete_id = %s AND is_active = 1
            """,
            (user["user_id"], user["username"], delete_id),
        )
        execute_write(
            """
            INSERT INTO audit_logs
                (table_name, operation_type, record_pk, previous_record_version_id, record_version_id, old_values, new_values)
            VALUES (%s, 'UPDATE', %s, %s, %s,
                    JSON_OBJECT('logical_delete', TRUE, 'is_active', 1),
                    JSON_OBJECT('logical_delete', FALSE, 'is_active', 0,
                                'restored_by_user_id', %s,
                                'restored_by_username', %s))
            """,
            (
                table_name,
                record_pk,
                restore_previous_version_id,
                restore_record_version_id,
                user["user_id"],
                user["username"],
            ),
        )
        mark_lineage_restored(table_name, record_pk, record.get("airfoil_id"), source_version, user)
    except pymysql.MySQLError as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        log_user_action(user["user_id"], f"Failed restore {table_name}.{record_pk}", "RESTORE SOFT DELETE", 0, elapsed_ms)
        return jsonify({"error": friendly_mysql_error(exc, table_name), "mysql_error": str(exc)}), 400

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    log_user_action(user["user_id"], f"Restored {table_name}.{record_pk}", "RESTORE SOFT DELETE", 1 if affected else 0, elapsed_ms)
    return jsonify(
        {
            "ok": True,
            "delete_id": delete_id,
            "table": table_name,
            "record_pk": record_pk,
            "affected_rows": affected,
            "elapsed_ms": elapsed_ms,
        }
    )


@app.get("/api/saved_transactions")
def list_saved_transactions() -> Any:
    user = current_user()
    if not user:
        return jsonify({"error": "please login first"}), 401
    rows = query_all(
        """
        SELECT saved_id, title, sql_text, created_at, updated_at
        FROM saved_transactions
        WHERE user_id = %s
        ORDER BY updated_at DESC, saved_id DESC
        """,
        (user["user_id"],),
    )
    return jsonify(rows)


@app.post("/api/saved_transactions/save")
def save_transaction() -> Any:
    user = current_user()
    if not user:
        return jsonify({"error": "please login first"}), 401
    payload = request.get_json(silent=True) or {}
    title = str(payload.get("title", "")).strip()
    sql_text = str(payload.get("sql", "")).strip()
    if not title or len(title) > 128:
        return jsonify({"error": "title must be 1-128 characters"}), 400
    statements = split_sql_statements(sql_text)
    if not statements:
        return jsonify({"error": "transaction SQL is empty"}), 400
    if len(statements) > 20:
        return jsonify({"error": "at most 20 statements per saved transaction"}), 400
    if any(not is_allowed_transaction_sql(statement) for statement in statements):
        return jsonify({"error": "saved transaction only allows SELECT/INSERT/UPDATE/DELETE and cannot touch users/query_logs or DDL"}), 400

    execute_write(
        """
        INSERT INTO saved_transactions (user_id, title, sql_text)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE
            sql_text = VALUES(sql_text),
            updated_at = CURRENT_TIMESTAMP
        """,
        (user["user_id"], title, sql_text),
    )
    log_user_action(user["user_id"], f"Saved transaction {title}", "UPSERT saved_transactions", 1)
    rows = query_all(
        """
        SELECT saved_id, title, sql_text, created_at, updated_at
        FROM saved_transactions
        WHERE user_id = %s AND title = %s
        """,
        (user["user_id"], title),
    )
    return jsonify(rows[0])


@app.post("/api/saved_transactions/delete")
def delete_saved_transaction() -> Any:
    user = current_user()
    if not user:
        return jsonify({"error": "please login first"}), 401
    payload = request.get_json(silent=True) or {}
    saved_id = int(payload.get("saved_id", 0) or 0)
    if saved_id <= 0:
        return jsonify({"error": "invalid saved_id"}), 400
    affected = execute_write(
        "DELETE FROM saved_transactions WHERE saved_id = %s AND user_id = %s",
        (saved_id, user["user_id"]),
    )
    log_user_action(user["user_id"], f"Deleted saved transaction {saved_id}", "DELETE FROM saved_transactions", 1 if affected else 0)
    return jsonify({"ok": bool(affected), "deleted": affected})


DB_OBJECT_EXPERIMENT_SQL: dict[str, list[dict[str, str]]] = {
    "views": [
        {
            "title": "视图查询：v_airfoil_overview",
            "sql": """SELECT *
FROM v_airfoil_overview
ORDER BY anomaly_count DESC, airfoil_id
LIMIT 8;""",
        },
        {
            "title": "视图查询：v_performance_with_ld",
            "sql": """SELECT airfoil_id, alpha_deg, reynolds_number, cl, cd,
       ROUND(lift_drag_ratio, 6) AS lift_drag_ratio
FROM v_performance_with_ld
WHERE reynolds_number = 50000
ORDER BY lift_drag_ratio DESC
LIMIT 8;""",
        },
        {
            "title": "视图查询：v_anomaly_details",
            "sql": """SELECT anomaly_id, airfoil_id, airfoil_name, rule_type, cl, cd,
       ROUND(lift_drag_ratio, 6) AS lift_drag_ratio
FROM v_anomaly_details
ORDER BY anomaly_id
LIMIT 8;""",
        },
    ],
    "trigger_reject": [
        {
            "title": "准备一条非异常性能记录",
            "sql": """INSERT INTO performance_records
    (perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
VALUES
    (9200001, 'ag03', 1, 2.34, 654322, 0.100, 0.010, 0.000, 'generated_synthetic', 0)
ON DUPLICATE KEY UPDATE
    airfoil_id = VALUES(airfoil_id),
    version_id = VALUES(version_id),
    alpha_deg = VALUES(alpha_deg),
    reynolds_number = VALUES(reynolds_number),
    cl = VALUES(cl),
    cd = VALUES(cd),
    cm = VALUES(cm),
    is_anomaly = 0;""",
        },
        {"title": "清理旧异常记录", "sql": "DELETE FROM anomaly_records WHERE anomaly_id = 9920001;"},
        {
            "title": "触发器拒绝测试",
            "sql": """INSERT INTO anomaly_records
    (anomaly_id, perf_id, airfoil_id, version_id, rule_type, detail)
VALUES
    (9920001, 9200001, 'ag03', 1, 'negative_cd', 'frontend trigger rejection demo');""",
        },
        {
            "title": "验证被引用性能记录",
            "sql": """SELECT perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, is_anomaly
FROM performance_records
WHERE perf_id = 9200001;""",
        },
    ],
    "trigger_audit": [
        {
            "title": "准备审计测试记录",
            "sql": """INSERT INTO performance_records
    (perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
VALUES
    (9200001, 'ag03', 1, 2.34, 654322, 0.100, 0.010, 0.000, 'generated_synthetic', 0)
ON DUPLICATE KEY UPDATE
    cl = 0.100,
    cd = 0.010,
    cm = 0.000,
    is_anomaly = 0;""",
        },
        {"title": "触发 UPDATE 审计", "sql": "UPDATE performance_records SET cl = cl + 0.002 WHERE perf_id = 9200001;"},
        {
            "title": "查看当前性能记录",
            "sql": """SELECT perf_id, cl, cd, cm, is_anomaly
FROM performance_records
WHERE perf_id = 9200001;""",
        },
        {
            "title": "查看触发器写入的审计日志",
            "sql": """SELECT audit_id, table_name, operation_type, record_pk, old_values, new_values, changed_at
FROM audit_logs
WHERE table_name = 'performance_records' AND record_pk = '9200001'
ORDER BY audit_id DESC
LIMIT 5;""",
        },
    ],
    "proc_summary": [
        {"title": "调用单翼型性能统计存储过程", "sql": "CALL sp_airfoil_performance_summary('ag03', 1);"},
        {"title": "调用同一 Re 下多翼型对比存储过程", "sql": "CALL sp_compare_airfoils_by_re(50000, 'max_ld', 10);"},
    ],
    "proc_import_bad": [
        {"title": "清理正式表测试记录", "sql": "DELETE FROM performance_records WHERE perf_id IN (9900101, 9900102);"},
        {"title": "清理暂存表测试批次", "sql": "DELETE FROM performance_import_staging WHERE batch_id = 'demo_bad_batch';"},
        {
            "title": "写入非法批量导入暂存数据",
            "sql": """INSERT INTO performance_import_staging
    (batch_id, perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
VALUES
    ('demo_bad_batch', 9900101, 'ag03', 1, 0, 123456, 0.5, 0.01, 0.0, 'generated_synthetic', 0),
    ('demo_bad_batch', 9900102, 'ag03', 1, 99, 123456, 0.6, 0.02, 0.0, 'generated_synthetic', 0);""",
        },
        {"title": "调用批量导入存储过程", "sql": "CALL sp_import_performance_batch('demo_bad_batch');"},
        {
            "title": "验证正式表没有写入非法批次",
            "sql": """SELECT perf_id, airfoil_id, alpha_deg, reynolds_number
FROM performance_records
WHERE perf_id IN (9900101, 9900102);""",
        },
    ],
    "proc_import_good": [
        {"title": "清理正式表测试记录", "sql": "DELETE FROM performance_records WHERE perf_id IN (9900201, 9900202);"},
        {"title": "清理暂存表测试批次", "sql": "DELETE FROM performance_import_staging WHERE batch_id = 'demo_good_batch';"},
        {
            "title": "写入合法批量导入暂存数据",
            "sql": """INSERT INTO performance_import_staging
    (batch_id, perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
VALUES
    ('demo_good_batch', 9900201, 'ag03', 1, -1, 123457, 0.45, 0.012, 0.0, 'generated_synthetic', 0),
    ('demo_good_batch', 9900202, 'ag03', 1, 1, 123457, 0.55, 0.013, 0.0, 'generated_synthetic', 0);""",
        },
        {"title": "调用批量导入存储过程", "sql": "CALL sp_import_performance_batch('demo_good_batch');"},
        {
            "title": "验证正式表已写入合法批次",
            "sql": """SELECT perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd
FROM performance_records
WHERE perf_id IN (9900201, 9900202)
ORDER BY perf_id;""",
        },
    ],
}


DB_OBJECT_DEFINITION_SQL: dict[str, list[dict[str, str]]] = {
    "views": [
        {
            "title": "创建视图：v_airfoil_overview（翼型总览）",
            "sql": """CREATE VIEW v_airfoil_overview AS
SELECT a.airfoil_id, a.name, a.family, a.source_type,
       COUNT(DISTINCT dv.version_id) AS version_count,
       COUNT(DISTINCT cp.point_order) AS coordinate_count,
       COUNT(DISTINCT pr.perf_id) AS performance_count,
       COUNT(DISTINCT ar.anomaly_id) AS anomaly_count
FROM airfoils a
LEFT JOIN data_versions dv ON dv.airfoil_id = a.airfoil_id
LEFT JOIN coordinate_points cp ON cp.airfoil_id = dv.airfoil_id AND cp.version_id = dv.version_id
LEFT JOIN performance_records pr ON pr.airfoil_id = dv.airfoil_id AND pr.version_id = dv.version_id
LEFT JOIN anomaly_records ar ON ar.perf_id = pr.perf_id
GROUP BY a.airfoil_id, a.name, a.family, a.source_type;""",
        },
        {
            "title": "创建视图：v_performance_with_ld（性能记录派生升阻比）",
            "sql": """CREATE VIEW v_performance_with_ld AS
SELECT p.perf_id, p.airfoil_id, a.name AS airfoil_name, p.version_id,
       p.alpha_deg, p.reynolds_number, p.cl, p.cd, p.cm,
       CASE WHEN p.cd = 0 THEN NULL ELSE p.cl / p.cd END AS lift_drag_ratio,
       p.is_anomaly
FROM performance_records p
JOIN airfoils a ON a.airfoil_id = p.airfoil_id;""",
        },
        {
            "title": "创建视图：v_anomaly_details（异常详情关联查询）",
            "sql": """CREATE VIEW v_anomaly_details AS
SELECT ar.anomaly_id, ar.rule_type, ar.detail,
       p.perf_id, p.airfoil_id, a.name AS airfoil_name,
       p.version_id, p.alpha_deg, p.reynolds_number, p.cl, p.cd, p.cm,
       CASE WHEN p.cd = 0 THEN NULL ELSE p.cl / p.cd END AS lift_drag_ratio
FROM anomaly_records ar
JOIN performance_records p ON p.perf_id = ar.perf_id
JOIN airfoils a ON a.airfoil_id = p.airfoil_id;""",
        },
    ],
    "trigger_reject": [
        {
            "title": "创建触发器：trg_anomaly_requires_flag_insert（异常记录必须引用异常性能记录）",
            "sql": """CREATE TRIGGER trg_anomaly_requires_flag_insert
BEFORE INSERT ON anomaly_records
FOR EACH ROW
BEGIN
    IF (SELECT is_anomaly FROM performance_records WHERE perf_id = NEW.perf_id) <> 1 THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'AnomalyRecord must reference a PerformanceRecord with is_anomaly = 1';
    END IF;
END;""",
        },
    ],
    "trigger_audit": [
        {
            "title": "创建触发器：trg_audit_performance_update（性能记录更新审计）",
            "sql": """CREATE TRIGGER trg_audit_performance_update
AFTER UPDATE ON performance_records
FOR EACH ROW
FOLLOWS trg_lineage_performance_update
BEGIN
    INSERT INTO audit_logs
        (table_name, operation_type, record_pk, previous_record_version_id, record_version_id, old_values, new_values)
    VALUES
        ('performance_records', 'UPDATE', CAST(OLD.perf_id AS CHAR),
         COALESCE((SELECT previous_record_version_id FROM data_record_lineage
                   WHERE table_name = 'performance_records' AND record_pk = CAST(OLD.perf_id AS CHAR) LIMIT 1), 0),
         COALESCE((SELECT record_version_id FROM data_record_lineage
                   WHERE table_name = 'performance_records' AND record_pk = CAST(OLD.perf_id AS CHAR) LIMIT 1), 1),
         JSON_OBJECT('cl', OLD.cl, 'cd', OLD.cd, 'cm', OLD.cm, 'is_anomaly', OLD.is_anomaly),
         JSON_OBJECT('cl', NEW.cl, 'cd', NEW.cd, 'cm', NEW.cm, 'is_anomaly', NEW.is_anomaly));
END;""",
        },
    ],
    "proc_summary": [
        {
            "title": "创建存储过程：sp_airfoil_performance_summary（单翼型性能统计）",
            "sql": """CREATE PROCEDURE sp_airfoil_performance_summary(IN p_airfoil_id VARCHAR(64), IN p_version_id INT)
BEGIN
    SELECT p.airfoil_id, a.name AS airfoil_name, p.version_id, p.reynolds_number,
           COUNT(*) AS sample_count,
           ROUND(MIN(p.cd), 6) AS min_cd,
           ROUND(MAX(p.cl), 6) AS max_cl,
           ROUND(AVG(p.cl), 6) AS avg_cl,
           ROUND(MAX(p.cl / NULLIF(p.cd, 0)), 6) AS max_lift_drag_ratio,
           SUM(p.is_anomaly) AS anomaly_count
    FROM performance_records p
    JOIN airfoils a ON a.airfoil_id = p.airfoil_id
    WHERE p.airfoil_id = p_airfoil_id AND p.version_id = p_version_id
    GROUP BY p.airfoil_id, a.name, p.version_id, p.reynolds_number
    ORDER BY p.reynolds_number;
END;""",
        },
        {
            "title": "创建存储过程：sp_compare_airfoils_by_re（同一 Re 多翼型对比）",
            "sql": """CREATE PROCEDURE sp_compare_airfoils_by_re(IN p_reynolds_number INT, IN p_metric VARCHAR(32), IN p_limit_count INT)
BEGIN
    SELECT ranked.airfoil_id, ranked.airfoil_name, ranked.metric_name, ranked.metric_value
    FROM (
        SELECT p.airfoil_id, a.name AS airfoil_name,
               CASE ... END AS metric_name,
               CASE ... END AS metric_value
        FROM performance_records p
        JOIN airfoils a ON a.airfoil_id = p.airfoil_id
        WHERE p.reynolds_number = p_reynolds_number
        GROUP BY p.airfoil_id, a.name
    ) ranked
    ORDER BY metric_value DESC
    LIMIT p_limit_count;
END;""",
        },
    ],
    "proc_import_bad": [
        {
            "title": "创建存储过程：sp_validate_performance_import_batch（导入前校验）",
            "sql": """CREATE PROCEDURE sp_validate_performance_import_batch(IN p_batch_id VARCHAR(64))
BEGIN
    UPDATE performance_import_staging
    SET validation_error = CONCAT_WS('; ',
        CASE WHEN alpha_deg < -20 OR alpha_deg > 25 THEN 'alpha_deg out of range [-20, 25]' END,
        CASE WHEN reynolds_number <= 0 THEN 'reynolds_number must be positive' END,
        CASE WHEN referenced data version does not exist THEN 'referenced data version does not exist' END,
        CASE WHEN perf_id already exists THEN 'perf_id already exists' END
    )
    WHERE batch_id = p_batch_id AND imported = 0;
    SELECT * FROM performance_import_staging WHERE batch_id = p_batch_id;
END;""",
        },
        {
            "title": "创建存储过程：sp_import_performance_batch（非法批次整体回滚）",
            "sql": """CREATE PROCEDURE sp_import_performance_batch(IN p_batch_id VARCHAR(64))
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION BEGIN ROLLBACK; RESIGNAL; END;
    START TRANSACTION;
    CALL sp_validate_performance_import_batch(p_batch_id);
    IF EXISTS(SELECT 1 FROM performance_import_staging WHERE batch_id = p_batch_id AND validation_error IS NOT NULL) THEN
        ROLLBACK;
        SELECT 'rejected' AS status;
    ELSE
        INSERT INTO performance_records (...) SELECT ... FROM performance_import_staging WHERE batch_id = p_batch_id;
        COMMIT;
    END IF;
END;""",
        },
    ],
    "proc_import_good": [
        {
            "title": "创建存储过程：sp_import_performance_batch（合法批次整体提交）",
            "sql": """CREATE PROCEDURE sp_import_performance_batch(IN p_batch_id VARCHAR(64))
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION BEGIN ROLLBACK; RESIGNAL; END;
    START TRANSACTION;
    CALL sp_validate_performance_import_batch(p_batch_id);
    INSERT INTO performance_records (...)
    SELECT ... FROM performance_import_staging
    WHERE batch_id = p_batch_id AND validation_error IS NULL;
    UPDATE performance_import_staging SET imported = 1 WHERE batch_id = p_batch_id;
    COMMIT;
END;""",
        },
    ],
}
DB_OBJECT_DEFINITION_OBJECTS: dict[str, list[tuple[str, str, str]]] = {
    "views": [
        ("VIEW", "v_airfoil_overview", "视图：翼型总览"),
        ("VIEW", "v_performance_with_ld", "视图：性能记录派生升阻比"),
        ("VIEW", "v_anomaly_details", "视图：异常详情关联查询"),
    ],
    "trigger_reject": [
        ("TRIGGER", "trg_anomaly_requires_flag_insert", "触发器：异常记录必须引用异常性能记录"),
        ("TRIGGER", "trg_anomaly_requires_flag_update", "触发器：异常记录更新时重新校验"),
    ],
    "trigger_audit": [
        ("TRIGGER", "trg_audit_performance_update", "触发器：性能记录更新审计"),
    ],
    "proc_summary": [
        ("PROCEDURE", "sp_airfoil_performance_summary", "存储过程：单翼型性能统计"),
        ("PROCEDURE", "sp_compare_airfoils_by_re", "存储过程：同一 Re 多翼型对比"),
    ],
    "proc_import_bad": [
        ("PROCEDURE", "sp_validate_performance_import_batch", "存储过程：批量导入校验"),
        ("PROCEDURE", "sp_import_performance_batch", "存储过程：批量导入提交或回滚"),
    ],
    "proc_import_good": [
        ("PROCEDURE", "sp_validate_performance_import_batch", "存储过程：批量导入校验"),
        ("PROCEDURE", "sp_import_performance_batch", "存储过程：批量导入提交或回滚"),
    ],
}


def quote_identifier(identifier: str) -> str:
    return "`" + identifier.replace("`", "``") + "`"


def db_object_definition_blocks(scenario: str) -> list[dict[str, str]]:
    blocks: list[dict[str, str]] = []
    for object_type, object_name, title in DB_OBJECT_DEFINITION_OBJECTS.get(scenario, []):
        try:
            rows = query_all(f"SHOW CREATE {object_type} {quote_identifier(object_name)}")
            if not rows:
                continue
            row = rows[0]
            create_sql = ""
            for key, value in row.items():
                normalized = str(key).lower()
                if normalized.startswith("create ") or normalized == "sql original statement":
                    create_sql = str(value)
                    break
            if create_sql:
                blocks.append({"title": title, "sql": create_sql})
        except pymysql.MySQLError:
            continue
    return blocks or DB_OBJECT_DEFINITION_SQL.get(scenario, [])
@app.post("/api/db_object_experiment/run")
def run_db_object_experiment() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403

    scenario = str((request.get_json(silent=True) or {}).get("scenario", "")).strip()
    sections: list[dict[str, Any]] = []
    sql_log = f"DB object experiment: {scenario}"
    start = time.perf_counter()

    try:
        if scenario == "views":
            sections = [
                {
                    "title": "v_airfoil_overview",
                    "note": "Aggregated airfoil version, coordinate, performance, and anomaly counts.",
                    "rows": query_all(
                        """
                        SELECT *
                        FROM v_airfoil_overview
                        ORDER BY anomaly_count DESC, airfoil_id
                        LIMIT 8
                        """
                    ),
                },
                {
                    "title": "v_performance_with_ld",
                    "note": "Derived lift_drag_ratio（升阻比）= CL（升力系数） / CD（阻力系数） is exposed by the view.",
                    "rows": query_all(
                        """
                        SELECT airfoil_id, alpha_deg, reynolds_number, cl, cd, ROUND(lift_drag_ratio, 6) AS lift_drag_ratio
                        FROM v_performance_with_ld
                        WHERE reynolds_number = 50000
                        ORDER BY lift_drag_ratio DESC
                        LIMIT 8
                        """
                    ),
                },
                {
                    "title": "v_anomaly_details",
                    "note": "Anomaly records are joined with airfoil names and performance values.",
                    "rows": query_all(
                        """
                        SELECT anomaly_id, airfoil_id, airfoil_name, rule_type, cl, cd, ROUND(lift_drag_ratio, 6) AS lift_drag_ratio
                        FROM v_anomaly_details
                        ORDER BY anomaly_id
                        LIMIT 8
                        """
                    ),
                },
            ]
        elif scenario == "trigger_reject":
            execute_write(
                """
                INSERT INTO performance_records
                    (perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
                VALUES
                    (9200001, 'ag03', 1, 2.34, 654322, 0.100, 0.010, 0.000, 'generated_synthetic', 0)
                ON DUPLICATE KEY UPDATE
                    airfoil_id = VALUES(airfoil_id),
                    version_id = VALUES(version_id),
                    alpha_deg = VALUES(alpha_deg),
                    reynolds_number = VALUES(reynolds_number),
                    cl = VALUES(cl),
                    cd = VALUES(cd),
                    cm = VALUES(cm),
                    is_anomaly = 0
                """
            )
            execute_write("DELETE FROM anomaly_records WHERE anomaly_id = 9920001")
            expected_error = ""
            try:
                execute_write(
                    """
                    INSERT INTO anomaly_records
                        (anomaly_id, perf_id, airfoil_id, version_id, rule_type, detail)
                    VALUES
                        (9920001, 9200001, 'ag03', 1, 'negative_cd', 'frontend trigger rejection demo')
                    """
                )
            except pymysql.MySQLError as exc:
                expected_error = str(exc)
            sections = [
                {
                    "title": "Trigger rejection result",
                    "note": "The trigger should reject anomaly_records when referenced performance_records.is_anomaly = 0.",
                    "rows": [
                        {
                            "status": "rejected" if expected_error else "unexpectedly inserted",
                            "expected_error": expected_error or "none",
                        }
                    ],
                },
                {
                    "title": "Referenced performance record",
                    "rows": query_all(
                        """
                        SELECT perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, is_anomaly
                        FROM performance_records
                        WHERE perf_id = 9200001
                        """
                    ),
                },
            ]
        elif scenario == "trigger_audit":
            execute_write(
                """
                INSERT INTO performance_records
                    (perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
                VALUES
                    (9200001, 'ag03', 1, 2.34, 654322, 0.100, 0.010, 0.000, 'generated_synthetic', 0)
                ON DUPLICATE KEY UPDATE
                    cl = 0.100,
                    cd = 0.010,
                    cm = 0.000,
                    is_anomaly = 0
                """
            )
            execute_write("UPDATE performance_records SET cl = cl + 0.002 WHERE perf_id = 9200001")
            sections = [
                {
                    "title": "Updated performance record",
                    "rows": query_all(
                        """
                        SELECT perf_id, cl, cd, cm, is_anomaly
                        FROM performance_records
                        WHERE perf_id = 9200001
                        """
                    ),
                },
                {
                    "title": "Audit trigger output",
                    "note": "trg_audit_performance_update wrote old_values and new_values automatically.",
                    "rows": query_all(
                        """
                        SELECT audit_id, table_name, operation_type, record_pk, old_values, new_values, changed_at
                        FROM audit_logs
                        WHERE table_name = 'performance_records' AND record_pk = '9200001'
                        ORDER BY audit_id DESC
                        LIMIT 5
                        """
                    ),
                },
            ]
        elif scenario == "proc_summary":
            sections = [
                {
                    "title": "CALL sp_airfoil_performance_summary('ag03', 1)",
                    "rows": query_result_sets("CALL sp_airfoil_performance_summary(%s, %s)", ("ag03", 1))[0],
                },
                {
                    "title": "CALL sp_compare_airfoils_by_re(50000, 'max_ld', 10)",
                    "rows": query_result_sets("CALL sp_compare_airfoils_by_re(%s, %s, %s)", (50000, "max_ld", 10))[0],
                },
            ]
        elif scenario == "proc_import_bad":
            execute_write("DELETE FROM performance_records WHERE perf_id IN (9900101, 9900102)")
            execute_write(
                "DELETE FROM performance_import_staging WHERE batch_id COLLATE utf8mb4_unicode_ci = %s COLLATE utf8mb4_unicode_ci",
                ("demo_bad_batch",),
            )
            execute_write(
                """
                INSERT INTO performance_import_staging
                    (batch_id, perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
                VALUES
                    ('demo_bad_batch', 9900101, 'ag03', 1, 0, 123456, 0.5, 0.01, 0.0, 'generated_synthetic', 0),
                    ('demo_bad_batch', 9900102, 'ag03', 1, 99, 123456, 0.6, 0.02, 0.0, 'generated_synthetic', 0)
                """
            )
            result_sets = query_result_sets("CALL sp_import_performance_batch(%s)", ("demo_bad_batch",))
            sections = [
                {"title": "Procedure status", "rows": result_sets[0] if result_sets else []},
                {"title": "Rejected rows", "rows": result_sets[1] if len(result_sets) > 1 else []},
                {
                    "title": "Formal table verification",
                    "note": "Expected: no rows in performance_records.",
                    "rows": query_all(
                        """
                        SELECT perf_id, airfoil_id, alpha_deg, reynolds_number
                        FROM performance_records
                        WHERE perf_id IN (9900101, 9900102)
                        """
                    ),
                },
            ]
        elif scenario == "proc_import_good":
            execute_write("DELETE FROM performance_records WHERE perf_id IN (9900201, 9900202)")
            execute_write(
                "DELETE FROM performance_import_staging WHERE batch_id COLLATE utf8mb4_unicode_ci = %s COLLATE utf8mb4_unicode_ci",
                ("demo_good_batch",),
            )
            execute_write(
                """
                INSERT INTO performance_import_staging
                    (batch_id, perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
                VALUES
                    ('demo_good_batch', 9900201, 'ag03', 1, -1, 123457, 0.45, 0.012, 0.0, 'generated_synthetic', 0),
                    ('demo_good_batch', 9900202, 'ag03', 1, 1, 123457, 0.55, 0.013, 0.0, 'generated_synthetic', 0)
                """
            )
            result_sets = query_result_sets("CALL sp_import_performance_batch(%s)", ("demo_good_batch",))
            sections = [
                {"title": "Procedure status", "rows": result_sets[0] if result_sets else []},
                {
                    "title": "Imported rows in performance_records",
                    "rows": query_all(
                        """
                        SELECT perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd
                        FROM performance_records
                        WHERE perf_id IN (9900201, 9900202)
                        ORDER BY perf_id
                        """
                    ),
                },
            ]
        else:
            return jsonify({"error": "unknown scenario"}), 400
    except pymysql.MySQLError as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        log_user_action(user["user_id"], f"Failed DB object experiment {scenario}", sql_log, 0, elapsed_ms)
        return jsonify({"error": str(exc), "scenario": scenario}), 400

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    log_user_action(user["user_id"], f"Ran DB object experiment {scenario}", sql_log, 1, elapsed_ms)
    return jsonify(
        {
            "scenario": scenario,
            "elapsed_ms": elapsed_ms,
            "definition_blocks": db_object_definition_blocks(scenario),
            "sql_blocks": DB_OBJECT_EXPERIMENT_SQL.get(scenario, []),
            "sections": sections,
        }
    )


def performance_index_exists() -> bool:
    rows = query_all(
        """
        SELECT COUNT(*) AS count
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = 'performance_records'
          AND index_name = 'idx_perf_reynolds_alpha'
        """
    )
    return rows[0]["count"] > 0


@app.get("/api/index_experiment/status")
def index_experiment_status() -> Any:
    return jsonify({"exists": performance_index_exists()})


@app.get("/api/index_experiment/indexes")
def index_experiment_indexes() -> Any:
    table_name = request.args.get("table", "performance_records")
    if table_name not in INDEX_ALLOWED_TABLES:
        return jsonify({"error": "table is not allowed"}), 400
    rows = query_all(
        """
        SELECT
            INDEX_NAME AS index_name,
            NON_UNIQUE AS non_unique,
            SEQ_IN_INDEX AS seq_in_index,
            COLUMN_NAME AS column_name,
            INDEX_TYPE AS index_type
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = %s
        ORDER BY index_name, seq_in_index
        """,
        (table_name,),
    )
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = grouped.setdefault(
            row["index_name"],
            {
                "index_name": row["index_name"],
                "unique": "NO" if row["non_unique"] else "YES",
                "columns": [],
                "index_type": row["index_type"],
            },
        )
        item["columns"].append(row["column_name"])
    return jsonify(
        [
            {
                "index_name": item["index_name"],
                "unique": item["unique"],
                "columns": ", ".join(item["columns"]),
                "index_type": item["index_type"],
            }
            for item in grouped.values()
        ]
    )


@app.get("/api/index_experiment/tables")
def index_experiment_tables() -> Any:
    return jsonify(sorted(INDEX_ALLOWED_TABLES))


@app.get("/api/index_experiment/columns")
def index_experiment_columns() -> Any:
    table_name = request.args.get("table", "")
    columns = table_columns(table_name)
    if not columns:
        return jsonify({"error": "table is not allowed or has no columns"}), 400
    return jsonify(columns)


@app.post("/api/index_experiment/create")
def create_index_experiment_index() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403
    payload = request.get_json(silent=True) or {}
    table_name = str(payload.get("table", "performance_records")).strip()
    index_name = str(payload.get("index_name", "")).strip()
    columns = [str(col).strip() for col in payload.get("columns", []) if str(col).strip()]

    if table_name not in INDEX_ALLOWED_TABLES:
        return jsonify({"error": "table is not allowed"}), 400
    if not valid_identifier(index_name):
        return jsonify({"error": "invalid index name"}), 400
    valid_columns = set(table_columns(table_name))
    if not columns or any(col not in valid_columns for col in columns):
        return jsonify({"error": "invalid index columns"}), 400
    if index_name.upper() == "PRIMARY":
        return jsonify({"error": "cannot create PRIMARY here"}), 400

    column_sql = ", ".join(f"`{col}`" for col in columns)
    sql = f"CREATE INDEX `{index_name}` ON `{table_name}`({column_sql})"
    try:
        execute_write(sql)
    except pymysql.err.OperationalError as exc:
        log_user_action(user["user_id"], f"Rejected custom index creation on {table_name}", sql, 0)
        return jsonify({"error": str(exc)}), 409
    log_user_action(user["user_id"], f"Created custom index {index_name} on {table_name}", sql, 1)
    return jsonify({"ok": True, "table": table_name, "index_name": index_name, "columns": columns})


@app.post("/api/index_experiment/drop")
def drop_index_experiment_index() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403
    payload = request.get_json(silent=True) or {}
    table_name = str(payload.get("table", "performance_records")).strip()
    index_name = str(payload.get("index_name", "")).strip()
    if table_name not in INDEX_ALLOWED_TABLES:
        return jsonify({"error": "table is not allowed"}), 400
    if not valid_identifier(index_name) or index_name.upper() == "PRIMARY":
        return jsonify({"error": "invalid index name"}), 400

    sql = f"DROP INDEX `{index_name}` ON `{table_name}`"
    try:
        execute_write(sql)
    except pymysql.err.OperationalError as exc:
        log_user_action(user["user_id"], f"Rejected custom index drop on {table_name}", sql, 0)
        return jsonify({"error": str(exc)}), 409
    log_user_action(user["user_id"], f"Dropped custom index {index_name} on {table_name}", sql, 1)
    return jsonify({"ok": True, "table": table_name, "index_name": index_name})


@app.get("/api/index_experiment/run")
def run_index_experiment() -> Any:
    reynolds_number = int(request.args.get("reynolds_number", "500000"))
    sql = """
        SELECT airfoil_id, version_id, alpha_deg, cl, cd
        FROM performance_records
        WHERE reynolds_number = %s
        ORDER BY alpha_deg
    """
    explain_rows = query_all("EXPLAIN " + sql, (reynolds_number,))
    start = time.perf_counter()
    rows = query_all(sql, (reynolds_number,))
    elapsed_ms = (time.perf_counter() - start) * 1000
    return jsonify(
        {
            "reynolds_number": reynolds_number,
            "elapsed_ms": round(elapsed_ms, 3),
            "row_count": len(rows),
            "explain": explain_rows,
        }
    )


@app.post("/api/index_experiment/run_sql")
def run_index_experiment_sql() -> Any:
    user = current_user()
    if not user:
        return jsonify({"error": "login required"}), 401
    payload = request.get_json(silent=True) or {}
    sql = str(payload.get("sql", "")).strip()
    normalized = sql.rstrip(";").lstrip().lower()
    if not normalized.startswith("select") or not is_safe_select(sql):
        log_user_action(user["user_id"], "Rejected index experiment SQL", sql, 0)
        return jsonify({"error": "index experiment only accepts one SELECT statement"}), 400

    runnable_sql = sql.rstrip(";")
    try:
        explain_rows = query_all("EXPLAIN " + runnable_sql)
        start = time.perf_counter()
        rows = query_all(runnable_sql)
        elapsed_ms = (time.perf_counter() - start) * 1000
    except pymysql.MySQLError as exc:
        log_user_action(user["user_id"], "Failed index experiment SQL", sql, 0)
        return jsonify({"error": str(exc)}), 400

    log_user_action(user["user_id"], "Ran index experiment SQL", sql, 1)
    return jsonify(
        {
            "elapsed_ms": round(elapsed_ms, 3),
            "row_count": len(rows),
            "rows": rows[:100],
            "explain": explain_rows,
        }
    )


@app.post("/api/transaction_experiment/run")
def run_transaction_experiment() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403

    payload = request.get_json(silent=True) or {}
    sql_text = str(payload.get("sql", "")).strip()
    mode = str(payload.get("mode", "rollback")).strip().lower()
    if mode not in {"commit", "rollback"}:
        return jsonify({"error": "mode must be commit or rollback"}), 400

    statements = split_sql_statements(sql_text)
    if not statements:
        return jsonify({"error": "transaction SQL is empty"}), 400
    if len(statements) > 20:
        return jsonify({"error": "at most 20 statements per transaction"}), 400
    if any(not is_allowed_transaction_sql(statement) for statement in statements):
        log_user_action(user["user_id"], "Rejected transaction experiment", sql_text, 0)
        return jsonify({"error": "transaction experiment only allows SELECT/INSERT/UPDATE/DELETE, and cannot touch users/query_logs or DDL"}), 400

    conn = pymysql.connect(**db_config(), autocommit=False)
    results: list[dict[str, Any]] = []
    start = time.perf_counter()
    status = "rolled back"
    try:
        with conn.cursor() as cur:
            cur.execute("START TRANSACTION")
            for index, statement in enumerate(statements, start=1):
                statement_start = time.perf_counter()
                affected = cur.execute(statement)
                elapsed_ms = (time.perf_counter() - statement_start) * 1000
                if statement.lstrip().lower().startswith("select "):
                    rows = list(cur.fetchall())
                    results.append(
                        {
                            "step": index,
                            "type": "SELECT",
                            "sql": statement,
                            "row_count": len(rows),
                            "affected_rows": None,
                            "elapsed_ms": round(elapsed_ms, 3),
                            "rows": rows[:50],
                        }
                    )
                else:
                    results.append(
                        {
                            "step": index,
                            "type": statement.split(None, 1)[0].upper(),
                            "sql": statement,
                            "row_count": 0,
                            "affected_rows": int(affected),
                            "elapsed_ms": round(elapsed_ms, 3),
                            "rows": [],
                        }
                    )

        if mode == "commit":
            conn.commit()
            status = "committed"
        else:
            conn.rollback()
            status = "rolled back"
    except pymysql.MySQLError as exc:
        conn.rollback()
        elapsed_total = (time.perf_counter() - start) * 1000
        log_user_action(user["user_id"], "Failed transaction experiment", sql_text, 0, int(elapsed_total))
        return jsonify({"error": str(exc), "status": "rolled back", "results": results}), 400
    finally:
        conn.close()

    elapsed_total = (time.perf_counter() - start) * 1000
    log_user_action(user["user_id"], f"Transaction experiment {status}", sql_text, 1, int(elapsed_total))
    return jsonify(
        {
            "status": status,
            "mode": mode,
            "statement_count": len(statements),
            "elapsed_ms": round(elapsed_total, 3),
            "results": results,
        }
    )


@app.post("/api/transaction_experiment/run_queue")
def run_transaction_queue() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403

    payload = request.get_json(silent=True) or {}
    mode = str(payload.get("mode", "rollback")).strip().lower()
    if mode not in {"commit", "rollback"}:
        return jsonify({"error": "mode must be commit or rollback"}), 400

    saved_ids_raw = payload.get("saved_ids", [])
    if not isinstance(saved_ids_raw, list):
        return jsonify({"error": "saved_ids must be an ordered list"}), 400
    try:
        saved_ids = [int(x) for x in saved_ids_raw if int(x or 0) > 0]
    except (TypeError, ValueError):
        return jsonify({"error": "saved_ids must contain numeric ids"}), 400
    if not saved_ids:
        return jsonify({"error": "transaction queue is empty"}), 400
    if len(saved_ids) > 10:
        return jsonify({"error": "at most 10 saved transactions per queue run"}), 400

    placeholders = ",".join(["%s"] * len(saved_ids))
    saved_rows = query_all(
        f"""
        SELECT saved_id, title, sql_text
        FROM saved_transactions
        WHERE user_id = %s AND saved_id IN ({placeholders})
        """,
        tuple([user["user_id"], *saved_ids]),
    )
    saved_by_id = {int(row["saved_id"]): row for row in saved_rows}
    missing = [saved_id for saved_id in saved_ids if saved_id not in saved_by_id]
    if missing:
        return jsonify({"error": f"saved transaction not found or not yours: {missing}"}), 404

    ordered_transactions = [saved_by_id[saved_id] for saved_id in saved_ids]
    timeline: list[dict[str, Any]] = []
    transaction_results: list[dict[str, Any]] = []
    start = time.perf_counter()

    def add_event(queue_index: int, title: str, event: str, status: str = "ok", elapsed_ms: float | None = None, detail: str = "") -> None:
        timeline.append(
            {
                "at_ms": round((time.perf_counter() - start) * 1000, 3),
                "queue_step": queue_index,
                "transaction": title,
                "event": event,
                "status": status,
                "elapsed_ms": None if elapsed_ms is None else round(elapsed_ms, 3),
                "detail": detail,
            }
        )

    final_status = "rolled back" if mode == "rollback" else "committed"
    for queue_index, item in enumerate(ordered_transactions, start=1):
        title = str(item["title"])
        sql_text = str(item["sql_text"])
        statements = split_sql_statements(sql_text)
        if not statements:
            return jsonify({"error": f"{title}: transaction SQL is empty"}), 400
        if len(statements) > 20:
            return jsonify({"error": f"{title}: at most 20 statements per transaction"}), 400
        if any(not is_allowed_transaction_sql(statement) for statement in statements):
            log_user_action(user["user_id"], "Rejected transaction queue", sql_text, 0)
            return jsonify({"error": f"{title}: only SELECT/INSERT/UPDATE/DELETE are allowed"}), 400

        conn = pymysql.connect(**db_config(), autocommit=False)
        results: list[dict[str, Any]] = []
        tx_start = time.perf_counter()
        try:
            with conn.cursor() as cur:
                cur.execute("START TRANSACTION")
                add_event(queue_index, title, "BEGIN")
                for stmt_index, statement in enumerate(statements, start=1):
                    statement_start = time.perf_counter()
                    affected = cur.execute(statement)
                    elapsed_ms = (time.perf_counter() - statement_start) * 1000
                    statement_type = statement.split(None, 1)[0].upper()
                    if statement.lstrip().lower().startswith("select "):
                        rows = list(cur.fetchall())
                        results.append(
                            {
                                "queue_step": queue_index,
                                "step": stmt_index,
                                "type": "SELECT",
                                "sql": statement,
                                "row_count": len(rows),
                                "affected_rows": None,
                                "elapsed_ms": round(elapsed_ms, 3),
                                "rows": rows[:50],
                            }
                        )
                        add_event(queue_index, title, f"SQL {stmt_index}: SELECT", "ok", elapsed_ms, f"rows={len(rows)}")
                    else:
                        results.append(
                            {
                                "queue_step": queue_index,
                                "step": stmt_index,
                                "type": statement_type,
                                "sql": statement,
                                "row_count": 0,
                                "affected_rows": int(affected),
                                "elapsed_ms": round(elapsed_ms, 3),
                                "rows": [],
                            }
                        )
                        add_event(queue_index, title, f"SQL {stmt_index}: {statement_type}", "ok", elapsed_ms, f"affected={int(affected)}")

            if mode == "commit":
                commit_start = time.perf_counter()
                conn.commit()
                add_event(queue_index, title, "COMMIT", "ok", (time.perf_counter() - commit_start) * 1000)
                tx_status = "committed"
            else:
                rollback_start = time.perf_counter()
                conn.rollback()
                add_event(queue_index, title, "ROLLBACK", "ok", (time.perf_counter() - rollback_start) * 1000)
                tx_status = "rolled back"
            transaction_results.append(
                {
                    "queue_step": queue_index,
                    "saved_id": int(item["saved_id"]),
                    "title": title,
                    "status": tx_status,
                    "statement_count": len(statements),
                    "elapsed_ms": round((time.perf_counter() - tx_start) * 1000, 3),
                    "results": results,
                }
            )
        except pymysql.MySQLError as exc:
            conn.rollback()
            add_event(queue_index, title, "ROLLBACK after error", "failed", detail=str(exc))
            transaction_results.append(
                {
                    "queue_step": queue_index,
                    "saved_id": int(item["saved_id"]),
                    "title": title,
                    "status": "rolled back",
                    "statement_count": len(statements),
                    "elapsed_ms": round((time.perf_counter() - tx_start) * 1000, 3),
                    "results": results,
                    "error": str(exc),
                }
            )
            final_status = "failed"
            elapsed_total = (time.perf_counter() - start) * 1000
            log_user_action(user["user_id"], "Failed transaction queue", " -> ".join(row["title"] for row in ordered_transactions), 0, int(elapsed_total))
            conn.close()
            return jsonify(
                {
                    "status": final_status,
                    "mode": mode,
                    "elapsed_ms": round(elapsed_total, 3),
                    "queue_count": len(saved_ids),
                    "timeline": timeline,
                    "transactions": transaction_results,
                    "error": str(exc),
                }
            ), 400
        finally:
            if conn.open:
                conn.close()

    elapsed_total = (time.perf_counter() - start) * 1000
    log_user_action(user["user_id"], f"Transaction queue {final_status}", " -> ".join(row["title"] for row in ordered_transactions), 1, int(elapsed_total))
    return jsonify(
        {
            "status": final_status,
            "mode": mode,
            "elapsed_ms": round(elapsed_total, 3),
            "queue_count": len(saved_ids),
            "timeline": timeline,
            "transactions": transaction_results,
        }
    )


@app.post("/api/transaction_experiment/concurrency")
def run_concurrency_experiment() -> Any:
    user = current_user()
    if not user or not is_manager(user["role"]):
        return jsonify({"error": "engineer/admin permission required"}), 403

    perf_id = int((request.get_json(silent=True) or {}).get("perf_id", 9100001))
    setup_sql = """
        INSERT INTO performance_records
            (perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
        VALUES
            (%s, 'ag03', 1, 1.23, 654321, 0.100, 0.010, 0.000, 'generated_synthetic', 0)
        ON DUPLICATE KEY UPDATE
            cl = 0.100,
            cd = 0.010,
            cm = 0.000,
            is_anomaly = 0
    """
    execute_write(setup_sql, (perf_id,))

    steps: list[dict[str, Any]] = []
    errors: list[str] = []
    steps_lock = threading.Lock()
    start_time = time.perf_counter()

    def add_step(actor: str, event: str, elapsed_ms: float | None = None) -> None:
        with steps_lock:
            steps.append(
                {
                    "actor": actor,
                    "event": event,
                    "elapsed_ms": None if elapsed_ms is None else round(elapsed_ms, 3),
                    "at_ms": round((time.perf_counter() - start_time) * 1000, 3),
                }
            )

    def tx_a() -> None:
        conn = pymysql.connect(**db_config(), autocommit=False)
        try:
            with conn.cursor() as cur:
                cur.execute("SET innodb_lock_wait_timeout = 8")
                cur.execute("START TRANSACTION")
                add_step("User A", "BEGIN")
                began = time.perf_counter()
                cur.execute("UPDATE performance_records SET cl = 0.111 WHERE perf_id = %s", (perf_id,))
                add_step("User A", "UPDATE cl = 0.111; row lock is held for 2 seconds", (time.perf_counter() - began) * 1000)
                time.sleep(2)
                conn.commit()
                add_step("User A", "COMMIT, row lock released")
        except pymysql.MySQLError as exc:
            conn.rollback()
            errors.append(f"User A: {exc}")
            add_step("User A", "ROLLBACK after error")
        finally:
            conn.close()

    def tx_b() -> None:
        time.sleep(0.3)
        conn = pymysql.connect(**db_config(), autocommit=False)
        try:
            with conn.cursor() as cur:
                cur.execute("SET innodb_lock_wait_timeout = 8")
                cur.execute("START TRANSACTION")
                add_step("User B", "BEGIN")
                began = time.perf_counter()
                cur.execute("UPDATE performance_records SET cl = 0.222 WHERE perf_id = %s", (perf_id,))
                add_step("User B", "UPDATE cl = 0.222; waited for User A row lock", (time.perf_counter() - began) * 1000)
                conn.commit()
                add_step("User B", "COMMIT")
        except pymysql.MySQLError as exc:
            conn.rollback()
            errors.append(f"User B: {exc}")
            add_step("User B", "ROLLBACK after error")
        finally:
            conn.close()

    thread_a = threading.Thread(target=tx_a)
    thread_b = threading.Thread(target=tx_b)
    thread_a.start()
    thread_b.start()
    thread_a.join()
    thread_b.join()
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    final_rows = query_all(
        """
        SELECT perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm
        FROM performance_records
        WHERE perf_id = %s
        """,
        (perf_id,),
    )
    is_valid = 0 if errors else 1
    log_user_action(
        user["user_id"],
        "Concurrency experiment: two users update one performance record",
        f"User A and User B update performance_records.perf_id = {perf_id}",
        is_valid,
        int(elapsed_ms),
    )
    return jsonify(
        {
            "perf_id": perf_id,
            "status": "failed" if errors else "completed",
            "elapsed_ms": round(elapsed_ms, 3),
            "steps": steps,
            "errors": errors,
            "final_rows": final_rows,
        }
    )


INDEX_HTML = r"""
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Airfoil Database</title>
  <style>
    :root {
      --bg:#edf1ee;
      --shell:#191d1b;
      --shell-2:#232823;
      --panel:#ffffff;
      --panel-soft:#f7f8f4;
      --panel-warm:#fffaf0;
      --line:#d8ded7;
      --line-strong:#aeb9ae;
      --ink:#20251f;
      --muted:#657066;
      --accent:#16746b;
      --accent-2:#b46f19;
      --danger:#b42318;
      --ok:#2f7a39;
      --shadow:0 18px 44px rgba(33,38,31,.14);
      --mono:Consolas,"SFMono-Regular","Liberation Mono",monospace;
      --ui:"Segoe UI",Arial,"Microsoft YaHei",sans-serif;
    }
    * { box-sizing:border-box; }
    html,body { height:100%; }
    body {
      margin:0;
      font-family:var(--ui);
      font-size:14px;
      color:var(--ink);
      background:
        linear-gradient(135deg,rgba(22,116,107,.10),transparent 34%),
        linear-gradient(315deg,rgba(180,111,25,.11),transparent 30%),
        var(--bg);
      letter-spacing:0;
    }
    body::before {
      content:"";
      position:fixed;
      inset:0;
      pointer-events:none;
      background-image:
        linear-gradient(rgba(32,37,31,.045) 1px,transparent 1px),
        linear-gradient(90deg,rgba(32,37,31,.04) 1px,transparent 1px);
      background-size:36px 36px;
      mask-image:linear-gradient(180deg,rgba(0,0,0,.72),rgba(0,0,0,.08));
    }
    h1,h2 { margin:0; letter-spacing:0; }
    h1 { font-size:24px; line-height:1.15; font-weight:760; }
    h2 { margin:0 0 10px; font-size:15px; line-height:1.25; font-weight:720; }
    .sub,.status { color:var(--muted); font-size:13px; line-height:1.45; overflow-wrap:anywhere; }
    #airfoilMeta { display:block; line-height:1.55; }
    #airfoilMeta b { color:#3a4338; font-weight:700; }
    .authGate {
      position:fixed;
      inset:0;
      z-index:1000;
      min-height:100vh;
      display:grid;
      place-items:center;
      padding:24px;
      overflow:auto;
      background:
        linear-gradient(135deg,#181d1a 0%,#2f3328 48%,#efe9dc 100%);
    }
    .authCard {
      width:min(500px,100%);
      background:rgba(255,255,255,.92);
      border:1px solid rgba(255,255,255,.72);
      border-radius:8px;
      padding:26px;
      box-shadow:0 28px 70px rgba(0,0,0,.28);
      display:grid;
      gap:14px;
      backdrop-filter:blur(14px);
    }
    .authCard h1 { font-size:28px; }
    .authActions { display:flex; gap:10px; flex-wrap:wrap; }
    .app {
      height:100vh;
      min-height:0;
      display:none;
      grid-template-columns:330px minmax(0,1fr);
      overflow:hidden;
      position:relative;
    }
    .app.visible { display:grid; }
    .app.noAside { grid-template-columns:minmax(0,1fr); }
    .app.noAside aside { display:none; }
    aside {
      height:100vh;
      min-height:0;
      padding:20px;
      display:grid;
      grid-template-rows:auto auto minmax(0,1fr);
      gap:14px;
      overflow:hidden;
      color:#f5f6ef;
      background:
        linear-gradient(180deg,rgba(255,255,255,.06),rgba(255,255,255,.02)),
        var(--shell);
      border-right:1px solid rgba(255,255,255,.10);
      box-shadow:18px 0 42px rgba(23,27,23,.18);
    }
    aside h1 { color:#fffaf0; }
    aside .sub, aside .status { color:#c1cabb; }
    main {
      height:100vh;
      min-width:0;
      min-height:0;
      padding:0 20px 28px;
      display:block;
      overflow-y:auto;
      overflow-x:hidden;
      scroll-behavior:smooth;
    }
    input,select,textarea {
      border:1px solid var(--line);
      border-radius:6px;
      background:#fff;
      color:var(--ink);
      padding:9px 11px;
      outline:none;
      min-width:0;
      font-size:14px;
      font-family:var(--ui);
      transition:border-color .16s ease, box-shadow .16s ease, background .16s ease;
    }
    input:focus,select:focus,textarea:focus {
      border-color:var(--accent);
      box-shadow:0 0 0 3px rgba(22,116,107,.14);
    }
    textarea {
      min-height:78px;
      resize:vertical;
      font-family:var(--mono);
      font-size:13px;
      line-height:1.5;
    }
    button.action,.tabBtn {
      min-height:36px;
      border:1px solid var(--line);
      border-radius:6px;
      background:#fff;
      color:var(--ink);
      padding:0 12px;
      cursor:pointer;
      font-size:14px;
      font-family:var(--ui);
      display:inline-flex;
      align-items:center;
      justify-content:center;
      gap:6px;
      transition:transform .14s ease, border-color .14s ease, background .14s ease, color .14s ease, box-shadow .14s ease;
    }
    button.action:hover,.tabBtn:hover { transform:translateY(-1px); border-color:var(--line-strong); box-shadow:0 8px 18px rgba(33,38,31,.10); }
    button.primary,.tabBtn.active { background:var(--accent); border-color:var(--accent); color:#fff; box-shadow:0 10px 24px rgba(22,116,107,.22); }
    .search {
      width:100%;
      height:40px;
      color:#f5f6ef;
      background:rgba(255,255,255,.08);
      border-color:rgba(255,255,255,.18);
    }
    .search::placeholder { color:#aeb9ae; }
    .search:focus { background:rgba(255,255,255,.12); border-color:#7bc6bc; box-shadow:0 0 0 3px rgba(123,198,188,.18); }
    .list {
      min-height:0;
      overflow-y:auto;
      overflow-x:hidden;
      border:1px solid rgba(255,255,255,.14);
      background:rgba(255,255,255,.06);
      border-radius:8px;
    }
    .item {
      width:100%;
      min-height:62px;
      display:grid;
      grid-template-columns:minmax(0,1fr) auto;
      gap:10px;
      border:0;
      border-bottom:1px solid rgba(255,255,255,.10);
      background:transparent;
      padding:12px;
      text-align:left;
      cursor:pointer;
      color:#f7f7f0;
    }
    .item:hover,.item.active { background:rgba(22,116,107,.22); }
    .item.active { box-shadow:inset 3px 0 0 #7bc6bc; }
    .item strong { display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:14px; }
    .item span { color:#c1cabb; font-size:12px; }
    .badge { align-self:start; border-radius:999px; background:#fffaf0; padding:3px 8px; font-size:12px; color:#473312; font-weight:700; }
    .pageTabs {
      position:sticky;
      top:0;
      z-index:100;
      display:flex;
      flex-wrap:wrap;
      gap:8px;
      align-items:center;
      margin:0 -20px 16px;
      padding:14px 20px;
      background:#edf1ee;
      border-bottom:1px solid rgba(174,185,174,.72);
      box-shadow:0 8px 18px rgba(33,38,31,.08);
      overflow:hidden;
      isolation:isolate;
    }
    .pageTabs::before {
      content:"";
      position:absolute;
      inset:0;
      z-index:-1;
      background:#edf1ee;
    }
    .pageTabs .userMenu { margin-left:auto; }
    .tabBtn { min-height:38px; padding:0 14px; line-height:1; }
    .page { min-height:0; display:none; gap:14px; align-content:start; }
    .page.active { display:grid; }
    .splitPage { grid-template-columns:minmax(360px,.9fr) minmax(460px,1.1fr); align-items:start; }
    #pageIndex.splitPage { grid-template-columns:1fr; }
    .panel,.titlebar,.versionBox,section,.page > .experiment {
      background:rgba(255,255,255,.90);
      border:1px solid rgba(216,222,215,.95);
      border-radius:8px;
      padding:14px;
      box-shadow:var(--shadow);
      backdrop-filter:blur(10px);
    }
    .panel { display:grid; gap:12px; }
    .toolbar { display:flex; gap:10px; align-items:center; justify-content:space-between; margin-bottom:10px; min-width:0; }
    .toolbar h2 { margin:0; flex:0 0 auto; }
    .chartSection .toolbar .status { text-align:right; max-width:72%; }
    .userMenu { display:none; align-items:center; justify-content:flex-end; gap:10px; min-width:0; }
    .userMenu .status { white-space:nowrap; }
    .top { display:grid; grid-template-columns:minmax(0,1fr) minmax(260px,340px); gap:14px; align-items:stretch; }
    .titlebar {
      min-height:92px;
      display:flex;
      flex-direction:column;
      justify-content:center;
      background:
        linear-gradient(135deg,rgba(22,116,107,.14),rgba(255,250,240,.90) 42%,rgba(180,111,25,.12)),
        #fff;
    }
    .versionBox { display:grid; grid-template-columns:auto minmax(190px,1fr); gap:10px; align-items:center; min-height:92px; }
    .versionBox h2 { margin:0; }
    .versionBox select { width:100%; }
    .formRow { display:grid; grid-template-columns:160px 160px auto; gap:8px; align-items:center; }
    .sqlRow { display:grid; grid-template-columns:minmax(220px,260px) minmax(0,1fr) auto; gap:10px; align-items:start; }
    .adminPanel,.editorPanel,.transactionPanel,.dbObjectPanel,.batchPanel,.governancePanel { display:none; border-top:1px solid var(--line); padding-top:12px; gap:10px; }
    .adminPanel.visible,.editorPanel.visible,.transactionPanel.visible,.dbObjectPanel.visible,.batchPanel.visible,.governancePanel.visible { display:grid; }
    .createRow { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)) auto; gap:8px; align-items:center; }
    .grid { min-height:0; display:grid; grid-template-columns:repeat(2,minmax(360px,1fr)); grid-auto-rows:auto; gap:14px; }
    section { min-height:0; overflow:hidden; display:grid; grid-template-rows:auto minmax(0,1fr); }
    .chartSection { position:relative; height:320px; }
    .wideChartSection { grid-column:1 / -1; height:390px; }
    .compareScroll,.versionDiffScroll { min-height:0; height:100%; overflow-y:auto; overflow-x:hidden; border:1px solid var(--line); border-radius:6px; background:#fffdfa; }
    .compareScroll canvas,.versionDiffScroll canvas { display:block; border:0; border-radius:0; }
    .versionInfoSection { grid-column:1 / -1; }
    .anomalySection { grid-column:1 / -1; min-height:260px; }
    .shapeSection { height:370px; grid-template-rows:auto auto minmax(0,1fr); }
    .shapeLegend { display:flex; flex-wrap:wrap; gap:10px 16px; align-items:center; margin:2px 0 10px; padding:8px 10px; border:1px solid rgba(29,79,72,.12); border-radius:6px; background:rgba(255,253,250,.82); color:#435046; font-size:13px; }
    .legendItem { display:inline-flex; align-items:center; gap:6px; white-space:nowrap; font-weight:700; }
    .legendMark { width:22px; height:0; border-top:3px solid currentColor; display:inline-block; }
    .legendDiamond { width:9px; height:9px; display:inline-block; background:currentColor; transform:rotate(45deg); }
    .legendRing { width:10px; height:10px; display:inline-block; border:2px solid currentColor; border-radius:50%; background:transparent; }
    canvas { width:100%; height:100%; border:1px solid var(--line); border-radius:6px; background:#fffdfa; }
    .chartTooltip {
      position:absolute;
      display:none;
      pointer-events:none;
      z-index:5;
      max-width:220px;
      border:1px solid var(--line);
      border-radius:6px;
      background:rgba(255,255,255,.96);
      box-shadow:0 14px 30px rgba(33,38,31,.18);
      padding:7px 9px;
      font-family:var(--mono);
      font-size:12px;
      line-height:1.38;
      color:var(--ink);
    }
    #shapeTooltip { max-width:190px; }
    .metrics { display:grid; grid-template-columns:repeat(6,minmax(0,1fr)); grid-auto-rows:78px; gap:8px; align-content:start; }
    .metric {
      border:1px solid var(--line);
      border-radius:6px;
      padding:10px;
      background:linear-gradient(180deg,#fff,#f8faf5);
      display:flex;
      flex-direction:column;
      justify-content:center;
    }
    .metric b { font-size:21px; line-height:1.1; color:#173c37; }
    .metric span { color:var(--muted); font-size:13px; }
    .versionContent { min-height:0; overflow:auto; display:grid; align-content:start; gap:12px; }
    .experiment { border-top:1px solid var(--line); padding-top:12px; display:grid; gap:10px; }
    #pageDbObjects,
    #pageDbObjects .experiment {
      min-width:0;
      max-width:100%;
    }
    .indexSqlPanel { min-height:0; display:grid; grid-template-rows:auto auto auto minmax(0,1fr); gap:10px; }
    .experimentControls { display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
    .iconAction { min-width:42px; font-size:22px; font-weight:700; line-height:1; }
    .iconAction.dangerIcon { color:var(--danger); }
    .rowDeleteBtn { min-width:30px; min-height:28px; padding:0 8px; color:var(--danger); font-weight:700; }
    .indexForm { display:none; gap:8px; border:1px solid var(--line); border-radius:6px; background:var(--panel-soft); padding:10px; }
    .indexForm.visible { display:grid; }
    .compactIndexForm.visible { grid-template-columns:minmax(220px,320px) minmax(0,1fr) auto; align-items:start; }
    .compactIndexForm .status { grid-column:1 / -1; margin:0; }
    .compactIndexForm .indexColumnBox { max-height:74px; }
    #indexList { max-height:420px; min-height:260px; }
    .indexColumnBox { max-height:120px; overflow:auto; border:1px solid var(--line); border-radius:6px; background:#fff; padding:8px; }
    .keyFilterBox { max-height:none; display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:10px; }
    .keyFilter { display:grid; gap:5px; align-content:start; }
    .keyFilter span { font-size:13px; color:var(--muted); }
    .glossaryStrip {
      grid-column:1 / -1;
      display:flex;
      flex-wrap:wrap;
      gap:8px;
      align-items:center;
      padding:10px 12px;
      border:1px solid rgba(22,116,107,.16);
      border-radius:8px;
      background:
        linear-gradient(135deg,rgba(22,116,107,.10),rgba(255,255,255,.88) 42%,rgba(180,111,25,.10)),
        rgba(255,255,255,.88);
      box-shadow:0 14px 30px rgba(33,38,31,.08);
    }
    .glossaryStrip .status { margin-right:2px; font-weight:650; color:#34423b; }
    .fieldGlossary { display:flex; flex-wrap:wrap; gap:6px; margin-top:6px; }
    .termLabel { display:inline-flex; flex-wrap:wrap; gap:5px; align-items:baseline; line-height:1.25; }
    .termLabel .termCode { color:#172033; font-weight:720; font-family:var(--mono); }
    .termLabel .termZh { color:var(--accent); font-size:12px; font-weight:650; }
    .termHint {
      display:inline-flex;
      align-items:center;
      min-height:22px;
      border:1px solid rgba(22,116,107,.18);
      border-radius:999px;
      background:rgba(22,116,107,.08);
      color:#245c55;
      padding:2px 8px;
      font-size:12px;
      font-weight:650;
      box-shadow:inset 0 1px 0 rgba(255,255,255,.72);
    }
    .keyFilter select { width:100%; }
    .inlineEditCell { background:var(--panel-soft); padding:12px 14px; white-space:normal; }
    .inlineEditBox { display:grid; gap:10px; min-width:720px; }
    .inlineEditGrid { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:8px; }
    .inlineEditGrid label { display:grid; gap:5px; color:var(--muted); font-size:13px; }
    .inlineEditGrid input,.inlineEditGrid select,.inlineEditGrid textarea { width:100%; }
    .inlineEditGrid textarea { min-height:72px; resize:vertical; grid-column:1 / -1; }
    .inlineEditActions { display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
    .indexSqlArea { width:100%; min-height:150px; }
    .transactionArea { width:100%; min-height:130px; }
    .box {
      max-height:260px;
      overflow:auto;
      border:1px solid var(--line);
      border-radius:6px;
      background:#fffdfa;
      padding:10px;
      font-family:var(--mono);
      font-size:13px;
      line-height:1.48;
      white-space:normal;
    }
    .box h2 { margin:8px 0 6px; font-size:15px; font-family:var(--ui); }
    .transactionQueueBox { display:grid; gap:8px; border:1px solid var(--line); border-radius:6px; background:rgba(255,255,255,.72); padding:10px; }
    .queueList { display:grid; gap:6px; max-height:160px; overflow:auto; }
    .queueItem { display:grid; grid-template-columns:auto minmax(0,1fr) auto auto auto; gap:8px; align-items:center; border:1px solid var(--line); border-radius:6px; background:#fff; padding:7px 8px; }
    .queueItem strong { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .queueItem .status { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .txnChartWrap { overflow:auto; border:1px solid var(--line); border-radius:6px; background:#fffdfa; padding:10px; margin:8px 0 12px; }
    .txnSvg { display:block; min-width:860px; width:100%; height:auto; font-family:var(--ui); }
    .txnSvg text { fill:#536174; font-size:12px; }
    .txnSvg .laneLabel { fill:#172033; font-weight:700; font-size:13px; }
    .txnSvg .axis { stroke:#cfd8e6; stroke-width:1; }
    .txnSvg .gridLine { stroke:#e6ebf2; stroke-width:1; }
    .txnSvg .txnDurationBar { fill:#1f766f; opacity:.92; filter:drop-shadow(0 2px 3px rgba(31,118,111,.25)); }
    #transactionResult { max-height:none; min-height:300px; }
    #dbObjectResult {
      width:100%;
      max-width:100%;
      min-width:0;
      max-height:none;
      min-height:520px;
      overflow:visible;
      font-family:var(--ui);
      font-size:14px;
      line-height:1.55;
    }
    #dbObjectResult .tableWrap {
      width:100%;
      max-width:100%;
      min-width:0;
      display:block;
      max-height:none;
      overflow:auto;
      padding-bottom:10px;
      scrollbar-gutter:stable both-edges;
    }
    #dbObjectResult table { min-width:max-content; }
    #dbObjectResult .sqlBlock {
      margin:10px 0 12px;
      border:1px solid var(--line);
      border-radius:6px;
      background:rgba(255,255,255,.76);
      overflow:hidden;
    }
    #dbObjectResult .sqlBlock summary {
      cursor:pointer;
      list-style:none;
      padding:10px 12px;
      color:#263229;
      font-family:var(--ui);
      font-weight:680;
      border-bottom:1px solid transparent;
    }
    #dbObjectResult .sqlBlock summary::-webkit-details-marker { display:none; }
    #dbObjectResult .sqlBlock summary::before { content:"+"; display:inline-block; width:16px; color:var(--accent); }
    #dbObjectResult .sqlBlock[open] summary { border-bottom-color:var(--line); }
    #dbObjectResult .sqlBlock[open] summary::before { content:"-"; }
    #dbObjectResult pre {
      margin:0;
      max-height:300px;
      overflow:auto;
      white-space:pre-wrap;
      overflow-wrap:anywhere;
      word-break:break-word;
      border:0;
      background:#fff;
      padding:10px 12px;
      font-family:Consolas,monospace;
      font-size:12px;
      line-height:1.5;
      color:#172033;
    }
    #dbObjectResult .sqlBlock pre,
    #governanceResult .sqlBlock pre {
      white-space:pre-wrap;
      overflow-x:auto;
      overflow-wrap:anywhere;
      word-break:break-word;
      font-family:Consolas,var(--mono);
    }
    #adminReviewFilterBox { display:none; margin-bottom:10px; }
    #adminReviewFilterBox.visible { display:grid; }
    #adminResult { max-height:none; height:calc(100vh - 260px); min-height:420px; overflow:auto; }
    #adminResult .tableWrap { max-height:calc(100vh - 340px); overflow:auto; padding-bottom:8px; scrollbar-gutter:stable both-edges; }
    #adminResult table { min-width:max-content; }
    #governanceResult { max-height:none; height:calc(100vh - 260px); min-height:360px; overflow:auto; }
    #mainTableResult { max-height:none; min-height:360px; overflow:auto; }
    #governanceResult .tableWrap,#mainTableResult .tableWrap { max-height:calc(100vh - 350px); overflow:auto; padding-bottom:8px; }
    .tableWrap { overflow:auto; border:1px solid var(--line); border-radius:6px; max-width:100%; padding-bottom:6px; background:#fff; }
    table { width:100%; min-width:max-content; border-collapse:collapse; font-size:13px; background:#fff; }
    th,td { border-bottom:1px solid var(--line); padding:9px 10px; text-align:left; white-space:nowrap; }
    th { position:sticky; top:0; background:#f1f4ef; z-index:1; color:#3a4338; }
    tbody tr:hover td { background:#fbf7ec; }
    .panel:hover,.chartSection:hover,.versionInfoSection:hover,main > section:hover {
      border-color:rgba(22,116,107,.24);
      box-shadow:0 20px 48px rgba(33,38,31,.16);
    }
    .rowActions { display:flex; gap:6px; align-items:center; }
    .rowActions .rowDeleteBtn { color:var(--danger); border-color:#efc2bd; }
    .danger { color:var(--danger); font-weight:700; }
    .chartSection::before {
      content:"";
      position:absolute;
      inset:10px 10px auto auto;
      width:76px;
      height:2px;
      border-radius:999px;
      background:linear-gradient(90deg,var(--accent),var(--accent-2));
      opacity:.72;
    }
    .page.active > .panel,
    .page.active > .governancePanel,
    .page.active > .batchPanel,
    .page.active > .transactionPanel,
    .page.active > .dbObjectPanel,
    .page.active > .adminPanel {
      animation:panelRise .28s ease both;
    }
    @keyframes panelRise {
      from { opacity:.72; transform:translateY(8px); }
      to { opacity:1; transform:translateY(0); }
    }
    @media (max-width:1100px){
      .app{grid-template-columns:1fr;}
      aside{height:auto;min-height:360px;border-right:0;border-bottom:1px solid rgba(255,255,255,.14);}
      main{height:100vh;min-height:0;overflow-y:auto;}
      .grid,.splitPage{grid-template-columns:1fr;grid-template-rows:auto;}
      .top,.formRow,.sqlRow,.createRow{grid-template-columns:1fr;}
      .userMenu{justify-content:flex-start; flex-wrap:wrap;}
      .metrics{grid-template-columns:repeat(2,minmax(0,1fr));}
      .pageTabs{position:sticky;top:0;margin:0 -20px 16px;background:#edf1ee;z-index:200;}
    }
  </style>
</head>
<body data-ui-redesign="aurora-command">
<div class="authGate" id="authGate">
  <div class="authCard">
    <div>
      <h1>翼型数据库系统</h1>
      <div class="sub">登录后进入数据库界面；公开注册仅创建只读用户。</div>
    </div>
    <input id="gateName" placeholder="username">
    <input id="gatePassword" type="password" placeholder="password">
    <div class="authActions">
      <button class="action primary" id="gateLoginBtn" onclick="gateLogin()">登录</button>
      <button class="action" id="gateRegisterBtn" onclick="gateRegisterViewer()">注册只读用户</button>
    </div>
    <div class="box" id="gateMessage">管理员账号由服务器预先创建。</div>
  </div>
</div>
<div class="app" id="appShell">
  <aside>
    <div><h1>翼型数据库</h1><div class="sub" id="summary">读取数据库中</div></div>
    <input class="search" id="search" placeholder="搜索 airfoil_id 或名称">
    <div class="list" id="airfoilList"></div>
  </aside>
  <main>
    <div class="pageTabs">
      <button class="tabBtn active" data-tab="overview">总览驾驶舱</button>
      <button class="tabBtn" data-tab="governance">数据治理</button>
      <button class="tabBtn" data-tab="batch">批量导入</button>
      <button class="tabBtn" data-tab="sql">SQL 工作台</button>
      <button class="tabBtn" data-tab="index">索引实验</button>
      <button class="tabBtn" data-tab="transaction">事务实验</button>
      <button class="tabBtn" data-tab="dbobjects">数据库对象</button>
      <button class="tabBtn" data-tab="admin">管理审计</button>
    </div>
    <div class="page active fullPage" id="pageOverview"></div>
    <div class="page fullPage" id="pageSql"></div>
    <div class="page splitPage" id="pageIndex"></div>
    <div class="page fullPage" id="pageTransaction"></div>
    <div class="page fullPage" id="pageDbObjects"></div>
    <div class="page fullPage" id="pageBatch"></div>
    <div class="page fullPage" id="pageGovernance"></div>
    <div class="page fullPage" id="pageAdmin"></div>
    <div class="panel">
      <div class="toolbar">
        <h2>User & QueryLog</h2>
        <div class="userMenu" id="loggedInBar">
          <div class="status" id="userStatus">Not logged in</div>
        <button class="action" id="logoutBtn">退出</button>
        </div>
      </div>
      <div class="sqlRow">
        <div class="status" id="permissionHint">Login to query</div>

        <textarea id="sqlInput">SELECT airfoil_id, name, final_point_count FROM airfoils LIMIT 10</textarea>
        <button class="action primary" id="runSqlBtn">执行 SQL</button>
      </div>
      <div class="box" id="sqlResult">查询结果和操作日志会显示在这里。</div>
      <div class="adminPanel" id="adminPanel">
        <div class="toolbar">
          <h2>管理者审计区</h2>
          <div class="experimentControls">
            <select id="adminAuditTargetSelect">
              <option value="data_sources">data_sources</option>
              <option value="airfoils" selected>airfoils</option>
              <option value="data_versions">data_versions</option>
              <option value="coordinate_points">coordinate_points</option>
              <option value="performance_records">performance_records</option>
              <option value="anomaly_records">anomaly_records</option>
            </select>
            <button class="action" id="loadUsersBtn">查看 users</button>
            <button class="action" id="loadLogsBtn">查看 query_logs</button>
            <button class="action adminTraceBtn" data-table="data_record_lineage">记录修改追溯</button>
            <button class="action adminTraceBtn" data-table="data_import_records">来源/版本写入记录</button>
            <button class="action adminTraceBtn" data-table="audit_logs">审计日志</button>
            <button class="action adminTraceBtn" data-table="soft_delete_records">逻辑删除记录</button>
            <select id="adminTableSelect">
              <option value="data_sources">data_sources</option>
              <option value="airfoils" selected>airfoils</option>
              <option value="data_versions">data_versions</option>
              <option value="coordinate_points">coordinate_points</option>
              <option value="performance_records">performance_records</option>
              <option value="anomaly_records">anomaly_records</option>
            </select>
            <select id="adminLimitSelect">
              <option value="100">100 rows</option>
              <option value="500">500 rows</option>
              <option value="all">全部</option>
            </select>
            <button class="action" id="loadMainTableBtn">查看主表</button>
          </div>
        </div>
        <div class="indexColumnBox keyFilterBox" id="adminReviewFilterBox"></div>
        <div class="box" id="adminResult">engineer/admin 可查看 users、query_logs 与主数据表。</div>
        <div class="createRow" id="adminCreateUserRow">
          <input id="adminNewUsername" placeholder="new username">
          <input id="adminNewPassword" type="password" placeholder="new password">
          <select id="adminNewRole">
            <option value="viewer">viewer</option>
            <option value="analyst">analyst</option>
            <option value="engineer">engineer</option>
            <option value="admin">admin</option>
          </select>
          <span class="status">admin only</span>
          <span></span>
          <button class="action primary" id="adminCreateUserBtn">创建 User</button>
        </div>
      </div>
      <div class="editorPanel" id="editorPanel">
        <div class="toolbar"><h2>图形化创建翼型</h2><div class="status">engineer/admin 可用</div></div>
        <div class="createRow">
          <input id="newAirfoilId" placeholder="airfoil_id">
          <input id="newAirfoilName" placeholder="name">
          <input id="newAirfoilFamily" placeholder="family" value="Manual">
          <input id="newAirfoilPoints" placeholder="point count" value="1">
          <span></span>
          <button class="action primary" id="createAirfoilBtn">创建 Airfoil</button>
        </div>
        <div class="toolbar"><h2>翼型基本信息修改</h2><div class="status">从 airfoils 查询结果点击“编辑”后自动填入</div></div>
        <div class="createRow">
          <input id="editAirfoilId" placeholder="airfoil_id">
          <input id="editAirfoilName" placeholder="name">
          <input id="editAirfoilSource" placeholder="source">
          <input id="editAirfoilFamily" placeholder="family">
          <select id="editAirfoilGenerated"><option value="0">real</option><option value="1">generated</option></select>
          <button class="action primary" id="updateAirfoilBtn">更新 Airfoil</button>
        </div>
        <div class="createRow">
          <select id="editAirfoilSourceType">
            <option value="uiuc_raw">uiuc_raw</option>
            <option value="uiuc_raw_with_tracked_augmentation">uiuc_raw_with_tracked_augmentation</option>
            <option value="generated_synthetic">generated_synthetic</option>
            <option value="injected_anomaly">injected_anomaly</option>
          </select>
          <input id="editAirfoilSourceFile" placeholder="source_file">
          <select id="editAirfoilAugmented"><option value="0">real only</option><option value="1">augmented</option></select>
          <input id="editAirfoilOriginalPoints" placeholder="original_point_count">
          <input id="editAirfoilFinalPoints" placeholder="final_point_count">
          <span></span>
        </div>
        <div class="toolbar"><h2>性能记录修改</h2><div class="status">engineer/admin 可用，UPDATE 会触发审计日志</div></div>
        <div class="createRow">
          <input id="editPerfId" placeholder="perf_id">
          <input id="editCl" placeholder="CL（升力系数）">
          <input id="editCd" placeholder="CD（阻力系数）">
          <input id="editCm" placeholder="CM（力矩系数）">
          <select id="editIsAnomaly"><option value="0">normal</option><option value="1">anomaly</option></select>
          <button class="action primary" id="updatePerformanceBtn">更新 Performance</button>
        </div>
        <div class="toolbar"><h2>异常记录修改</h2><div class="status">从 anomaly_records 查询结果点击“编辑”后自动填入</div></div>
        <div class="createRow">
          <input id="editAnomalyId" placeholder="anomaly_id">
          <input id="editAnomalyPerfId" placeholder="perf_id">
          <input id="editAnomalyAirfoilId" placeholder="airfoil_id">
          <input id="editAnomalyVersionId" placeholder="version_id">
          <select id="editAnomalyRuleType">
            <option value="negative_cd">negative_cd</option>
            <option value="extreme_cl">extreme_cl</option>
            <option value="extreme_ld_ratio">extreme_ld_ratio</option>
          </select>
          <button class="action primary" id="updateAnomalyBtn">更新 Anomaly</button>
        </div>
        <textarea id="editAnomalyDetail" placeholder="detail"></textarea>
      </div>
      <div class="governancePanel" id="governancePanel">
        <div class="toolbar" id="governanceExperimentHeader">
          <h2>数据治理</h2>
          <div class="status">异常规则 / 版本追踪 / 来源说明 / 删除策略</div>
        </div>
        <div class="experimentControls" id="governanceExperimentButtons">
          <button class="action primary" id="mainTableModeBtn">主数据表查看</button>
          <button class="action governanceBtn" data-scenario="anomaly">异常规则检测</button>
          <button class="action governanceBtn" data-scenario="version">版本追踪</button>
          <button class="action governanceBtn" data-scenario="source">数据来源说明</button>
          <button class="action governanceBtn" data-scenario="delete">删除策略说明</button>
        </div>
        <div id="mainTableSection">
          <div class="toolbar">
            <h2>工况反查翼型与版本</h2>
            <div class="status">按 <span class="termHint">Re/雷诺数</span>、<span class="termHint">alpha_deg/攻角</span>、<span class="termHint">CL/升力系数</span>、<span class="termHint">CD/阻力系数</span>、<span class="termHint">CL/CD/升阻比</span> 查询满足要求的 airfoils 与 data_versions</div>
          </div>
          <div class="indexColumnBox keyFilterBox" id="conditionSearchBox">
            <div class="keyFilter"><span class="termLabel"><span class="termCode">Reynolds number</span><span class="termZh">雷诺数</span></span><input id="conditionRe" placeholder="100000"></div>
            <div class="keyFilter"><span class="termLabel"><span class="termCode">alpha_deg</span><span class="termZh">攻角，度</span></span><input id="conditionAlpha" placeholder="6"></div>
            <div class="keyFilter"><span class="termLabel"><span class="termCode">CL min</span><span class="termZh">最小升力系数</span></span><input id="conditionClMin" placeholder="0.5"></div>
            <div class="keyFilter"><span class="termLabel"><span class="termCode">CL max</span><span class="termZh">最大升力系数</span></span><input id="conditionClMax" placeholder="optional"></div>
            <div class="keyFilter"><span class="termLabel"><span class="termCode">CD min</span><span class="termZh">最小阻力系数</span></span><input id="conditionCdMin" placeholder="optional"></div>
            <div class="keyFilter"><span class="termLabel"><span class="termCode">CD max</span><span class="termZh">最大阻力系数</span></span><input id="conditionCdMax" placeholder="0.05"></div>
            <div class="keyFilter"><span class="termLabel"><span class="termCode">CL/CD min</span><span class="termZh">最小升阻比</span></span><input id="conditionLdMin" placeholder="optional"></div>
            <div class="keyFilter"><span>异常记录</span><select id="conditionAnomalyMode"><option value="normal">排除异常</option><option value="include">包含异常</option><option value="only">只看异常</option></select></div>
            <div class="keyFilter"><span>limit</span><select id="conditionLimit"><option value="50">50 rows</option><option value="100" selected>100 rows</option><option value="300">300 rows</option></select></div>
            <div class="keyFilter"><span>&nbsp;</span><button class="action primary" id="runConditionSearchBtn">查询满足条件的翼型</button></div>
          </div>
          <div class="box" id="conditionSearchResult">输入工况条件后，可反查满足性能要求的翼型与版本。</div>
          <div class="toolbar">
            <h2>主数据表查看</h2>
            <div class="experimentControls" id="governanceTableControls"></div>
          </div>
          <div class="indexColumnBox keyFilterBox" id="mainTableFilterBox"></div>
          <div class="box" id="mainTableResult">请选择关系并查看主表。</div>
          <div class="experimentControls" id="mainAddControls">
            <button class="action" id="toggleMainAddBtn">+ 添加记录</button>
          </div>
          <div class="indexColumnBox keyFilterBox" id="mainAddBox" style="display:none"></div>
        </div>
        <div class="box" id="governanceResult" style="display:none">点击上方按钮查看数据治理证据。</div>
      </div>
      <div class="transactionPanel" id="transactionPanel">
        <div class="toolbar">
          <h2>事务实验</h2>
          <div class="status">同一连接内 BEGIN / COMMIT / ROLLBACK</div>
        </div>
        <div class="status">
          这里允许多条 SELECT / INSERT / UPDATE / DELETE；DDL 和 users/query_logs 不参与事务实验。
        </div>
        <div class="experimentControls">
          <button class="action" id="concurrencyScenarioBtn">场景1：并发修改同一性能记录</button>
          <button class="action" id="bulkImportScenarioBtn">场景2：批量导入失败回滚</button>
          <button class="action" id="versionScenarioBtn">场景3：主表键级联更新版本表</button>
        </div>
        <div class="experimentControls">
          <input id="savedTransactionTitle" placeholder="transaction title">
          <button class="action" id="saveTransactionBtn">保存当前事务</button>
          <select id="savedTransactionSelect"></select>
          <button class="action" id="loadSavedTransactionBtn">载入</button>
          <button class="action" id="deleteSavedTransactionBtn">删除</button>
        </div>
        <textarea class="transactionArea" id="transactionSqlInput">UPDATE airfoils
SET family = 'Transaction Test'
WHERE airfoil_id = 'ag03';

SELECT airfoil_id, name, family
FROM airfoils
WHERE airfoil_id = 'ag03';</textarea>
        <div class="experimentControls">
          <button class="action primary" id="rollbackTransactionBtn">执行并回滚</button>
          <button class="action" id="commitTransactionBtn">执行并提交</button>
        </div>
        <div class="transactionQueueBox">
          <div class="toolbar">
            <h2>有序事务列表</h2>
            <div class="status">按列表顺序逐个 BEGIN / SQL / COMMIT 或 ROLLBACK</div>
          </div>
          <div class="experimentControls">
            <button class="action" id="addSavedToQueueBtn">加入列表</button>
            <button class="action" id="clearTransactionQueueBtn">清空列表</button>
            <button class="action primary" id="runQueueRollbackBtn">运行列表并回滚</button>
            <button class="action" id="runQueueCommitBtn">运行列表并提交</button>
          </div>
          <div class="queueList" id="transactionQueueList">事务列表为空。先保存事务，再从下拉框加入列表。</div>
        </div>
        <div class="box" id="transactionResult">事务实验结果会显示在这里。</div>
      </div>
      <div class="dbObjectPanel" id="dbObjectPanel">
        <div class="toolbar">
          <h2>数据库对象实验</h2>
          <div class="status">触发器 / 视图 / 存储过程</div>
        </div>
        <div class="status">
          点击按钮后由后端执行固定实验 SQL，并把结果表直接显示在页面中。
        </div>
        <div class="experimentControls">
          <button class="action primary dbObjectBtn" data-scenario="views">视图查询</button>
          <button class="action dbObjectBtn" data-scenario="trigger_reject">触发器拒绝非法异常</button>
          <button class="action dbObjectBtn" data-scenario="trigger_audit">触发器自动审计</button>
          <button class="action dbObjectBtn" data-scenario="proc_summary">存储过程统计分析</button>
          <button class="action dbObjectBtn" data-scenario="proc_import_bad">非法批量导入</button>
          <button class="action dbObjectBtn" data-scenario="proc_import_good">合法批量导入</button>
        </div>
        <div class="box" id="dbObjectResult">数据库对象实验结果会显示在这里。</div>
      </div>
      <div class="batchPanel" id="batchPanel">
        <div class="toolbar"><h2>自定义批量导入</h2><div class="status">选择关系后导入 CSV/TSV；文件表头必须与该关系属性顺序完全一致</div></div>
        <div class="experimentControls">
          <select id="batchImportTarget">
            <option value="performance_records">performance_records</option>
            <option value="airfoils">airfoils</option>
            <option value="data_versions">data_versions</option>
            <option value="coordinate_points">coordinate_points</option>
            <option value="data_sources">data_sources</option>
          </select>
          <input id="batchImportId" placeholder="batch_id" value="ui_batch_001">
          <input id="batchImportFile" type="file" accept=".csv,.tsv,.txt">
          <button class="action" id="loadGoodBatchBtn">载入合法样例</button>
          <button class="action" id="loadBadBatchBtn">载入非法样例</button>
          <button class="action primary" id="runBatchImportBtn">导入批次</button>
        </div>
        <div class="box" id="batchExpectedHeader">请选择关系后查看期望表头。</div>
        <textarea class="transactionArea" id="batchImportInput">perf_id,airfoil_id,version_id,alpha_deg,reynolds_number,cl,cd,cm,source_type,is_anomaly
9910001,ag03,1,-2,123458,0.42,0.012,0.0,generated_synthetic,0
9910002,ag03,1,2,123458,0.62,0.014,0.0,generated_synthetic,0</textarea>
        <div class="box" id="batchImportResult">批量导入结果会显示在这里。</div>
      </div>
      </div>

    <div class="top">
      <div class="titlebar"><h1 id="airfoilTitle">选择一个翼型</h1><div class="sub" id="airfoilMeta">坐标、性能和异常记录会显示在这里</div></div>
      <div class="versionBox"><h2>版本</h2><select id="versionSelect"></select></div>
    </div>
    <div class="glossaryStrip" aria-label="性能字段说明">
      <span class="status">性能字段</span>
      <span class="termHint">Reynolds number（雷诺数）</span>
      <span class="termHint">alpha_deg（攻角，度）</span>
      <span class="termHint">CL（升力系数）</span>
      <span class="termHint">CD（阻力系数）</span>
      <span class="termHint">CM（力矩系数）</span>
      <span class="termHint">CL/CD（升阻比）</span>
    </div>
    <div class="grid">
      <section class="chartSection shapeSection"><div class="toolbar"><h2>二维轮廓</h2><div class="status" id="coordStatus">-</div></div><div class="shapeLegend"><span class="legendItem" style="color:#1f766f"><span class="legendMark"></span>upper 正面</span><span class="legendItem" style="color:#2563a6"><span class="legendMark"></span>lower 反面</span><span class="legendItem" style="color:#b25d2a"><span class="legendDiamond"></span>augmented 增强点</span><span class="legendItem" style="color:#b42318"><span class="legendRing"></span>anomaly 异常提示</span></div><canvas id="shapeCanvas"></canvas><div class="chartTooltip" id="shapeTooltip"></div></section>
      <section class="chartSection"><div class="toolbar"><h2>CL（升力系数）-alpha（攻角）曲线</h2><select id="reSelect"></select></div><canvas id="perfCanvas"></canvas><div class="chartTooltip" id="perfTooltip"></div></section>
      <section class="chartSection"><div class="toolbar"><h2>CD（阻力系数）-alpha（攻角）曲线</h2><select id="cdReSelect"></select></div><canvas id="cdCanvas"></canvas><div class="chartTooltip" id="cdTooltip"></div></section>
      <section class="chartSection"><div class="toolbar"><h2>CL/CD（升阻比）-alpha（攻角）曲线</h2><select id="ldReSelect"></select></div><canvas id="ldCanvas"></canvas><div class="chartTooltip" id="ldTooltip"></div></section>
      <section class="chartSection wideChartSection"><div class="toolbar"><h2>同一 Re（雷诺数）下多翼型性能对比</h2><div class="experimentControls"><select id="compareReSelect"><option value="50000">Re 50,000（雷诺数）</option><option value="100000">Re 100,000（雷诺数）</option><option value="200000">Re 200,000（雷诺数）</option><option value="500000">Re 500,000（雷诺数）</option></select><button class="action primary compareMetricBtn" data-metric="max_cl">最大 CL（升力系数）</button><button class="action compareMetricBtn" data-metric="min_cd">最小 CD（阻力系数）</button><button class="action compareMetricBtn" data-metric="max_ld">最大 CL/CD（升阻比）</button><button class="action compareMetricBtn" data-metric="avg_cl">平均 CL（升力系数）</button></div></div><div class="compareScroll" id="compareScroll"><canvas id="compareCanvas"></canvas></div><div class="chartTooltip" id="compareTooltip"></div></section>
      <section class="chartSection wideChartSection"><div class="toolbar"><h2>不同版本翼型性能差异图</h2><div class="status" id="versionDiffStatus">当前翼型版本对比</div></div><div class="versionDiffScroll" id="versionDiffScroll"><canvas id="versionDiffCanvas"></canvas></div><div class="chartTooltip" id="versionDiffTooltip"></div></section>
      <section class="versionInfoSection">
        <div class="toolbar"><h2>版本信息</h2><div class="status" id="perfStatus">-</div></div>
        <div class="versionContent">
          <div class="metrics" id="metrics"></div>
          <div class="experiment">
            <div class="toolbar"><h2>索引实验</h2><div class="status" id="indexStatus">-</div></div>
            <div class="status">选择关系后查看该关系上的索引；点 + 新增索引，点每行 × 删除对应索引。</div>
            <div class="experimentControls">
              <select id="indexTableSelect"></select>
              <button class="action" id="loadIndexesBtn">查看当前索引</button>
            </div>
            <div class="box" id="indexList">点击“查看当前索引”显示所选表上的索引。</div>
            <div class="experimentControls">
              <button class="action iconAction primary" id="showCreateIndexBtn" title="添加索引">+</button>
            </div>
            <div class="indexForm compactIndexForm" id="indexForm">
              <div class="status" id="indexFormHint">选择表和属性，输入索引名后创建索引。</div>
              <input id="indexNameInput" placeholder="index name, e.g. idx_perf_re_alpha">
              <div class="indexColumnBox" id="indexColumnBox"></div>
              <div class="experimentControls">
                <button class="action primary" id="createIndexBtn">保存新增索引</button>
              </div>
            </div>
          </div>
        </div>
      </section>
      <section>
        <div class="toolbar"><h2>索引实验 SQL</h2><div class="status">SELECT only</div></div>
        <div class="indexSqlPanel">
          <div class="status">在这里自己编写查询；运行后显示结果表、EXPLAIN 和耗时。</div>
          <textarea class="indexSqlArea" id="indexSqlInput">SELECT airfoil_id, version_id, alpha_deg, cl, cd
FROM performance_records
WHERE reynolds_number = 500000
ORDER BY alpha_deg</textarea>
          <div class="experimentControls">
            <button class="action primary" id="runIndexBtn">运行实验 SQL</button>
          </div>
          <div class="box" id="indexResult">等待运行</div>
        </div>
      </section>
    </div>
    <section>
      <div class="toolbar"><h2>异常记录</h2><div class="status" id="anomalyStatus">-</div></div>
      <div class="tableWrap"><table><thead><tr><th>ID</th><th>规则</th><th>alpha（攻角）</th><th>Re（雷诺数）</th><th>CL（升力系数）</th><th>CD（阻力系数）</th></tr></thead><tbody id="anomalyRows"></tbody></table></div>
    </section>
  </main>
</div>
<script>
const state={airfoils:[],selectedAirfoil:null,selectedVersion:1,versions:[],selectedRe:50000,compareMetric:"max_cl",coordinates:[],performance:[],anomalies:[],currentUser:null,savedTransactions:[],transactionQueue:[],shapeScreen:[],perfScreen:[],cdScreen:[],ldScreen:[],compareScreen:[],versionDiffScreen:[],appDataLoaded:false,mainFilterCache:{},secondaryChartTimer:null};
const $=id=>document.getElementById(id);
function on(id,event,handler){const el=$(id); if(el&&!el.dataset[`bound${event}`]){el.addEventListener(event,handler);el.dataset[`bound${event}`]="1";}}
const DEFAULT_TRANSACTION_SQL=`UPDATE airfoils
SET family = 'Transaction Test'
WHERE airfoil_id = 'ag03';

SELECT airfoil_id, name, family
FROM airfoils
WHERE airfoil_id = 'ag03';`;
async function getJson(url){const r=await fetch(url); if(!r.ok) throw new Error(await r.text()); return await r.json();}
async function postJson(url,body={}){const r=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}); const data=await r.json(); if(!r.ok) throw data; return data;}
function num(v,d=4){const n=Number(v); return Number.isFinite(n)?n.toFixed(d):"-";}
const FIELD_LABELS={
  user_id:"user_id（用户编号）",
  username:"username（用户名）",
  role:"role（角色）",
  created_at:"created_at（创建时间）",
  log_id:"log_id（查询日志编号）",
  sql_text:"sql_text（SQL全文）",
  is_valid:"is_valid（是否有效）",
  elapsed_ms:"elapsed_ms（耗时ms）",
  row_count:"row_count（结果行数）",
  operation_type:"operation_type（操作类型）",
  table_name:"table_name（关系名）",
  record_pk:"record_pk（记录主键）",
  old_values:"old_values（修改前数据）",
  new_values:"new_values（修改后数据）",
  performed_by_user_id:"performed_by_user_id（执行用户编号）",
  performed_by_username:"performed_by_username（执行用户名）",
  performed_at:"performed_at（执行时间）",
  audit_id:"audit_id（审计编号）",
  lineage_id:"lineage_id（追溯编号）",
  source_record_pk:"source_record_pk（来源记录主键）",
  current_record_version_id:"current_record_version_id（当前记录版本）",
  previous_record_version_id:"previous_record_version_id（上一记录版本）",
  record_version_id:"record_version_id（记录版本）",
  is_modified:"is_modified（是否被修改）",
  last_modified_at:"last_modified_at（最后修改时间）",
  last_operation:"last_operation（最后操作）",
  modified_by_user_id:"modified_by_user_id（修改用户编号）",
  modified_by_username:"modified_by_username（修改用户名）",
  modified_count:"modified_count（修改次数）",
  delete_id:"delete_id（删除记录编号）",
  delete_reason:"delete_reason（删除原因）",
  deleted_at:"deleted_at（删除时间）",
  deleted_by_user_id:"deleted_by_user_id（删除用户编号）",
  deleted_by_username:"deleted_by_username（删除用户名）",
  is_active:"is_active（是否仍处于删除状态）",
  restored_at:"restored_at（恢复时间）",
  restored_by_user_id:"restored_by_user_id（恢复用户编号）",
  restored_by_username:"restored_by_username（恢复用户名）",
  row_snapshot:"row_snapshot（删除前完整数据）",
  import_id:"import_id（导入记录编号）",
  import_method:"import_method（导入方式）",
  import_source:"import_source（导入来源）",
  imported_at:"imported_at（导入时间）",
  imported_by_user_id:"imported_by_user_id（导入用户编号）",
  imported_by_username:"imported_by_username（导入用户名）",
  affected_rows:"affected_rows（影响行数）",
  batch_id:"batch_id（批次编号）",
  source_type:"source_type（来源类型）",
  source_name:"source_name（来源名称）",
  source_url:"source_url（来源链接）",
  description:"description（说明）",
  airfoil_id:"airfoil_id（翼型编号）",
  name:"name（名称）",
  source:"source（数据来源）",
  family:"family（翼型族类）",
  is_generated:"is_generated（是否生成数据）",
  source_file:"source_file（源文件）",
  has_augmented_coordinates:"has_augmented_coordinates（是否补点）",
  original_point_count:"original_point_count（原始坐标点数）",
  final_point_count:"final_point_count（最终坐标点数）",
  version_id:"version_id（数据集版本）",
  version_type:"version_type（版本类型）",
  coordinate_source_type:"coordinate_source_type（坐标来源类型）",
  point_order:"point_order（点序号）",
  x:"x（横坐标）",
  y:"y（纵坐标）",
  surface:"surface（上下表面）",
  point_source:"point_source（点来源）",
  is_augmented:"is_augmented（是否补点）",
  original_order:"original_order（原始序号）",
  augmentation_method:"augmentation_method（补点方法）",
  perf_id:"perf_id（性能记录编号）",
  is_anomaly:"is_anomaly（是否异常）",
  anomaly_id:"anomaly_id（异常编号）",
  rule_type:"rule_type（异常规则）",
  detail:"detail（详情）",
  alpha:"alpha（攻角）",
  alpha_deg:"alpha_deg（攻角，度）",
  reynolds_number:"Reynolds number（雷诺数）",
  cl:"CL（升力系数）",
  cd:"CD（阻力系数）",
  cm:"CM（力矩系数）",
  lift_drag_ratio:"CL/CD（升阻比）",
  max_cl:"最大CL（升力系数）",
  min_cd:"最小CD（阻力系数）",
  max_ld:"最大CL/CD（升阻比）",
  avg_cl:"平均CL（升力系数）",
  imported_count:"imported_count（成功导入数）",
  invalid_count:"invalid_count（非法记录数）",
  status:"status（状态）",
  validation_error:"validation_error（校验错误）",
  staging_id:"staging_id（暂存记录编号）",
  sample_count:"sample_count（样本数）",
  anomaly_count:"anomaly_count（异常数）",
  max_lift_drag_ratio:"max_lift_drag_ratio（最大升阻比）",
  metric_name:"metric_name（指标名）",
  metric_value:"metric_value（指标值）",
  airfoil_name:"airfoil_name（翼型名称）"
};
function fieldLabel(name){return FIELD_LABELS[name]||name;}
function fieldGlossaryHtml(fields){
  const items=(fields||[]).filter(name=>FIELD_LABELS[name]).map(name=>`<span class="termHint">${escapeHtml(FIELD_LABELS[name])}</span>`);
  return items.length?`<br><b>字段含义：</b><span class="fieldGlossary">${items.join("")}</span>`:"";
}
function metricLabel(metric){
  return {
    max_cl:"最大CL（升力系数）",
    min_cd:"最小CD（阻力系数）",
    max_ld:"最大CL/CD（升阻比）",
    avg_cl:"平均CL（升力系数）"
  }[metric]||metric;
}
function isManager(){const u=state.currentUser; return u&&(u.role==="engineer"||u.role==="admin");}
function isAdmin(){return state.currentUser&&state.currentUser.role==="admin";}
function canUseMainData(){const u=state.currentUser; return u&&(u.role==="analyst"||u.role==="engineer"||u.role==="admin");}
function escapeHtml(value){return String(value??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[m]));}
function formatSqlForDisplay(sql){
  let text=String(sql??"").replace(/\r\n/g,"\n").replace(/\s+/g," ").trim();
  const breaks=[
    "CREATE VIEW","CREATE TRIGGER","CREATE PROCEDURE","SQL SECURITY"," AS SELECT "," SELECT "," FROM "," LEFT JOIN "," RIGHT JOIN "," INNER JOIN "," JOIN ",
    " WHERE "," GROUP BY "," ORDER BY "," HAVING "," LIMIT "," VALUES "," SET "," ON DUPLICATE KEY UPDATE "," BEGIN "," END"," INSERT INTO "," UPDATE "," DELETE FROM ",
    " AND "," OR "
  ];
  breaks.forEach(keyword=>{
    const escaped=keyword.trim().replace(/[.*+?^${}()|[\]\\]/g,"\\$&").replace(/\s+/g,"\\s+");
    const pattern=new RegExp(`\\s+${escaped}\\s+`,"gi");
    const replacement=`\n${keyword.trim()} `;
    text=text.replace(pattern,replacement);
  });
  text=text
    .replace(/,\s*/g,",\n    ")
    .replace(/\(\s*SELECT\s+/gi,"(\nSELECT ")
    .replace(/\)\s*SELECT\s+/gi,")\nSELECT ")
    .replace(/\n{3,}/g,"\n\n")
    .trim();
  return text;
}
function sqlPre(sql){return `<pre>${escapeHtml(formatSqlForDisplay(sql))}</pre>`;}
function rowsToTable(rows,options={}){
  if(!rows||!rows.length)return "<div class='status'>No rows</div>";
  const cols=Object.keys(rows[0]);
  const editableTable=isManager()&&["data_sources","airfoils","data_versions","coordinate_points","performance_records","anomaly_records"].includes(options.table);
  const restorableTable=isAdmin()&&options.table==="soft_delete_records";
  const adminRecordButtons=r=>{
    if(!isAdmin()||!editableTable)return "";
    const payload=escapeHtml(JSON.stringify(r));
    return [
      `<button class="action rowAdminTraceBtn" data-review-table="data_import_records" data-table="${escapeHtml(options.table)}" data-row="${payload}">来源</button>`,
      `<button class="action rowAdminTraceBtn" data-review-table="data_record_lineage" data-table="${escapeHtml(options.table)}" data-row="${payload}">追溯</button>`,
      `<button class="action rowAdminTraceBtn" data-review-table="audit_logs" data-table="${escapeHtml(options.table)}" data-row="${payload}">审计</button>`
    ].join("");
  };
  const actionCell=r=>{
    if(editableTable){
      const payload=escapeHtml(JSON.stringify(r));
      return `<td><div class="rowActions"><button class="action rowEditBtn" data-table="${escapeHtml(options.table)}" data-row="${payload}">编辑</button><button class="action rowDeleteBtn mainRowDeleteBtn" data-table="${escapeHtml(options.table)}" data-row="${payload}">删除</button>${adminRecordButtons(r)}</div></td>`;
    }
    if(restorableTable){
      const active=String(r.is_active??"0")==="1";
      return `<td><div class="rowActions">${active?`<button class="action restoreDeleteBtn" data-delete-id="${escapeHtml(r.delete_id)}" data-table="${escapeHtml(r.table_name||"")}" data-record-pk="${escapeHtml(r.record_pk||"")}">恢复</button>`:`<span class="status">已恢复</span>`}</div></td>`;
    }
    if(options.table==="data_record_lineage"){
      const payload=escapeHtml(JSON.stringify(r));
      return `<td><div class="rowActions"><button class="action lineageToAuditBtn" data-row="${payload}">查看审计</button></div></td>`;
    }
    return "";
  };
  const cell=(r,c)=>{
    if(c==="sql_text"&&r.log_id){
      const text=String(r[c]??"");
      const brief=text.length>90?`${text.slice(0,90)}...`:text;
      return `<td><a href="/query_logs/${encodeURIComponent(r.log_id)}/sql" target="_blank" rel="noopener">查看全文</a><br><span class="status">${escapeHtml(brief)}</span></td>`;
    }
    return `<td>${escapeHtml(r[c])}</td>`;
  };
  const actionHead=(editableTable||restorableTable||options.table==="data_record_lineage")?"<th>操作</th>":"";
  return `<div class="tableWrap"><table><thead><tr>${actionHead}${cols.map(c=>`<th>${escapeHtml(fieldLabel(c))}</th>`).join("")}</tr></thead><tbody>${rows.map(r=>`<tr>${actionCell(r)}${cols.map(c=>cell(r,c)).join("")}</tr>`).join("")}</tbody></table></div>`;
}
function noRowsHint(table,target,filters){
  const filterText=Object.entries(filters||{}).map(([k,v])=>`${fieldLabel(k)}=${v}`).join("，")||"全部";
  return `<div class="status">没有查到记录。当前审计表：${escapeHtml(table)}；目标关系：${escapeHtml(target)}；筛选条件：${escapeHtml(filterText)}。可以换一个目标关系，或清空上方筛选条件后再查。</div>`;
}
function rowRecordPk(table,row){
  if(table==="data_sources")return row.source_type;
  if(table==="airfoils")return row.airfoil_id;
  if(table==="data_versions")return `${row.airfoil_id}#${row.version_id}`;
  if(table==="coordinate_points")return `${row.airfoil_id}#${row.version_id}#${row.point_order}`;
  if(table==="performance_records")return row.perf_id;
  if(table==="anomaly_records")return row.anomaly_id;
  return row.record_pk||row.id||"";
}
function tablePrimaryKeyColumns(table){
  return {
    data_sources:["source_type"],
    airfoils:["airfoil_id"],
    data_versions:["airfoil_id","version_id"],
    coordinate_points:["airfoil_id","version_id","point_order"],
    performance_records:["perf_id"],
    anomaly_records:["anomaly_id"]
  }[table]||["record_pk"];
}
function buildRecordPkFromFilters(table,values){
  if(table==="data_sources")return values.source_type||"";
  if(table==="airfoils")return values.airfoil_id||"";
  if(table==="data_versions")return values.airfoil_id&&values.version_id?`${values.airfoil_id}#${values.version_id}`:"";
  if(table==="coordinate_points")return values.airfoil_id&&values.version_id&&values.point_order?`${values.airfoil_id}#${values.version_id}#${values.point_order}`:"";
  if(table==="performance_records")return values.perf_id||"";
  if(table==="anomaly_records")return values.anomaly_id||"";
  return values.record_pk||"";
}
function showSqlResult(target,data){
  const meta=`<h2>执行性能</h2><div class="status">Rows: ${data.row_count} · Time: ${data.elapsed_ms} ms${data.affected_rows==null?"":` · Affected: ${data.affected_rows}`}</div>`;
  const explain=data.explain&&data.explain.length?`<h2>EXPLAIN</h2>${rowsToTable(data.explain)}`:"";
  target.innerHTML=`${meta}${explain}<h2>Result</h2>${rowsToTable(data.rows)}`;
}
function resetTransactionEditor(){
  if($("savedTransactionTitle"))$("savedTransactionTitle").value="";
  if($("savedTransactionSelect"))$("savedTransactionSelect").value="";
  if($("transactionSqlInput"))$("transactionSqlInput").value=DEFAULT_TRANSACTION_SQL;
  state.transactionQueue=[];
  renderTransactionQueue();
  if($("transactionResult"))$("transactionResult").textContent="事务实验结果会显示在这里。";
}
function setupPages(){
  const panel=document.querySelector("main > .panel");
  const top=document.querySelector("main > .top");
  const glossary=document.querySelector("main > .glossaryStrip");
  const grid=document.querySelector("main > .grid");
  const anomaly=document.querySelector("main > section:last-of-type");
  const indexExperiment=$("indexStatus").closest(".experiment");
  const indexSqlSection=$("indexSqlInput").closest("section");
  document.querySelector(".pageTabs").appendChild($("loggedInBar"));
  $("pageSql").appendChild(panel);
  $("pageIndex").appendChild(indexExperiment);
  $("pageIndex").appendChild(indexSqlSection);
  $("pageTransaction").appendChild($("transactionPanel"));
  $("pageDbObjects").appendChild($("dbObjectPanel"));
  $("pageBatch").appendChild($("batchPanel"));
  $("pageGovernance").appendChild($("governancePanel"));
  $("governanceTableControls").appendChild($("adminTableSelect"));
  $("governanceTableControls").appendChild($("adminLimitSelect"));
  $("governanceTableControls").appendChild($("loadMainTableBtn"));
  $("pageGovernance").appendChild($("editorPanel"));
  $("pageAdmin").appendChild($("adminPanel"));
  $("pageOverview").appendChild(top);
  if(glossary)$("pageOverview").appendChild(glossary);
  $("pageOverview").appendChild(grid);
  $("pageOverview").appendChild(anomaly);
  document.querySelectorAll(".tabBtn").forEach(btn=>{
    btn.addEventListener("click",()=>showPage(btn.dataset.tab));
  });
}
function showPage(name){
  document.querySelectorAll(".tabBtn").forEach(btn=>btn.classList.toggle("active",btn.dataset.tab===name));
  const ids={overview:"pageOverview",sql:"pageSql",index:"pageIndex",transaction:"pageTransaction",dbobjects:"pageDbObjects",batch:"pageBatch",governance:"pageGovernance",admin:"pageAdmin"};
  Object.entries(ids).forEach(([key,id])=>$(id).classList.toggle("active",key===name));
  $("appShell").classList.toggle("noAside",name!=="overview");
  hideTooltip("shapeTooltip");hideTooltip("perfTooltip");
  if(name==="governance")showMainTableSection(true);
  if(name==="overview")setTimeout(()=>{drawShape();drawPerformance();drawCd();drawLd();scheduleSecondaryCharts();},0);
}
async function init(){
  on("logoutBtn","click",logout);
  setupPages();
  $("search").addEventListener("input",renderAirfoilList);
  $("versionSelect").addEventListener("change",e=>{state.selectedVersion=Number(e.target.value);loadVersionData();});
  ["reSelect","cdReSelect","ldReSelect"].forEach(id=>$(id).addEventListener("change",e=>changeSelectedRe(e.target.value)));
  $("compareReSelect").addEventListener("change",drawCompare);
  document.querySelectorAll(".compareMetricBtn").forEach(btn=>btn.addEventListener("click",()=>{state.compareMetric=btn.dataset.metric;document.querySelectorAll(".compareMetricBtn").forEach(b=>b.classList.toggle("primary",b===btn));drawCompare();}));
  $("shapeCanvas").addEventListener("mousemove",handleShapeHover);
  $("shapeCanvas").addEventListener("mouseleave",()=>hideTooltip("shapeTooltip"));
  $("perfCanvas").addEventListener("mousemove",handlePerfHover);
  $("perfCanvas").addEventListener("mouseleave",()=>hideTooltip("perfTooltip"));
  $("cdCanvas").addEventListener("mousemove",e=>handleSeriesHover(e,"cdCanvas","cdTooltip",state.cdScreen));
  $("cdCanvas").addEventListener("mouseleave",()=>hideTooltip("cdTooltip"));
  $("ldCanvas").addEventListener("mousemove",e=>handleSeriesHover(e,"ldCanvas","ldTooltip",state.ldScreen));
  $("ldCanvas").addEventListener("mouseleave",()=>hideTooltip("ldTooltip"));
  $("compareCanvas").addEventListener("mousemove",handleCompareHover);
  $("compareCanvas").addEventListener("mouseleave",()=>hideTooltip("compareTooltip"));
  $("versionDiffCanvas").addEventListener("mousemove",handleVersionDiffHover);
  $("versionDiffCanvas").addEventListener("mouseleave",()=>hideTooltip("versionDiffTooltip"));
  $("runSqlBtn").addEventListener("click",runSql);
  document.querySelectorAll(".queryTemplateBtn").forEach(btn=>btn.addEventListener("click",()=>loadQueryTemplate(btn.dataset.template)));
  $("loadUsersBtn").addEventListener("click",loadUsers);
  $("loadLogsBtn").addEventListener("click",loadLogs);
  document.querySelectorAll(".adminTraceBtn").forEach(btn=>btn.addEventListener("click",()=>openAdminReviewTable(btn.dataset.table)));
  $("adminAuditTargetSelect").addEventListener("change",()=>{if(state.adminReviewTable)openAdminReviewTable(state.adminReviewTable);});
  $("loadMainTableBtn").addEventListener("click",loadMainTable);
  $("runConditionSearchBtn").addEventListener("click",runConditionSearch);
  $("adminTableSelect").addEventListener("change",changeMainTable);
  $("toggleMainAddBtn").addEventListener("click",toggleMainAddForm);
  $("mainTableModeBtn").addEventListener("click",showMainTableMode);
  document.querySelectorAll(".governanceBtn").forEach(btn=>btn.addEventListener("click",()=>runDataGovernance(btn.dataset.scenario)));
  $("adminCreateUserBtn").addEventListener("click",adminCreateUser);
  $("createAirfoilBtn").addEventListener("click",createAirfoil);
  $("updateAirfoilBtn").addEventListener("click",updateAirfoilRecord);
  $("updatePerformanceBtn").addEventListener("click",updatePerformanceRecord);
  $("updateAnomalyBtn").addEventListener("click",updateAnomalyRecord);
  $("rollbackTransactionBtn").addEventListener("click",()=>runTransaction("rollback"));
  $("commitTransactionBtn").addEventListener("click",()=>runTransaction("commit"));
  $("saveTransactionBtn").addEventListener("click",saveCurrentTransaction);
  $("loadSavedTransactionBtn").addEventListener("click",loadSelectedSavedTransaction);
  $("deleteSavedTransactionBtn").addEventListener("click",deleteSelectedSavedTransaction);
  $("addSavedToQueueBtn").addEventListener("click",addSelectedTransactionToQueue);
  $("clearTransactionQueueBtn").addEventListener("click",clearTransactionQueue);
  $("runQueueRollbackBtn").addEventListener("click",()=>runTransactionQueue("rollback"));
  $("runQueueCommitBtn").addEventListener("click",()=>runTransactionQueue("commit"));
  $("concurrencyScenarioBtn").addEventListener("click",runConcurrencyScenario);
  $("bulkImportScenarioBtn").addEventListener("click",loadBulkImportScenario);
  $("versionScenarioBtn").addEventListener("click",loadVersionAtomicScenario);
  document.querySelectorAll(".dbObjectBtn").forEach(btn=>btn.addEventListener("click",()=>runDbObjectExperiment(btn.dataset.scenario)));
  $("loadGoodBatchBtn").addEventListener("click",()=>loadBatchSample("good"));
  $("loadBadBatchBtn").addEventListener("click",()=>loadBatchSample("bad"));
  $("runBatchImportBtn").addEventListener("click",runBatchImport);
  $("batchImportTarget").addEventListener("change",updateBatchHeaderHint);
  $("batchImportFile").addEventListener("change",loadBatchFile);
  $("indexTableSelect").addEventListener("change",loadIndexColumns);
  $("loadIndexesBtn").addEventListener("click",loadIndexes);
  $("showCreateIndexBtn").addEventListener("click",()=>showIndexForm("create"));
  $("createIndexBtn").addEventListener("click",createIndex);
  $("runIndexBtn").addEventListener("click",runIndex);
  window.addEventListener("resize",()=>{drawShape();drawPerformance();drawCd();drawLd();scheduleSecondaryCharts();});
  updateBatchHeaderHint();
  await loadMe();
  if(state.currentUser)await loadAppData();
}
async function loadAppData(){
  const [summary,airfoils]=await Promise.all([getJson("/api/summary"),getJson("/api/airfoils")]);
  state.airfoils=airfoils;
  $("summary").textContent=`${summary.airfoils} 个翼型 · ${summary.coordinate_points} 个坐标点 · ${summary.performance_records} 条性能记录`;
  renderAirfoilList();
  const current=state.selectedAirfoil&&airfoils.some(a=>a.airfoil_id===state.selectedAirfoil)?state.selectedAirfoil:(airfoils[0]?airfoils[0].airfoil_id:null);
  if(current)selectAirfoil(current).catch(err=>console.error(err));
  if(canUseMainData()){
    loadMainTableFilters().catch(err=>console.error(err));
    if(!isAdmin())loadMainTable().catch(err=>console.error(err));
  }
  if(isAdmin()){
    loadIndexTables().catch(err=>console.error(err));
    refreshIndexStatus().catch(err=>console.error(err));
    loadIndexes().catch(err=>console.error(err));
  }
  state.appDataLoaded=true;
}
async function loadMe(){const previousUserId=state.currentUser?state.currentUser.user_id:null;const data=await getJson("/api/auth/me"); state.currentUser=data.authenticated?data.user:null; const nextUserId=state.currentUser?state.currentUser.user_id:null; updateAuth(previousUserId!==nextUserId);}
function updateAuth(userChanged=false){
  const u=state.currentUser;
  if(!u){
    $("authGate").style.display="grid";
    $("appShell").classList.remove("visible");
    $("userStatus").textContent="Not logged in";
    $("permissionHint").textContent="Login to query. Register creates viewer only.";
    $("loggedInBar").style.display="none";
    state.savedTransactions=[];
    renderSavedTransactions();
    resetTransactionEditor();
    $("adminPanel").classList.remove("visible");
    $("editorPanel").classList.remove("visible");
    $("transactionPanel").classList.remove("visible");
    $("dbObjectPanel").classList.remove("visible");
    $("batchPanel").classList.remove("visible");
    $("governancePanel").classList.remove("visible");
    return;
  }
  $("authGate").style.display="none";
  $("appShell").classList.add("visible");
  $("loggedInBar").style.display="flex";
  $("userStatus").textContent=isAdmin()?`Current user: ${u.username} · ${u.role} · full admin`:canUseMainData()?`Current user: ${u.username} · ${u.role} · main data access`:`Current user: ${u.username} · ${u.role} · read-only`;
  $("permissionHint").textContent=isAdmin()?"Admin SQL: SELECT/INSERT/UPDATE/DELETE/CREATE INDEX/DROP INDEX":"Guided queries only; use Main Data for no-SQL access";
  $("adminPanel").classList.toggle("visible",isAdmin());
  $("editorPanel").classList.remove("visible");
  $("transactionPanel").classList.toggle("visible",isAdmin());
  $("dbObjectPanel").classList.toggle("visible",isAdmin());
  $("batchPanel").classList.toggle("visible",isAdmin());
  $("governancePanel").classList.toggle("visible",canUseMainData());
  $("governanceExperimentHeader").style.display=isAdmin()?"":"none";
  $("governanceExperimentButtons").style.display=isAdmin()?"":"none";
  document.querySelector('[data-tab="sql"]').style.display=isAdmin()?"inline-flex":"none";
  document.querySelector('[data-tab="index"]').style.display=isAdmin()?"inline-flex":"none";
  document.querySelector('[data-tab="transaction"]').style.display=isAdmin()?"inline-flex":"none";
  document.querySelector('[data-tab="dbobjects"]').style.display=isAdmin()?"inline-flex":"none";
  document.querySelector('[data-tab="batch"]').style.display=isAdmin()?"inline-flex":"none";
  document.querySelector('[data-tab="governance"]').style.display=canUseMainData()?"inline-flex":"none";
  document.querySelector('[data-tab="admin"]').style.display=isAdmin()?"inline-flex":"none";
  if((!isAdmin()&&($("pageSql").classList.contains("active")||$("pageIndex").classList.contains("active")||$("pageTransaction").classList.contains("active")||$("pageDbObjects").classList.contains("active")||$("pageBatch").classList.contains("active")||$("pageAdmin").classList.contains("active")))||(!canUseMainData()&&$("pageGovernance").classList.contains("active"))){
    showPage("overview");
  }
  $("adminCreateUserRow").style.display=isAdmin()?"grid":"none";
  if(userChanged)resetTransactionEditor();
  if(canUseMainData()){
    syncMainTableOptions();
  }
  if(userChanged&&canUseMainData()&&!isAdmin()){
    showPage("governance");
    loadMainTable();
  }
  refreshSavedTransactions();
}
async function gateLogin(){try{$("gateMessage").textContent="正在登录...";const data=await postJson("/api/auth/login",{username:$("gateName").value.trim(),password:$("gatePassword").value});await loadMe();$("gateMessage").textContent=`Login ok: ${data.username} (${data.role})`;if(state.currentUser)loadAppData().catch(err=>{$("gateMessage").textContent=`Load data failed: ${err.message||err}`;});}catch(e){$("gateMessage").textContent=`Login failed: ${e.error||"unknown error"}`;}}
async function gateRegisterViewer(){try{$("gateMessage").textContent="正在注册...";const data=await postJson("/api/auth/register",{username:$("gateName").value.trim(),password:$("gatePassword").value});await loadMe();$("gateMessage").textContent=`Register ok: ${data.username} (${data.role})`;if(state.currentUser)loadAppData().catch(err=>{$("gateMessage").textContent=`Load data failed: ${err.message||err}`;});}catch(e){$("gateMessage").textContent=`Register failed: ${e.error||"unknown error"}`;}}
async function logout(){try{$("userStatus").textContent="Logging out...";await postJson("/api/auth/logout");}finally{state.currentUser=null; state.appDataLoaded=false; state.airfoils=[]; state.selectedAirfoil=null; $("gatePassword").value=""; updateAuth(true); $("gateMessage").textContent="Logged out"; $("sqlResult").textContent="Logged out";}}
async function runSql(){
  try{
    const sql=$("sqlInput").value;
    const data=await postJson("/api/query_logs/run",{sql});
    showSqlResult($("sqlResult"),data);
    if(/^\s*(insert|update|delete|replace|create|drop|alter)\b/i.test(sql)){
      refreshMainDataAfterMutation({allTables:true}).catch(err=>console.error(err));
    }
  }catch(e){
    $("sqlResult").textContent=`SQL failed: ${e.error||"unknown error"}`;
  }
}
async function loadQueryTemplate(kind){
  const templates={
    airfoil_summary:`SELECT airfoil_id, name, family, source_type, final_point_count
FROM airfoils
ORDER BY final_point_count DESC
LIMIT 20;`,
    performance_rank:`SELECT airfoil_id, version_id, reynolds_number, MAX(cl) AS max_cl, MIN(cd) AS min_cd, MAX(cl / NULLIF(cd, 0)) AS max_ld
FROM performance_records
WHERE reynolds_number = 50000
GROUP BY airfoil_id, version_id, reynolds_number
ORDER BY max_ld DESC
LIMIT 20;`,
    anomaly_review:`SELECT ar.anomaly_id, ar.perf_id, ar.airfoil_id, ar.version_id, ar.rule_type, p.alpha_deg, p.reynolds_number, p.cl, p.cd
FROM anomaly_records ar
JOIN performance_records p
  ON p.perf_id = ar.perf_id
ORDER BY ar.anomaly_id
LIMIT 50;`,
    version_trace:`SELECT a.airfoil_id, a.name, dv.version_id, dv.version_type, dv.coordinate_source_type, dv.description
FROM airfoils a
JOIN data_versions dv ON dv.airfoil_id = a.airfoil_id
WHERE a.airfoil_id = 'ag03'
ORDER BY dv.version_id;`
  };
  $("sqlInput").value=templates[kind]||templates.airfoil_summary;
  const target=$("pageGovernance").classList.contains("active")?$("governanceResult"):$("sqlResult");
  target.textContent="Running guided query...";
  try{
    const data=await postJson("/api/query_logs/run",{sql:$("sqlInput").value,natural_language:`guided query: ${kind}`});
    showSqlResult(target,data);
  }catch(e){
    target.textContent=`Guided query failed: ${e.error||"unknown error"}`;
  }
}
async function runDataGovernance(scenario){
  try{
    showMainTableSection(false);
    $("governanceResult").style.display="block";
    $("governanceResult").textContent="Running data governance check...";
    $("mainTableModeBtn").classList.remove("primary");
    document.querySelectorAll(".governanceBtn").forEach(b=>b.classList.toggle("primary",b.dataset.scenario===scenario));
    const d=await postJson("/api/data_governance/run",{
      scenario,
      airfoil_id:"",
      perf_id:"",
      limit:"80"
    });
    const pieces=[`<div class="status">Scenario=${escapeHtml(d.scenario)} · Time=${d.elapsed_ms} ms</div>`];
    if(d.sql_blocks&&d.sql_blocks.length){
      pieces.push("<h2>实验 SQL</h2>");
      d.sql_blocks.forEach((block,index)=>{
        pieces.push(`<div class="sqlBlock"><div class="status"><b>SQL ${index+1}：</b>${escapeHtml(block.title||"")}</div>${sqlPre(block.sql||"")}</div>`);
      });
    }
    (d.sections||[]).forEach(section=>{
      pieces.push(`<h2>${escapeHtml(section.title)}</h2>`);
      if(section.note){pieces.push(`<div class="status">${escapeHtml(section.note)}</div>`);}
      pieces.push(rowsToTable(section.rows||[]));
    });
    $("governanceResult").innerHTML=pieces.join("");
  }catch(e){
    $("governanceResult").textContent=`Data governance check failed: ${e.error||"unknown error"}`;
  }
}
function showMainTableSection(visible){
  const section=$("mainTableSection");
  if(section)section.style.display=visible?"grid":"none";
}
async function showMainTableMode(){
  showMainTableSection(true);
  $("governanceResult").style.display="none";
  document.querySelectorAll(".governanceBtn").forEach(b=>b.classList.remove("primary"));
  $("mainTableModeBtn").classList.add("primary");
  $("mainTableResult").textContent="请选择关系并查看主表。";
  await loadMainTableFilters();
}
async function runConditionSearch(){
  try{
    const params=new URLSearchParams();
    const mapping={
      conditionRe:"reynolds_number",
      conditionAlpha:"alpha_deg",
      conditionClMin:"cl_min",
      conditionClMax:"cl_max",
      conditionCdMin:"cd_min",
      conditionCdMax:"cd_max",
      conditionLdMin:"ld_min"
    };
    Object.entries(mapping).forEach(([id,key])=>{
      const value=$(id).value.trim();
      if(value)params.set(key,value);
    });
    params.set("limit",$("conditionLimit").value);
    const mode=$("conditionAnomalyMode").value;
    if(mode==="include")params.set("include_anomaly","1");
    if(mode==="only")params.set("anomaly_only","1");
    $("conditionSearchResult").textContent="正在按工况查询满足条件的翼型与版本...";
    const data=await getJson(`/api/condition_search?${params.toString()}`);
    const conditionText=[
      params.get("reynolds_number")?`Re（雷诺数）= ${escapeHtml(params.get("reynolds_number"))}`:"",
      params.get("alpha_deg")?`alpha_deg（攻角）= ${escapeHtml(params.get("alpha_deg"))}`:"",
      params.get("cl_min")?`CL（升力系数）>= ${escapeHtml(params.get("cl_min"))}`:"",
      params.get("cl_max")?`CL（升力系数）<= ${escapeHtml(params.get("cl_max"))}`:"",
      params.get("cd_min")?`CD（阻力系数）>= ${escapeHtml(params.get("cd_min"))}`:"",
      params.get("cd_max")?`CD（阻力系数）<= ${escapeHtml(params.get("cd_max"))}`:"",
      params.get("ld_min")?`CL/CD（升阻比）>= ${escapeHtml(params.get("ld_min"))}`:"",
      mode==="normal"?"is_anomaly = 0":mode==="only"?"is_anomaly = 1":"include anomalies"
    ].filter(Boolean).join(" · ")||"all conditions";
    $("conditionSearchResult").innerHTML=`<div class="status">Condition search · ${conditionText} · Rows=${data.row_count} · Time=${data.elapsed_ms} ms</div>${rowsToTable(data.rows)}`;
  }catch(e){
    $("conditionSearchResult").textContent=`Condition search failed: ${e.error||e.message||"unknown error"}`;
  }
}
function hideAdminReviewFilters(){
  const box=$("adminReviewFilterBox");
  if(box){box.classList.remove("visible");box.innerHTML="";}
  state.adminReviewTable=null;
}
async function loadUsers(){try{hideAdminReviewFilters();$("adminResult").innerHTML=rowsToTable(await getJson("/api/admin/users"));}catch(e){$("adminResult").textContent=e.message||String(e);}}
async function loadLogs(){try{hideAdminReviewFilters();$("adminResult").innerHTML=rowsToTable(await getJson("/api/admin/query_logs"));}catch(e){$("adminResult").textContent=e.message||String(e);}}
async function loadAdminReviewFilters(table){
  const box=$("adminReviewFilterBox");
  if(!box)return;
  const target=$("adminAuditTargetSelect")?.value||"airfoils";
  const previous={};
  const presets=state.adminReviewPresetFilters||{};
  document.querySelectorAll(".adminReviewPkFilter").forEach(input=>previous[input.dataset.pkColumn]=input.value);
  document.querySelectorAll(".adminReviewExtraFilter").forEach(input=>previous[input.dataset.filterColumn]=input.value);
  box.classList.add("visible");
  box.innerHTML=`<div class="status">正在加载 ${escapeHtml(target)} 主键筛选项（包含逻辑删除记录）...</div>`;
  const meta=await getJson(`/api/admin/main_table?table=${encodeURIComponent(target)}&limit=1&include_options=1&include_deleted=1`);
  const pkColumns=tablePrimaryKeyColumns(target);
  const options=meta.filter_options||{};
  const pkHtml=pkColumns.map(column=>{
    const values=options[column]||[];
    const current=String(presets[column]??previous[column]??"");
    if(values.length){
      return `<label class="keyFilter"><span>${escapeHtml(fieldLabel(column))}</span><select class="adminReviewPkFilter" data-pk-column="${escapeHtml(column)}"><option value="">全部</option>${values.map(value=>`<option value="${escapeHtml(value)}" ${current===String(value)?"selected":""}>${escapeHtml(value)}</option>`).join("")}</select></label>`;
    }
    return `<label class="keyFilter"><span>${escapeHtml(fieldLabel(column))}</span><input class="adminReviewPkFilter" data-pk-column="${escapeHtml(column)}" value="${escapeHtml(current)}" placeholder="输入 ${escapeHtml(column)} 检索"></label>`;
  }).join("");
  const hasRecordVersionFilters=["data_record_lineage","data_import_records","audit_logs"].includes(table);
  const lineageHtml=hasRecordVersionFilters
    ? ["previous_record_version_id","record_version_id"].map(column=>{
        const current=String(presets[column]??previous[column]??"");
        const hint=column==="previous_record_version_id" ? "旧值版本，如 1；初始/来源可填 null" : "新值版本，如 0 或 2";
        return `<label class="keyFilter"><span>${escapeHtml(fieldLabel(column))}</span><input class="adminReviewExtraFilter" data-filter-column="${escapeHtml(column)}" value="${escapeHtml(current)}" placeholder="${escapeHtml(hint)}"></label>`;
      }).join("")
    : "";
  const lineageHint=hasRecordVersionFilters
    ? "；也可填写旧值记录版本和新值记录版本，查询某条记录的版本来源或修改过程"
    : "";
  const reviewMeaning={
    data_import_records:"来源/版本写入记录：说明该记录由谁、通过系统/SQL/前端、从哪个来源写入。",
    data_record_lineage:"记录修改追溯：说明该记录当前版本、上一版本、最后修改者和修改次数。",
    audit_logs:"审计日志：记录 UPDATE/DELETE 等操作的修改前数据和修改后数据。",
    soft_delete_records:"逻辑删除记录：保存被删除记录的完整快照，并支持恢复。"
  }[table]||"管理员审查记录。";
  box.innerHTML=pkHtml+lineageHtml+`<div class="status">${escapeHtml(reviewMeaning)}<br>按 ${escapeHtml(target)} 的主键检索当前审计表；不填主键则显示该关系的全部相关记录${lineageHint}。</div>`;
  document.querySelectorAll(".adminReviewPkFilter,.adminReviewExtraFilter").forEach(input=>{
    input.addEventListener("change",()=>openAdminReviewTable(table,{reloadFilters:false}));
    if(input.tagName==="INPUT")input.addEventListener("keydown",event=>{if(event.key==="Enter")openAdminReviewTable(table,{reloadFilters:false});});
  });
}
async function openAdminReviewTable(table,options={}){
  try{
    showPage("admin");
    state.adminReviewTable=table;
    const target=$("adminAuditTargetSelect")?.value||"airfoils";
    const params=new URLSearchParams({table,limit:"100"});
    if(table==="data_record_lineage"||table==="audit_logs"||table==="soft_delete_records"){
      params.set("filter_table_name",target);
    }else if(table==="data_import_records"){
      params.set("filter_target_table",target);
    }
    if(options.reloadFilters!==false){
      state.adminReviewPresetFilters=options.filters||{};
      await loadAdminReviewFilters(table);
    }
    const pkValues={};
    document.querySelectorAll(".adminReviewPkFilter").forEach(input=>{
      pkValues[input.dataset.pkColumn]=input.value.trim();
    });
    const recordPk=buildRecordPkFromFilters(target,pkValues);
    if(recordPk)params.set("filter_record_pk",recordPk);
    if(["data_record_lineage","data_import_records","audit_logs"].includes(table)){
      document.querySelectorAll(".adminReviewExtraFilter").forEach(input=>{
        const value=input.value.trim();
        if(value)params.set(`filter_${input.dataset.filterColumn}`,value);
      });
    }
    if(options.reloadFilters!==false)state.adminReviewPresetFilters={};
    $("adminResult").textContent=`正在审查 ${table} / ${target}...`;
    const data=await getJson(`/api/admin/main_table?${params.toString()}`);
    const label=table==="users"||table==="query_logs" ? data.table : `${data.table} · target ${target}`;
    const activeFilters=Object.entries(data.filters||{}).map(([k,v])=>`${escapeHtml(fieldLabel(k))} = "${escapeHtml(v)}"`).join(" · ")||"全部";
    const resultHtml=data.rows.length?rowsToTable(data.rows,{table:data.table}):noRowsHint(data.table,target,data.filters||{});
    $("adminResult").innerHTML=`<div class="status">Admin review: ${escapeHtml(label)} · showing ${data.rows.length} / ${data.total} rows · filters: ${activeFilters}</div>${resultHtml}`;
    attachAdminResultActions();
  }catch(e){
    $("adminResult").textContent=e.error||e.message||String(e);
  }
}
async function restoreSoftDeletedRecord(deleteId,table,recordPk){
  if(!confirm(`确认恢复 ${table}.${recordPk}？\n恢复后该记录会重新出现在主表查询和图表中。`))return;
  try{
    $("adminResult").insertAdjacentHTML("afterbegin",`<div class="status" id="restoreStatus">正在恢复 ${escapeHtml(table)}.${escapeHtml(recordPk)}...</div>`);
    const data=await postJson("/api/main_records/restore",{delete_id:deleteId});
    const status=$("restoreStatus");
    if(status)status.textContent=`已恢复 ${data.table}.${data.record_pk}，Time=${data.elapsed_ms} ms`;
    state.airfoils=await getJson("/api/airfoils");
    renderAirfoilList();
    if(state.selectedAirfoil)loadVersionData().catch(err=>console.error(err));
    await refreshMainDataAfterMutation({table,allTables:table==="airfoils"});
    await openAdminReviewTable("soft_delete_records");
  }catch(e){
    $("adminResult").insertAdjacentHTML("afterbegin",`<div class="status danger">恢复失败：${escapeHtml(e.error||e.message||"unknown error")}</div>`);
  }
}
function attachAdminResultActions(){
  document.querySelectorAll(".restoreDeleteBtn").forEach(btn=>{
    btn.addEventListener("click",()=>restoreSoftDeletedRecord(btn.dataset.deleteId,btn.dataset.table,btn.dataset.recordPk));
  });
  document.querySelectorAll(".lineageToAuditBtn").forEach(btn=>{
    btn.addEventListener("click",()=>{
      const row=JSON.parse(btn.dataset.row||"{}");
      const target=row.table_name||$("adminAuditTargetSelect")?.value||"airfoils";
      const presets={record_pk:String(row.record_pk??"")};
      const pkColumns=tablePrimaryKeyColumns(target);
      if(pkColumns.length===1){
        presets[pkColumns[0]]=String(row.record_pk??"");
      }
      if(row.previous_record_version_id!==undefined&&row.previous_record_version_id!==null){
        presets.previous_record_version_id=String(row.previous_record_version_id);
      }
      if(row.record_version_id!==undefined&&row.record_version_id!==null){
        presets.record_version_id=String(row.record_version_id);
      }
      $("adminAuditTargetSelect").value=target;
      openAdminReviewTable("audit_logs",{filters:presets});
    });
  });
}
function syncMainTableOptions(){
  const blocked=new Set(["users","query_logs","audit_logs","data_record_lineage","data_import_records","soft_delete_records","performance_import_staging","saved_transactions"]);
  Array.from($("adminTableSelect").options).forEach(option=>{
    option.hidden=!isAdmin()&&blocked.has(option.value);
  });
  if($("adminTableSelect").selectedOptions[0]?.hidden){
    $("adminTableSelect").value="airfoils";
  }
}
function invalidateMainTableFilters(table=null){
  if(!state.mainFilterCache)state.mainFilterCache={};
  if(table)delete state.mainFilterCache[table];
  else state.mainFilterCache={};
}
async function refreshAdminReviewAfterMutation(table){
  if(!isAdmin()||!state.adminReviewTable)return;
  if(!$("pageAdmin")?.classList.contains("active"))return;
  const target=$("adminAuditTargetSelect")?.value||"";
  if(table&&target&&table!==target&&!["airfoils","data_versions","coordinate_points","performance_records","anomaly_records","data_sources"].includes(target))return;
  const presets={};
  document.querySelectorAll(".adminReviewPkFilter").forEach(input=>presets[input.dataset.pkColumn]=input.value);
  document.querySelectorAll(".adminReviewExtraFilter").forEach(input=>presets[input.dataset.filterColumn]=input.value);
  try{
    await openAdminReviewTable(state.adminReviewTable,{filters:presets});
  }catch(err){
    console.error(err);
  }
}
async function refreshMainDataAfterMutation(options={}){
  const table=options.table||$("adminTableSelect")?.value||null;
  invalidateMainTableFilters(table);
  if(options.allTables)invalidateMainTableFilters();
  if(options.reloadAirfoils!==false){
    try{
      state.airfoils=await getJson("/api/airfoils");
      renderAirfoilList();
    }catch(err){console.error(err);}
  }
  if($("pageGovernance")?.classList.contains("active")){
    await loadMainTableFilters();
    await loadMainTable();
  }
  if(options.refreshAdminReview!==false){
    await refreshAdminReviewAfterMutation(table);
  }
  if(state.selectedAirfoil&&options.reloadVersion!==false){
    loadVersionData().catch(err=>console.error(err));
  }
}
async function loadMainTableFilters(){
  syncMainTableOptions();
  const table=$("adminTableSelect").value;
  const previous={};
  document.querySelectorAll(".mainTableFilter").forEach(select=>previous[select.dataset.column]=select.value);
  try{
    if(!state.mainFilterCache[table])$("mainTableFilterBox").innerHTML=`<div class="status">正在加载 ${escapeHtml(table)} 的筛选项...</div>`;
    const data=state.mainFilterCache[table]||await getJson(`/api/admin/main_table?table=${encodeURIComponent(table)}&limit=1&include_options=1`);
    state.mainFilterCache[table]=data;
    const filterColumns=data.filter_columns||[];
    const options=data.filter_options||{};
    $("mainTableFilterBox").innerHTML=filterColumns.length?filterColumns.map(column=>{
      const values=options[column]||[];
      return `<label class="keyFilter"><span>${escapeHtml(fieldLabel(column))}</span><select class="mainTableFilter" data-column="${escapeHtml(column)}"><option value="">全部</option>${values.map(value=>`<option value="${escapeHtml(value)}" ${String(previous[column]||"")===String(value)?"selected":""}>${escapeHtml(value)}</option>`).join("")}</select></label>`;
    }).join(""):`<div class="status">当前关系没有配置主键筛选项，默认显示全部记录。</div>`;
    document.querySelectorAll(".mainTableFilter").forEach(select=>select.addEventListener("change",loadMainTable));
    renderMainAddForm(false);
  }catch(e){
    $("mainTableFilterBox").innerHTML="";
    $("mainTableResult").textContent=e.error||e.message||String(e);
  }
}
async function changeMainTable(){
  await loadMainTableFilters();
  await loadMainTable();
}
function mainAddAllowedTable(){return ["data_sources","airfoils","data_versions","coordinate_points"].includes($("adminTableSelect").value);}
function renderMainAddForm(visible){
  const table=$("adminTableSelect").value;
  const canAdd=isManager()&&mainAddAllowedTable();
  $("mainAddControls").style.display=canAdd?"flex":"none";
  if(!canAdd){
    $("mainAddBox").style.display="none";
    $("mainAddBox").innerHTML="";
    return;
  }
  $("mainAddBox").style.display=visible?"grid":"none";
  $("toggleMainAddBtn").textContent=visible?"- 收起添加":"+ 添加记录";
  if(!visible)return;
  const sourceOptions=`<option value="uiuc_raw">uiuc_raw</option><option value="uiuc_raw_with_tracked_augmentation">uiuc_raw_with_tracked_augmentation</option><option value="generated_synthetic">generated_synthetic</option><option value="injected_anomaly">injected_anomaly</option>`;
  const field=(name,placeholder="",value="")=>`<label class="keyFilter"><span>${escapeHtml(fieldLabel(name))}</span><input class="mainAddInput" data-field="${escapeHtml(name)}" placeholder="${escapeHtml(placeholder||name)}" value="${escapeHtml(value)}"></label>`;
  const select=(name,options)=>`<label class="keyFilter"><span>${escapeHtml(fieldLabel(name))}</span><select class="mainAddInput" data-field="${escapeHtml(name)}">${options}</select></label>`;
  const airfoilOptions=(state.airfoils||[]).map(a=>`<option value="${escapeHtml(a.airfoil_id)}" ${a.airfoil_id===state.selectedAirfoil?"selected":""}>${escapeHtml(a.airfoil_id)} · ${escapeHtml(a.name||"")}</option>`).join("");
  const newId=`frontend_${Date.now().toString(36).slice(-6)}`;
  const selectedAirfoil=state.selectedAirfoil||(state.airfoils&&state.airfoils[0]?.airfoil_id)||"";
  let html="";
  if(table==="data_sources"){
    html=select("source_type",sourceOptions)+field("description","真实来源或生成规则说明");
  }else if(table==="airfoils"){
    html=[
      field("airfoil_id","如 naca0012",newId),
      field("name","翼型名称"),
      field("source","UIUC / Frontend Input","Frontend Input"),
      field("family","系列","Manual"),
      select("source_type",sourceOptions),
      field("source_file","来源文件",`frontend\\${newId}.dat`),
      field("original_point_count","原始点数","1"),
      field("final_point_count","最终点数","1"),
    ].join("");
  }else if(table==="data_versions"){
    html=[
      select("airfoil_id",airfoilOptions||`<option value="">请先加载 airfoils</option>`),
      field("version_id","版本号","99"),
      select("version_type",`<option value="imported_raw">imported_raw</option><option value="augmented_from_raw">augmented_from_raw</option>`),
      select("coordinate_source_type",`<option value="real_only">real_only</option><option value="mixed_real_and_augmented">mixed_real_and_augmented</option>`),
      field("description","版本说明","Frontend created data version"),
    ].join("");
  }else if(table==="coordinate_points"){
    html=[
      select("airfoil_id",airfoilOptions||`<option value="">请先加载 airfoils</option>`),
      field("version_id","版本号","1"),
      field("point_order","点序号","9999"),
      field("x","x 坐标","0.0"),
      field("y","y 坐标","0.0"),
      select("surface",`<option value="upper">upper</option><option value="lower">lower</option>`),
      select("point_source",`<option value="real">real</option><option value="augmented">augmented</option>`),
      select("is_augmented",`<option value="0">0</option><option value="1">1</option>`),
      field("original_order","原始序号，可空",""),
      select("augmentation_method",`<option value="original_coordinate">original_coordinate</option><option value="linear_interpolation">linear_interpolation</option>`),
    ].join("");
  }
  $("mainAddBox").innerHTML=html+`<button class="action primary" id="submitMainAddBtn">保存新增</button>`;
  attachMainAddFieldBehaviors(table);
  $("submitMainAddBtn").addEventListener("click",submitMainAddForm);
}
function attachMainAddFieldBehaviors(table){
  if(table==="airfoils"){
    const idInput=document.querySelector('.mainAddInput[data-field="airfoil_id"]');
    const sourceFile=document.querySelector('.mainAddInput[data-field="source_file"]');
    if(idInput&&sourceFile){
      const sync=()=>{
        const id=idInput.value.trim().toLowerCase().replace(/[^a-z0-9_]/g,"_");
        if(id)sourceFile.value=`frontend\\${id}.dat`;
      };
      idInput.addEventListener("input",sync);
      sync();
    }
    return;
  }
  if(table!=="coordinate_points")return;
  const pointSource=document.querySelector('.mainAddInput[data-field="point_source"]');
  const isAugmented=document.querySelector('.mainAddInput[data-field="is_augmented"]');
  const method=document.querySelector('.mainAddInput[data-field="augmentation_method"]');
  if(!pointSource||!isAugmented||!method)return;
  const sync=()=>{
    if(pointSource.value==="augmented"){
      isAugmented.value="1";
      method.value="linear_interpolation";
    }else{
      isAugmented.value="0";
      method.value="original_coordinate";
    }
  };
  pointSource.addEventListener("change",sync);
  isAugmented.addEventListener("change",()=>{
    pointSource.value=isAugmented.value==="1"?"augmented":"real";
    sync();
  });
  method.addEventListener("change",()=>{
    pointSource.value=method.value==="linear_interpolation"?"augmented":"real";
    sync();
  });
  sync();
}
function toggleMainAddForm(){
  const visible=$("mainAddBox").style.display==="none";
  renderMainAddForm(visible);
}
async function submitMainAddForm(){
  try{
    const table=$("adminTableSelect").value;
    const data={};
    document.querySelectorAll(".mainAddInput").forEach(input=>data[input.dataset.field]=input.value.trim());
    $("mainTableResult").textContent=`正在添加 ${table} 记录...`;
    const result=await postJson("/api/main_records/create",{table,data});
    $("mainTableResult").innerHTML=`<div class="status">Created ${escapeHtml(result.table)}.${escapeHtml(result.record_pk)} · Time=${result.elapsed_ms} ms</div>${rowsToTable(result.rows,{table:result.table})}`;
    await refreshMainDataAfterMutation({table,allTables:table==="airfoils"});
  }catch(e){
    $("mainTableResult").textContent=`Create record failed: ${e.error||e.message||"unknown error"}`;
  }
}
function inlineField(name,label,value,type="text",readOnly=false){
  return `<label>${escapeHtml(fieldLabel(label))}<input class="inlineEditInput" data-field="${escapeHtml(name)}" type="${escapeHtml(type)}" value="${escapeHtml(value??"")}" ${readOnly?"readonly":""}></label>`;
}
function inlineSelect(name,label,value,options){
  return `<label>${escapeHtml(fieldLabel(label))}<select class="inlineEditInput" data-field="${escapeHtml(name)}">${options.map(opt=>`<option value="${escapeHtml(opt)}" ${String(value??"")===String(opt)?"selected":""}>${escapeHtml(opt)}</option>`).join("")}</select></label>`;
}
function renderInlineEditForm(table,row,colspan){
  const sourceTypes=["uiuc_raw","uiuc_raw_with_tracked_augmentation","generated_synthetic","injected_anomaly"];
  const ruleTypes=["negative_cd","extreme_cl","missing_geometry","invalid_reynolds","manual_review"];
  let fields="";
  if(table==="airfoils"){
    fields=[
      inlineField("airfoil_id","airfoil_id",row.airfoil_id,"text",true),
      inlineField("name","name",row.name),
      inlineField("source","source",row.source),
      inlineField("family","family",row.family),
      inlineSelect("is_generated","is_generated",String(row.is_generated??0),["0","1"]),
      inlineSelect("source_type","source_type",row.source_type??"uiuc_raw",sourceTypes),
      inlineField("source_file","source_file",row.source_file),
      inlineSelect("has_augmented_coordinates","has_augmented_coordinates",String(row.has_augmented_coordinates??0),["0","1"]),
      inlineField("original_point_count","original_point_count",row.original_point_count,"number"),
      inlineField("final_point_count","final_point_count",row.final_point_count,"number")
    ].join("");
  }else if(table==="data_sources"){
    fields=[
      inlineField("source_type","source_type",row.source_type,"text",true),
      `<label>description<textarea class="inlineEditInput" data-field="description">${escapeHtml(row.description??"")}</textarea></label>`
    ].join("");
  }else if(table==="data_versions"){
    fields=[
      inlineField("airfoil_id","airfoil_id",row.airfoil_id,"text",true),
      inlineField("version_id","version_id",row.version_id,"number",true),
      inlineSelect("version_type","version_type",row.version_type??"imported_raw",["imported_raw","augmented_from_raw"]),
      inlineSelect("coordinate_source_type","coordinate_source_type",row.coordinate_source_type??"real_only",["real_only","mixed_real_and_augmented"]),
      `<label>description<textarea class="inlineEditInput" data-field="description">${escapeHtml(row.description??"")}</textarea></label>`
    ].join("");
  }else if(table==="coordinate_points"){
    fields=[
      inlineField("airfoil_id","airfoil_id",row.airfoil_id,"text",true),
      inlineField("version_id","version_id",row.version_id,"number",true),
      inlineField("point_order","point_order",row.point_order,"number",true),
      inlineField("x","x",row.x,"number"),
      inlineField("y","y",row.y,"number"),
      inlineSelect("surface","surface",row.surface??"upper",["upper","lower"]),
      inlineSelect("point_source","point_source",row.point_source??"real",["real","augmented"]),
      inlineSelect("is_augmented","is_augmented",String(row.is_augmented??0),["0","1"]),
      inlineField("original_order","original_order",row.original_order??"","number"),
      inlineSelect("augmentation_method","augmentation_method",row.augmentation_method??"original_coordinate",["original_coordinate","linear_interpolation"])
    ].join("");
  }else if(table==="performance_records"){
    fields=[
      inlineField("perf_id","perf_id",row.perf_id,"number",true),
      inlineField("cl","cl",row.cl,"number"),
      inlineField("cd","cd",row.cd,"number"),
      inlineField("cm","cm",row.cm,"number"),
      inlineSelect("is_anomaly","is_anomaly",String(row.is_anomaly??0),["0","1"])
    ].join("");
  }else if(table==="anomaly_records"){
    fields=[
      inlineField("anomaly_id","anomaly_id",row.anomaly_id,"number",true),
      inlineField("perf_id","perf_id",row.perf_id,"number"),
      inlineField("airfoil_id","airfoil_id",row.airfoil_id),
      inlineField("version_id","version_id",row.version_id,"number"),
      inlineSelect("rule_type","rule_type",row.rule_type??"extreme_cl",ruleTypes),
      `<label>detail<textarea class="inlineEditInput" data-field="detail">${escapeHtml(row.detail??"")}</textarea></label>`
    ].join("");
  }
  return `<tr class="inlineEditRow"><td class="inlineEditCell" colspan="${colspan}"><div class="inlineEditBox"><div class="status">正在编辑 ${escapeHtml(table)} 的当前记录</div><div class="inlineEditGrid">${fields}</div><div class="inlineEditActions"><button class="action primary inlineSaveBtn" data-table="${escapeHtml(table)}">保存修改</button><button class="action inlineCancelBtn">取消</button><span class="status inlineEditStatus"></span></div></div></td></tr>`;
}
function collectInlinePayload(rowEl){
  const payload={};
  rowEl.querySelectorAll(".inlineEditInput").forEach(input=>payload[input.dataset.field]=input.value.trim());
  return payload;
}
async function submitInlineEdit(table,rowEl){
  const status=rowEl.querySelector(".inlineEditStatus");
  const payload=collectInlinePayload(rowEl);
  const endpoint={data_sources:"/api/data_sources/update",airfoils:"/api/airfoils/update",data_versions:"/api/data_versions/update",coordinate_points:"/api/coordinate_points/update",performance_records:"/api/performance_records/update",anomaly_records:"/api/anomaly_records/update"}[table];
  try{
    status.textContent="正在保存...";
    const data=await postJson(endpoint,payload);
    status.textContent=`已保存，Affected=${data.affected_rows}，Time=${data.elapsed_ms} ms`;
    if(table==="airfoils"){
      getJson("/api/airfoils").then(rows=>{state.airfoils=rows;renderAirfoilList();}).catch(err=>console.error(err));
      if(state.selectedAirfoil===payload.airfoil_id)selectAirfoil(payload.airfoil_id).catch(err=>console.error(err));
    }else if(state.selectedAirfoil){
      loadVersionData().catch(err=>console.error(err));
    }
    setTimeout(()=>refreshMainDataAfterMutation({table,allTables:table==="airfoils"}).catch(err=>console.error(err)),350);
  }catch(e){
    status.textContent=`保存失败：${e.error||e.message||"unknown error"}`;
  }
}
async function softDeleteMainRecord(table,row){
  const label=row.airfoil_id||row.perf_id||row.anomaly_id||row.source_type||row.record_pk||"当前记录";
  if(!confirm(`确认逻辑删除 ${table}.${label}？\n业务表不会物理删除，完整行数据会写入 soft_delete_records。`))return;
  try{
    $("mainTableResult").insertAdjacentHTML("afterbegin",`<div class="status" id="softDeleteStatus">正在逻辑删除 ${escapeHtml(table)}.${escapeHtml(label)}...</div>`);
    const data=await postJson("/api/main_records/delete",{table,row,reason:"frontend logical delete"});
    const status=$("softDeleteStatus");
    if(status)status.textContent=`已逻辑删除 ${data.table}.${data.record_pk}，Time=${data.elapsed_ms} ms`;
    if(table==="airfoils"){
      state.airfoils=await getJson("/api/airfoils");
      renderAirfoilList();
      if(state.selectedAirfoil===row.airfoil_id){
        const next=state.airfoils[0]?.airfoil_id;
        state.selectedAirfoil=next||null;
        if(next)await selectAirfoil(next);
      }
    }else if(state.selectedAirfoil){
      loadVersionData().catch(err=>console.error(err));
    }
    await refreshMainDataAfterMutation({table,allTables:table==="airfoils"});
  }catch(e){
    $("mainTableResult").insertAdjacentHTML("afterbegin",`<div class="status danger">逻辑删除失败：${escapeHtml(e.error||e.message||"unknown error")}</div>`);
  }
}
function attachMainTableRowActions(){
  document.querySelectorAll(".rowEditBtn").forEach(button=>{
    button.addEventListener("click",()=>{
      document.querySelectorAll(".inlineEditRow").forEach(row=>row.remove());
      const table=button.dataset.table;
      const row=JSON.parse(button.dataset.row||"{}");
      const currentTr=button.closest("tr");
      const colspan=currentTr.children.length;
      currentTr.insertAdjacentHTML("afterend",renderInlineEditForm(table,row,colspan));
      const editRow=currentTr.nextElementSibling;
      editRow.querySelector(".inlineCancelBtn").addEventListener("click",()=>editRow.remove());
      editRow.querySelector(".inlineSaveBtn").addEventListener("click",()=>submitInlineEdit(table,editRow));
    });
  });
  document.querySelectorAll(".mainRowDeleteBtn").forEach(button=>{
    button.addEventListener("click",()=>{
      const table=button.dataset.table;
      const row=JSON.parse(button.dataset.row||"{}");
      softDeleteMainRecord(table,row);
    });
  });
  document.querySelectorAll(".rowAdminTraceBtn").forEach(button=>{
    button.addEventListener("click",()=>{
      const table=button.dataset.table;
      const reviewTable=button.dataset.reviewTable||"audit_logs";
      const row=JSON.parse(button.dataset.row||"{}");
      const presets={};
      tablePrimaryKeyColumns(table).forEach(column=>presets[column]=String(row[column]??""));
      $("adminAuditTargetSelect").value=table;
      openAdminReviewTable(reviewTable,{filters:presets});
    });
  });
}
async function loadMainTable(){
  try{
    showMainTableSection(true);
    $("governanceResult").style.display="none";
    syncMainTableOptions();
    const params=new URLSearchParams({table:$("adminTableSelect").value,limit:$("adminLimitSelect").value});
    document.querySelectorAll(".mainTableFilter").forEach(input=>{
      const value=input.value.trim();
      if(value)params.set(`filter_${input.dataset.column}`,value);
    });
    $("mainTableResult").textContent=`正在查询 ${$("adminTableSelect").value}...`;
    const data=await getJson(`/api/admin/main_table?${params.toString()}`);
    const activeFilters=Object.entries(data.filters||{}).map(([k,v])=>`${escapeHtml(k)} = "${escapeHtml(v)}"`).join(" · ")||"全部";
    $("mainTableResult").innerHTML=`<div class="status">Table: ${escapeHtml(data.table)} · showing ${data.rows.length} / ${data.total} rows · filters: ${activeFilters}</div>`+rowsToTable(data.rows,{table:data.table});
    attachMainTableRowActions();
  }catch(e){
    $("mainTableResult").textContent=e.error||e.message||String(e);
  }
}
async function adminCreateUser(){try{const data=await postJson("/api/admin/users/create",{username:$("adminNewUsername").value.trim(),password:$("adminNewPassword").value,role:$("adminNewRole").value});$("adminResult").textContent=`Created user: ${data.username} (${data.role})`; $("adminNewPassword").value="";}catch(e){$("adminResult").textContent=`Create user failed: ${e.error||"unknown error"}`;}}
async function createAirfoil(){try{const c=Number($("newAirfoilPoints").value||1);const id=$("newAirfoilId").value.trim();const data=await postJson("/api/airfoils/create",{airfoil_id:id,name:$("newAirfoilName").value.trim(),family:$("newAirfoilFamily").value.trim()||"Manual",original_point_count:c,final_point_count:c,source_file:`manual\\${id}.dat`});$("sqlResult").textContent=`Create ok: ${data.airfoil_id}`;await refreshMainDataAfterMutation({table:"airfoils",allTables:true});}catch(e){$("sqlResult").textContent=`Create failed: ${e.error||"unknown error"}`;}}
async function updateAirfoilRecord(){
  try{
    $("governanceResult").textContent="正在更新 airfoils 记录...";
    const payload={
      airfoil_id:$("editAirfoilId").value.trim(),
      name:$("editAirfoilName").value.trim(),
      source:$("editAirfoilSource").value.trim(),
      family:$("editAirfoilFamily").value.trim(),
      is_generated:$("editAirfoilGenerated").value,
      source_type:$("editAirfoilSourceType").value,
      source_file:$("editAirfoilSourceFile").value.trim(),
      has_augmented_coordinates:$("editAirfoilAugmented").value,
      original_point_count:$("editAirfoilOriginalPoints").value.trim(),
      final_point_count:$("editAirfoilFinalPoints").value.trim()
    };
    const data=await postJson("/api/airfoils/update",payload);
    $("governanceResult").innerHTML=`<div class="status">Updated airfoil. Affected=${data.affected_rows} · Time=${data.elapsed_ms} ms</div>${rowsToTable(data.rows,{table:"airfoils"})}`;
    refreshMainDataAfterMutation({table:"airfoils",allTables:true}).catch(err=>console.error(err));
    if(state.selectedAirfoil===payload.airfoil_id)selectAirfoil(payload.airfoil_id).catch(err=>console.error(err));
  }catch(e){
    $("governanceResult").textContent=`Update airfoil failed: ${e.error||"unknown error"}`;
  }
}
async function updatePerformanceRecord(){
  try{
    $("governanceResult").textContent="正在更新 performance_records 记录...";
    const payload={
      perf_id:$("editPerfId").value.trim(),
      cl:$("editCl").value.trim(),
      cd:$("editCd").value.trim(),
      cm:$("editCm").value.trim(),
      is_anomaly:$("editIsAnomaly").value
    };
    const data=await postJson("/api/performance_records/update",payload);
    $("governanceResult").innerHTML=`<div class="status">Updated performance record. Affected=${data.affected_rows} · Time=${data.elapsed_ms} ms</div>${rowsToTable(data.rows)}`;
    refreshMainDataAfterMutation({table:"performance_records",reloadAirfoils:false}).catch(err=>console.error(err));
    if(state.selectedAirfoil)loadVersionData().catch(err=>console.error(err));
  }catch(e){
    $("governanceResult").textContent=`Update performance failed: ${e.error||"unknown error"}`;
  }
}
async function updateAnomalyRecord(){
  try{
    $("governanceResult").textContent="正在更新 anomaly_records 记录...";
    const payload={
      anomaly_id:$("editAnomalyId").value.trim(),
      perf_id:$("editAnomalyPerfId").value.trim(),
      airfoil_id:$("editAnomalyAirfoilId").value.trim(),
      version_id:$("editAnomalyVersionId").value.trim(),
      rule_type:$("editAnomalyRuleType").value,
      detail:$("editAnomalyDetail").value.trim()
    };
    const data=await postJson("/api/anomaly_records/update",payload);
    $("governanceResult").innerHTML=`<div class="status">Updated anomaly record. Affected=${data.affected_rows} · Time=${data.elapsed_ms} ms</div>${rowsToTable(data.rows,{table:"anomaly_records"})}`;
    refreshMainDataAfterMutation({table:"anomaly_records",reloadAirfoils:false}).catch(err=>console.error(err));
    if(state.selectedAirfoil)loadVersionData().catch(err=>console.error(err));
  }catch(e){
    $("governanceResult").textContent=`Update anomaly failed: ${e.error||"unknown error"}`;
  }
}
const BATCH_HEADERS={
  data_sources:["source_type","description"],
  airfoils:["airfoil_id","name","source","family","is_generated","source_type","source_file","has_augmented_coordinates","original_point_count","final_point_count"],
  data_versions:["airfoil_id","version_id","version_type","coordinate_source_type","description"],
  coordinate_points:["airfoil_id","version_id","point_order","x","y","surface","point_source","is_augmented","original_order","augmentation_method"],
  performance_records:["perf_id","airfoil_id","version_id","alpha_deg","reynolds_number","cl","cd","cm","source_type","is_anomaly"]
};
const BATCH_SAMPLES={
  good:{
    data_sources:`source_type,description
ui_batch_source,Frontend CSV source description`,
    airfoils:`airfoil_id,name,source,family,is_generated,source_type,source_file,has_augmented_coordinates,original_point_count,final_point_count
batchaf01,Batch Airfoil 01,Frontend Batch,Manual,0,generated_synthetic,batch/batchaf01.dat,0,1,1`,
    data_versions:`airfoil_id,version_id,version_type,coordinate_source_type,description
ag03,2,augmented_from_raw,mixed_real_and_augmented,Frontend batch data version`,
    coordinate_points:`airfoil_id,version_id,point_order,x,y,surface,point_source,is_augmented,original_order,augmentation_method
ag03,1,999,0.5,0.02,upper,real,0,,original_coordinate`,
    performance_records:`perf_id,airfoil_id,version_id,alpha_deg,reynolds_number,cl,cd,cm,source_type,is_anomaly
9910201,ag03,1,-3,123460,0.36,0.013,0.0,generated_synthetic,0
9910202,ag03,1,3,123460,0.66,0.015,0.0,generated_synthetic,0`
  },
  bad:{
    data_sources:`source_type,description
,Bad source without primary key`,
    airfoils:`airfoil_id,name,source,family,is_generated,source_type,source_file,has_augmented_coordinates,original_point_count,final_point_count
batchaf_bad,Bad Airfoil,Frontend Batch,Manual,2,generated_synthetic,batch/bad.dat,0,1,1`,
    data_versions:`airfoil_id,version_id,version_type,coordinate_source_type,description
ag03,3,bad_version_type,mixed_real_and_augmented,Bad version type`,
    coordinate_points:`airfoil_id,version_id,point_order,x,y,surface,point_source,is_augmented,original_order,augmentation_method
ag03,1,1000,0.5,0.02,middle,real,0,,original_coordinate`,
    performance_records:`perf_id,airfoil_id,version_id,alpha_deg,reynolds_number,cl,cd,cm,source_type,is_anomaly
9910101,ag03,1,0,123459,0.52,0.011,0.0,generated_synthetic,0
9910102,ag03,1,99,123459,0.60,0.014,0.0,generated_synthetic,0`
  }
};
function updateBatchHeaderHint(){
  const table=$("batchImportTarget").value;
  const header=(BATCH_HEADERS[table]||[]).join(",");
  const idNote=table==="performance_records"
    ?"<br><span class='status'>说明：perf_id 可作为文件内临时编号从 1 开始填写；导入时系统会自动重映射为数据库中的全局唯一主键，并在结果中显示映射表。异常数据表不支持直接批量导入，应由异常检测规则生成。</span>"
    :"";
  $("batchExpectedHeader").innerHTML=`<b>目标关系：</b>${escapeHtml(table)}<br><b>期望表头：</b><code>${escapeHtml(header)}</code>${fieldGlossaryHtml(BATCH_HEADERS[table]||[])}<br><span class="status">请保证 CSV/TSV 第一行表头与上面完全一致，列名不能缺失、不能多出、不能乱序；数据行也要按同样顺序填写。</span>${idNote}`;
}
async function loadBatchFile(){
  const file=$("batchImportFile").files[0];
  if(!file)return;
  $("batchImportInput").value=await file.text();
  $("batchImportResult").textContent=`已读取本地文件：${file.name}。请核对目标关系和表头顺序后再导入。`;
}
function loadBatchSample(kind){
  const table=$("batchImportTarget").value;
  const sample=BATCH_SAMPLES[kind]&&BATCH_SAMPLES[kind][table];
  if(!sample){
    $("batchImportResult").textContent=`No ${kind} sample is configured for ${table}.`;
    return;
  }
  $("batchImportId").value=kind==="bad"?"ui_bad_batch":"ui_good_batch";
  $("batchImportInput").value=sample;
  updateBatchHeaderHint();
  $("batchImportResult").textContent=`Loaded ${kind} sample for ${table}. 请确认表头与目标关系属性顺序完全一致后导入。`;
}
function parseDelimitedLine(line,delimiter){
  const values=[];
  let current="";
  let quoted=false;
  for(let i=0;i<line.length;i++){
    const ch=line[i];
    if(ch==='"'){
      if(quoted&&line[i+1]==='"'){current+='"';i++;}
      else quoted=!quoted;
    }else if(ch===delimiter&&!quoted){
      values.push(current.trim());
      current="";
    }else{
      current+=ch;
    }
  }
  values.push(current.trim());
  return values;
}
function parseDelimitedRows(text,table){
  const lines=text.trim().split(/\r?\n/).filter(line=>line.trim().length>0);
  if(lines.length<2)throw new Error("至少需要一行表头和一行数据。");
  const delimiter=lines[0].includes("\t")?"\t":",";
  const headers=parseDelimitedLine(lines[0],delimiter);
  const expected=BATCH_HEADERS[table]||[];
  if(headers.length!==expected.length||headers.some((h,i)=>h!==expected[i])){
    throw new Error(`表头不匹配。请选择正确关系并按属性顺序排列。期望: ${expected.join(",")}；实际: ${headers.join(",")}`);
  }
  const rows=lines.slice(1).map((line,index)=>{
    const values=parseDelimitedLine(line,delimiter);
    if(values.length!==headers.length){
      throw new Error(`第 ${index+2} 行列数不正确。期望 ${headers.length} 列，实际 ${values.length} 列。`);
    }
    const row={};
    headers.forEach((h,i)=>row[h]=values[i]??"");
    return row;
  });
  return {headers,rows};
}
async function runBatchImport(){
  try{
    const table=$("batchImportTarget").value;
    const parsed=parseDelimitedRows($("batchImportInput").value,table);
    const data=await postJson("/api/batch_import/run",{table,batch_id:$("batchImportId").value.trim(),headers:parsed.headers,rows:parsed.rows});
    const pieces=[`<div class="status">Table=${escapeHtml(data.target_table||table)} · Batch=${escapeHtml(data.batch_id)} · Time=${data.elapsed_ms} ms</div>`];
    (data.sections||[]).forEach(section=>{pieces.push(`<h2>${escapeHtml(section.title)}</h2>${rowsToTable(section.rows||[])}`);});
    $("batchImportResult").innerHTML=pieces.join("");
    await refreshMainDataAfterMutation({table,allTables:["airfoils","data_versions","coordinate_points"].includes(table)});
  }catch(e){
    $("batchImportResult").textContent=`Batch import failed: ${e.error||e.message||"unknown error"}`;
  }
}
function loadBulkImportScenario(){$("transactionSqlInput").value=`INSERT INTO performance_records
(perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
VALUES
(9000001, 'ag03', 1, 0, 123456, 0.5, 0.01, 0.0, 'generated_synthetic', 0);

INSERT INTO performance_records
(perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
VALUES
(9000002, 'ag03', 1, 99, 123456, 0.6, 0.02, 0.0, 'generated_synthetic', 0);

SELECT perf_id, airfoil_id, alpha_deg, reynolds_number, cl, cd
FROM performance_records
WHERE perf_id IN (9000001, 9000002);`;$("transactionResult").textContent="场景2已填入：建议点击“执行并提交”，第二条 INSERT 会违反 alpha_deg CHECK，整批回滚。";}
function loadVersionAtomicScenario(){$("transactionSqlInput").value=`DELETE FROM data_versions
WHERE airfoil_id IN ('txn3_src', 'txn3_dst');

DELETE FROM airfoils
WHERE airfoil_id IN ('txn3_src', 'txn3_dst');

INSERT INTO airfoils
    (airfoil_id, name, source, family, is_generated, source_type, source_file,
     has_augmented_coordinates, original_point_count, final_point_count)
VALUES
    ('txn3_src', 'TXN Cascade Source', 'Transaction Experiment', 'Txn Cascade',
     1, 'generated_synthetic', 'txn/txn3_src.dat', 0, 1, 1);

INSERT INTO data_versions
    (airfoil_id, version_id, version_type, coordinate_source_type, description)
VALUES
    ('txn3_src', 1, 'imported_raw', 'real_only',
     'version row used to verify ON UPDATE CASCADE');

UPDATE airfoils
SET airfoil_id = 'txn3_dst'
WHERE airfoil_id = 'txn3_src';

SELECT a.airfoil_id AS airfoil_pk,
       v.airfoil_id AS version_fk,
       v.version_id,
       v.version_type,
       v.description
FROM airfoils a
JOIN data_versions v ON v.airfoil_id = a.airfoil_id
WHERE a.airfoil_id IN ('txn3_src', 'txn3_dst')
ORDER BY a.airfoil_id, v.version_id;`;$("transactionResult").textContent="场景3已填入：这里只手动 UPDATE 主表 airfoils.airfoil_id，data_versions.airfoil_id 依靠外键 ON UPDATE CASCADE 自动同步。点击“执行并回滚”可证明主表和版本表一同失败；点击“执行并提交”可证明二者一同成功。";}
function renderSavedTransactions(){
  const select=$("savedTransactionSelect");
  select.innerHTML=state.savedTransactions.map(r=>`<option value="${r.saved_id}">${escapeHtml(r.title)}</option>`).join("")||`<option value="">No saved transactions</option>`;
}
async function refreshSavedTransactions(){
  if(!state.currentUser){state.savedTransactions=[];renderSavedTransactions();return;}
  try{
    state.savedTransactions=await getJson("/api/saved_transactions");
    renderSavedTransactions();
  }catch(e){
    state.savedTransactions=[];
    renderSavedTransactions();
    $("transactionResult").textContent=`Load saved transactions failed: ${e.error||e.message||"unknown error"}`;
  }
}
async function saveCurrentTransaction(){
  try{
    const title=$("savedTransactionTitle").value.trim();
    const data=await postJson("/api/saved_transactions/save",{title,sql:$("transactionSqlInput").value});
    $("transactionResult").textContent=`Saved transaction: ${data.title}`;
    await refreshSavedTransactions();
    $("savedTransactionSelect").value=String(data.saved_id);
  }catch(e){
    $("transactionResult").textContent=`Save transaction failed: ${e.error||"unknown error"}`;
  }
}
function loadSelectedSavedTransaction(){
  const id=Number($("savedTransactionSelect").value||0);
  const item=state.savedTransactions.find(r=>Number(r.saved_id)===id);
  if(!item){$("transactionResult").textContent="No saved transaction selected.";return;}
  $("savedTransactionTitle").value=item.title;
  $("transactionSqlInput").value=item.sql_text;
  $("transactionResult").textContent=`Loaded transaction: ${item.title}`;
}
async function deleteSelectedSavedTransaction(){
  try{
    const id=Number($("savedTransactionSelect").value||0);
    if(!id){$("transactionResult").textContent="No saved transaction selected.";return;}
    await postJson("/api/saved_transactions/delete",{saved_id:id});
    $("transactionResult").textContent="Deleted saved transaction.";
    $("savedTransactionTitle").value="";
    await refreshSavedTransactions();
  }catch(e){
    $("transactionResult").textContent=`Delete transaction failed: ${e.error||"unknown error"}`;
  }
}
function renderTransactionQueue(){
  const box=$("transactionQueueList");
  if(!box)return;
  if(!state.transactionQueue.length){
    box.textContent="事务列表为空。先保存事务，再从下拉框加入列表。";
    return;
  }
  box.innerHTML=state.transactionQueue.map((item,index)=>`
    <div class="queueItem">
      <span class="badge">${index+1}</span>
      <strong>${escapeHtml(item.title)}</strong>
      <button class="action queueMoveBtn" data-index="${index}" data-dir="-1" title="上移">↑</button>
      <button class="action queueMoveBtn" data-index="${index}" data-dir="1" title="下移">↓</button>
      <button class="action rowDeleteBtn queueRemoveBtn" data-index="${index}" title="移除">×</button>
      <div class="status" style="grid-column:2 / -1">${escapeHtml(String(item.sql_text||"").split(/\s+/).slice(0,18).join(" "))}</div>
    </div>
  `).join("");
  document.querySelectorAll(".queueMoveBtn").forEach(btn=>btn.addEventListener("click",()=>{
    const index=Number(btn.dataset.index),dir=Number(btn.dataset.dir),next=index+dir;
    if(next<0||next>=state.transactionQueue.length)return;
    const copy=[...state.transactionQueue];
    [copy[index],copy[next]]=[copy[next],copy[index]];
    state.transactionQueue=copy;
    renderTransactionQueue();
  }));
  document.querySelectorAll(".queueRemoveBtn").forEach(btn=>btn.addEventListener("click",()=>{
    const index=Number(btn.dataset.index);
    state.transactionQueue=state.transactionQueue.filter((_,i)=>i!==index);
    renderTransactionQueue();
  }));
}
function addSelectedTransactionToQueue(){
  const id=Number($("savedTransactionSelect").value||0);
  const item=state.savedTransactions.find(r=>Number(r.saved_id)===id);
  if(!item){$("transactionResult").textContent="No saved transaction selected.";return;}
  state.transactionQueue.push(item);
  renderTransactionQueue();
  $("transactionResult").textContent=`Added to transaction list: ${item.title}`;
}
function clearTransactionQueue(){
  state.transactionQueue=[];
  renderTransactionQueue();
  $("transactionResult").textContent="Transaction list cleared.";
}
function transactionTimelineChart(data){
  const events=(data.timeline||[]).map(e=>({...e,at_ms:Number(e.at_ms||0),elapsed_ms:e.elapsed_ms==null?0:Number(e.elapsed_ms||0)}));
  if(!events.length)return `<div class="status">No timeline events.</div>`;
  const total=Math.max(Number(data.elapsed_ms||0),...events.map(e=>e.at_ms+Math.max(e.elapsed_ms,0.1)),1);
  const lanes=[...new Map(events.map(e=>[`${e.queue_step}:${e.transaction}`,{queue_step:e.queue_step,transaction:e.transaction}])).values()];
  const svgW=1040, left=160, right=28, top=34, laneH=48, plotW=svgW-left-right;
  const svgH=top+lanes.length*laneH+42;
  const x=ms=>left+(Math.max(0,Math.min(total,ms))/total)*plotW;
  const ticks=[0,total/4,total/2,total*3/4,total];
  const grid=ticks.map(t=>`<line class="gridLine" x1="${x(t)}" y1="20" x2="${x(t)}" y2="${svgH-24}"></line><text x="${x(t)}" y="16" text-anchor="${t===0?"start":t===total?"end":"middle"}">${num(t,2)} ms</text>`).join("");
  const lanesHtml=lanes.map((lane,laneIndex)=>{
    const cy=top+laneIndex*laneH+26;
    const laneEvents=events.filter(e=>e.queue_step===lane.queue_step&&e.transaction===lane.transaction);
    const start=Math.min(...laneEvents.map(e=>e.at_ms));
    const end=Math.max(...laneEvents.map(e=>e.at_ms+Math.max(e.elapsed_ms,0)));
    const startX=x(start);
    const barW=Math.max(8,x(end)-startX);
    const title=`${lane.transaction} · start ${num(start,3)} ms · end ${num(end,3)} ms · duration ${num(end-start,3)} ms`;
    return `<g><text class="laneLabel" x="12" y="${cy+4}">T${lane.queue_step}: ${escapeHtml(lane.transaction)}</text><line class="axis" x1="${left}" y1="${cy}" x2="${svgW-right}" y2="${cy}"></line><g><title>${escapeHtml(title)}</title><rect class="txnDurationBar" x="${startX}" y="${cy-9}" width="${barW}" height="18" rx="9"></rect></g></g>`;
  }).join("");
  return `<div class="txnChartWrap"><svg class="txnSvg" viewBox="0 0 ${svgW} ${svgH}" role="img" aria-label="Transaction duration timeline">${grid}${lanesHtml}</svg></div>`;
}
function renderTransactionTimeline(data){
  const pieces=[
    `<div class="status">Queue status=${escapeHtml(data.status)} · Mode=${escapeHtml(data.mode)} · Transactions=${data.queue_count} · Time=${data.elapsed_ms} ms</div>`,
    `<h2>Timeline Chart</h2>`,
    transactionTimelineChart(data),
    `<h2>Timeline Events</h2>`,
    rowsToTable(data.timeline||[])
  ];
  (data.transactions||[]).forEach(tx=>{
    pieces.push(`<h2>Transaction ${tx.queue_step}: ${escapeHtml(tx.title)} · ${escapeHtml(tx.status)} · ${tx.elapsed_ms} ms</h2>`);
    if(tx.error)pieces.push(`<div class="status danger">Error: ${escapeHtml(tx.error)}</div>`);
    (tx.results||[]).forEach(r=>{
      pieces.push(`<div class="status">Step ${r.step} · ${escapeHtml(r.type)} · ${r.elapsed_ms} ms · ${escapeHtml(r.sql)}</div>`);
      if(r.rows&&r.rows.length){pieces.push(rowsToTable(r.rows));}
      else{pieces.push(`<div class="status">Affected rows: ${r.affected_rows??0}</div>`);}
    });
  });
  $("transactionResult").innerHTML=pieces.join("");
}
async function runTransactionQueue(mode){
  try{
    if(!state.transactionQueue.length){$("transactionResult").textContent="Transaction list is empty.";return;}
    $("transactionResult").textContent="Transaction queue running...";
    const d=await postJson("/api/transaction_experiment/run_queue",{mode,saved_ids:state.transactionQueue.map(x=>x.saved_id)});
    renderTransactionTimeline(d);
    if(mode==="commit"){
      await refreshMainDataAfterMutation({allTables:true});
    }
  }catch(e){
    if(e.timeline||e.transactions){renderTransactionTimeline(e);}
    else{$("transactionResult").textContent=`Transaction queue failed: ${e.error||"unknown error"}`;}
  }
}
async function runConcurrencyScenario(){try{$("transactionResult").textContent="并发实验运行中：User A 持有行锁约 2 秒，User B 会等待...";const d=await postJson("/api/transaction_experiment/concurrency",{perf_id:9100001});const pieces=[`<div class="status">Status=${d.status} · perf_id=${d.perf_id} · Time=${d.elapsed_ms} ms</div><h2>Timeline</h2>${rowsToTable(d.steps)}`];if(d.errors&&d.errors.length){pieces.push(`<h2>Errors</h2>${rowsToTable(d.errors.map(x=>({error:x})))}`);}pieces.push(`<h2>Final Record</h2>${rowsToTable(d.final_rows)}`);$("transactionResult").innerHTML=pieces.join("");}catch(e){$("transactionResult").textContent=`Concurrency experiment failed: ${e.error||"unknown error"}`;}}
async function runTransaction(mode){try{const d=await postJson("/api/transaction_experiment/run",{sql:$("transactionSqlInput").value,mode});const pieces=[`<div class="status">Status=${d.status} · Statements=${d.statement_count} · Time=${d.elapsed_ms} ms</div>`];d.results.forEach(r=>{pieces.push(`<h2>Step ${r.step} · ${escapeHtml(r.type)} · ${r.elapsed_ms} ms</h2><div class="status">${escapeHtml(r.sql)}</div>`);if(r.rows&&r.rows.length){pieces.push(rowsToTable(r.rows));}else{pieces.push(`<div class="status">Affected rows: ${r.affected_rows??0}</div>`);}});$("transactionResult").innerHTML=pieces.join("");if(mode==="commit"){state.airfoils=await getJson("/api/airfoils");renderAirfoilList();if(state.selectedAirfoil)selectAirfoil(state.selectedAirfoil);}}catch(e){const partial=e.results&&e.results.length?`<h2>Partial Results</h2>${e.results.map(r=>`<div class="status">Step ${r.step}: ${escapeHtml(r.type)} · affected ${r.affected_rows??0}</div>`).join("")}`:"";$("transactionResult").innerHTML=`Transaction failed: ${escapeHtml(e.error||"unknown error")}<br>Status: ${escapeHtml(e.status||"rolled back")}${partial}`;}}
async function runTransaction(mode){
  try{
    const d=await postJson("/api/transaction_experiment/run",{sql:$("transactionSqlInput").value,mode});
    const pieces=[`<div class="status">Status=${d.status} · Statements=${d.statement_count} · Time=${d.elapsed_ms} ms</div>`];
    d.results.forEach(r=>{
      pieces.push(`<h2>Step ${r.step} · ${escapeHtml(r.type)} · ${r.elapsed_ms} ms</h2><div class="status">${escapeHtml(r.sql)}</div>`);
      if(r.rows&&r.rows.length){pieces.push(rowsToTable(r.rows));}
      else{pieces.push(`<div class="status">Affected rows: ${r.affected_rows??0}</div>`);}
    });
    $("transactionResult").innerHTML=pieces.join("");
    if(mode==="commit")await refreshMainDataAfterMutation({allTables:true});
  }catch(e){
    const partial=e.results&&e.results.length?`<h2>Partial Results</h2>${e.results.map(r=>`<div class="status">Step ${r.step}: ${escapeHtml(r.type)} · affected ${r.affected_rows??0}</div>`).join("")}`:"";
    $("transactionResult").innerHTML=`Transaction failed: ${escapeHtml(e.error||"unknown error")}<br>Status: ${escapeHtml(e.status||"rolled back")}${partial}`;
  }
}
async function runDbObjectExperiment(scenario){
  try{
    $("dbObjectResult").textContent="Running database object experiment...";
    document.querySelectorAll(".dbObjectBtn").forEach(b=>b.classList.toggle("primary",b.dataset.scenario===scenario));
    const d=await postJson("/api/db_object_experiment/run",{scenario});
    const dbObjectDefinitionHtml=(d.definition_blocks&&d.definition_blocks.length)
      ? `<h2>对象定义 SQL</h2><div class="status">下面展示本场景依赖的视图、触发器或存储过程定义。点击标题可展开查看代码。</div>${d.definition_blocks.map((block,index)=>`<details class="sqlBlock"><summary>对象 ${index+1}：${escapeHtml(block.title||"")}</summary>${sqlPre(block.sql||"")}</details>`).join("")}`
      : "";
    const dbObjectSqlBlocksHtml=(d.sql_blocks&&d.sql_blocks.length)
      ? `<h2>实验执行 SQL</h2>${d.sql_blocks.map((block,index)=>`<details class="sqlBlock" open><summary>SQL ${index+1}：${escapeHtml(block.title||"")}</summary>${sqlPre(block.sql||"")}</details>`).join("")}`
      : "";
    const pieces=[`<div class="status">Scenario=${escapeHtml(d.scenario)} · Time=${d.elapsed_ms} ms</div>`];
    (d.sections||[]).forEach(section=>{
      pieces.push(`<h2>${escapeHtml(section.title)}</h2>`);
      if(section.note){pieces.push(`<div class="status">${escapeHtml(section.note)}</div>`);}
      pieces.push(rowsToTable(section.rows||[]));
    });
    if(dbObjectSqlBlocksHtml)pieces.splice(1,0,dbObjectSqlBlocksHtml);
    if(dbObjectDefinitionHtml)pieces.splice(1,0,dbObjectDefinitionHtml);
    $("dbObjectResult").innerHTML=pieces.join("");
    await refreshMainDataAfterMutation({allTables:true,refreshAdminReview:false});
  }catch(e){
    $("dbObjectResult").textContent=`Experiment failed: ${e.error||"unknown error"}`;
  }
}
function renderAirfoilList(){const q=$("search").value.trim().toLowerCase();const list=$("airfoilList");list.innerHTML="";state.airfoils.filter(r=>!q||r.airfoil_id.toLowerCase().includes(q)||r.name.toLowerCase().includes(q)).forEach(r=>{const b=document.createElement("button");b.className="item"+(state.selectedAirfoil===r.airfoil_id?" active":"");b.innerHTML=`<div><strong>${r.airfoil_id} · ${r.name}</strong><span>${r.final_point_count} points · ${r.performance_count} perf</span></div><div class="badge">${r.anomaly_count}</div>`;b.onclick=()=>selectAirfoil(r.airfoil_id);list.appendChild(b);});}
async function selectAirfoil(id){
  state.selectedAirfoil=id;
  renderAirfoilList();
  const data=await getJson(`/api/airfoils/${encodeURIComponent(id)}`);
  state.versions=data.versions||[];
  const a=data.airfoil;
  $("airfoilTitle").textContent=`${a.airfoil_id} · ${a.name}`;
  $("airfoilMeta").innerHTML=[
    `<span><b>数据来源类型：</b>${escapeHtml(a.source_type||"-")}</span>`,
    `<span><b>源文件路径：</b>${escapeHtml(a.source_file||"-")}</span>`,
    `<span><b>坐标点数量：</b>原始 ${escapeHtml(a.original_point_count)}，最终 ${escapeHtml(a.final_point_count)}</span>`
  ].join("<br>");
  $("versionSelect").innerHTML=state.versions.map(v=>`<option value="${v.version_id}">version ${v.version_id} · ${v.version_type}</option>`).join("");
  if(!state.versions.length){
    state.coordinates=[];
    state.performance=[];
    state.anomalies=[];
    $("coordStatus").textContent="0 points";
    $("perfStatus").textContent="0 records";
    $("anomalyStatus").textContent="0 anomalies";
    drawShape();drawPerformance();drawCd();drawLd();
    return;
  }
  state.selectedVersion=Number(state.versions[0].version_id);
  await loadVersionData();
}
function syncReSelects(values){
  const options=values.map(re=>`<option value="${re}">Re ${re.toLocaleString()}（雷诺数）</option>`).join("");
  ["reSelect","cdReSelect","ldReSelect"].forEach(id=>{
    $(id).innerHTML=options;
    $(id).value=String(state.selectedRe);
  });
}
function changeSelectedRe(value){
  state.selectedRe=Number(value);
  ["reSelect","cdReSelect","ldReSelect"].forEach(id=>$(id).value=String(state.selectedRe));
  drawPerformance();
  drawCd();
  drawLd();
  scheduleSecondaryCharts();
}
async function loadVersionData(){
  ["shapeTooltip","perfTooltip","cdTooltip","ldTooltip","compareTooltip","versionDiffTooltip"].forEach(hideTooltip);
  const id=encodeURIComponent(state.selectedAirfoil),v=state.selectedVersion;
  try{
    const [coords,perf,anom]=await Promise.all([
      getJson(`/api/coordinates?airfoil_id=${id}&version_id=${v}`),
      getJson(`/api/performance?airfoil_id=${id}&version_id=${v}`),
      getJson(`/api/anomalies?airfoil_id=${id}&version_id=${v}`)
    ]);
    state.coordinates=coords;
    state.performance=perf;
    state.anomalies=anom;
    const res=[...new Set(perf.map(r=>Number(r.reynolds_number)))].sort((a,b)=>a-b);
    state.selectedRe=res.includes(state.selectedRe)?state.selectedRe:(res[0]||50000);
    syncReSelects(res);
    const upperCount=coords.filter(r=>r.surface==="upper").length;
    const lowerCount=coords.filter(r=>r.surface==="lower").length;
    const augCount=coords.filter(r=>Number(r.is_augmented)===1||r.point_source==="augmented").length;
    $("coordStatus").textContent=`${coords.length} points · upper ${upperCount} / lower ${lowerCount} · augmented ${augCount} · anomalies ${anom.length}`;
    $("perfStatus").textContent=`${perf.length} records`;
    $("anomalyStatus").textContent=`${anom.length} anomalies`;
    renderMetrics();renderAnomalies();drawShape();drawPerformance();drawCd();drawLd();scheduleSecondaryCharts();
  }catch(e){
    state.coordinates=[];
    state.performance=[];
    state.anomalies=[];
    $("coordStatus").textContent="load failed";
    $("perfStatus").textContent="load failed";
    $("anomalyStatus").textContent="load failed";
    drawShape();drawPerformance();drawCd();drawLd();
    console.error(e);
    alert(`翼型详情加载失败：${e.error||e.message||"unknown error"}`);
  }
}
function renderMetrics(){const cls=state.performance.map(r=>Number(r.cl));const cds=state.performance.map(r=>Number(r.cd));const ac=state.performance.filter(r=>Number(r.is_anomaly)===1).length;$("metrics").innerHTML=`<div class="metric"><b>${state.coordinates.length}</b><span>坐标点</span></div><div class="metric"><b>${num(Math.max(...cls),3)}</b><span>最大 CL（升力系数）</span></div><div class="metric"><b>${num(Math.min(...cds),5)}</b><span>最小 CD（阻力系数）</span></div><div class="metric"><b>${state.performance.length}</b><span>性能记录</span></div><div class="metric"><b>${ac}</b><span>异常标记</span></div><div class="metric"><b>${state.selectedVersion}</b><span>局部版本号</span></div>`;}
function renderAnomalies(){const body=$("anomalyRows");body.innerHTML=state.anomalies.map(r=>`<tr><td>${r.anomaly_id}</td><td class="danger">${r.rule_type}</td><td>${r.alpha_deg}</td><td>${Number(r.reynolds_number).toLocaleString()}</td><td>${num(r.cl,3)}</td><td>${num(r.cd,5)}</td></tr>`).join("")||`<tr><td colspan="6">当前翼型版本没有异常记录</td></tr>`;}
async function refreshIndexStatus(){const d=await getJson("/api/index_experiment/status");$("indexStatus").textContent=d.exists?"idx exists":"idx missing";}
async function loadIndexTables(){const tables=await getJson("/api/index_experiment/tables");$("indexTableSelect").innerHTML=tables.map(t=>`<option value="${t}" ${t==="performance_records"?"selected":""}>${t}</option>`).join("");await loadIndexColumns();}
async function loadIndexColumns(){const table=$("indexTableSelect").value;const cols=await getJson(`/api/index_experiment/columns?table=${encodeURIComponent(table)}`);$("indexColumnBox").innerHTML=cols.map(c=>`<label class="status"><input type="checkbox" class="indexColumnCheck" value="${c}"> ${c}</label>`).join("");await loadIndexes();}
function selectedIndexColumns(){return Array.from(document.querySelectorAll(".indexColumnCheck:checked")).map(x=>x.value);}
function renderIndexTable(rows){
  if(!rows||!rows.length)return "<div class='status'>当前表没有索引记录。</div>";
  const cols=Object.keys(rows[0]);
  return `<div class="tableWrap"><table><thead><tr><th>操作</th>${cols.map(c=>`<th>${escapeHtml(c)}</th>`).join("")}</tr></thead><tbody>${rows.map(r=>`<tr><td><button class="action rowDeleteBtn indexRowDeleteBtn" title="删除索引" data-index="${escapeHtml(r.index_name||"")}">×</button></td>${cols.map(c=>`<td>${escapeHtml(r[c])}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}
function attachIndexRowDeleteActions(){
  document.querySelectorAll(".indexRowDeleteBtn").forEach(btn=>btn.addEventListener("click",()=>{
    dropIndex(btn.dataset.index||"");
  }));
}
function showIndexForm(mode){
  $("indexForm").classList.add("visible");
  $("indexForm").dataset.mode=mode;
  const isCreate=mode==="create";
  $("indexFormHint").textContent="选择属性，输入索引名后创建索引。";
  $("indexColumnBox").style.display=isCreate?"block":"none";
  $("createIndexBtn").style.display="inline-flex";
}
async function loadIndexes(){try{const table=$("indexTableSelect").value||"performance_records";const rows=await getJson(`/api/index_experiment/indexes?table=${encodeURIComponent(table)}`);$("indexList").innerHTML=renderIndexTable(rows);attachIndexRowDeleteActions();}catch(e){$("indexList").textContent=e.message||String(e);}}
async function createIndex(){try{const payload={table:$("indexTableSelect").value,index_name:$("indexNameInput").value.trim(),columns:selectedIndexColumns()};const data=await postJson("/api/index_experiment/create",payload);await refreshIndexStatus();await loadIndexes();$("indexList").insertAdjacentHTML("afterbegin",`<div class="status">Created ${escapeHtml(data.index_name)} on ${escapeHtml(data.table)}(${data.columns.map(escapeHtml).join(", ")}).</div>`);}catch(e){$("indexList").textContent=e.error||"create failed";}}
async function dropIndex(indexName){try{const table=$("indexTableSelect").value;if(!indexName)return;if(!confirm(`删除 ${table}.${indexName} ?`))return;const data=await postJson("/api/index_experiment/drop",{table,index_name:indexName});await refreshIndexStatus();await loadIndexes();$("indexList").insertAdjacentHTML("afterbegin",`<div class="status">Dropped ${escapeHtml(data.index_name)} on ${escapeHtml(data.table)}.</div>`);}catch(e){$("indexList").textContent=e.error||"drop failed";}}
async function runIndex(){try{const d=await postJson("/api/index_experiment/run_sql",{sql:$("indexSqlInput").value});$("indexResult").innerHTML=`<div class="status">Rows=${d.row_count} · Time=${d.elapsed_ms} ms · showing first ${d.rows.length}</div><h2>Result</h2>${rowsToTable(d.rows)}<h2>EXPLAIN</h2>${rowsToTable(d.explain)}`;}catch(e){$("indexResult").textContent=`Experiment failed: ${e.error||"unknown error"}`;}}
function setupCanvas(canvas){const rect=canvas.getBoundingClientRect(),dpr=window.devicePixelRatio||1;canvas.width=Math.max(1,Math.floor(rect.width*dpr));canvas.height=Math.max(1,Math.floor(rect.height*dpr));const ctx=canvas.getContext("2d");ctx.setTransform(dpr,0,0,dpr,0,0);return{ctx,width:rect.width,height:rect.height};}
function axisFmt(value){
  const n=Number(value);
  if(!Number.isFinite(n))return "";
  const abs=Math.abs(n);
  if(abs>=1000)return n.toFixed(0);
  if(abs>=10)return n.toFixed(1);
  if(abs>=1)return n.toFixed(2);
  return n.toFixed(3);
}
function drawAxes(ctx,w,h,xMin=null,xMax=null,yMin=null,yMax=null){
  const left=52,right=30,top=20,bottom=42;
  const plotW=w-left-right,plotH=h-top-bottom;
  ctx.strokeStyle="#e1e6ef";
  ctx.lineWidth=1;
  ctx.font="11px Consolas";
  ctx.fillStyle="#62708a";
  ctx.textAlign="center";
  ctx.textBaseline="top";
  for(let i=0;i<=5;i++){
    const x=left+plotW*i/5;
    ctx.beginPath();ctx.moveTo(x,top);ctx.lineTo(x,top+plotH);ctx.stroke();
    if(xMin!==null&&xMax!==null){
      ctx.fillText(axisFmt(xMin+(xMax-xMin)*i/5),x,top+plotH+7);
    }
  }
  ctx.textAlign="right";
  ctx.textBaseline="middle";
  for(let i=0;i<=4;i++){
    const y=top+plotH*i/4;
    ctx.beginPath();ctx.moveTo(left,y);ctx.lineTo(left+plotW,y);ctx.stroke();
    if(yMin!==null&&yMax!==null){
      ctx.fillText(axisFmt(yMax-(yMax-yMin)*i/4),left-7,y);
    }
  }
  ctx.textAlign="left";
  ctx.textBaseline="alphabetic";
  return{left,right,top,bottom,plotW,plotH};
}
function nearestPoint(points,x,y,maxDist=28){let best=null,bestD=maxDist*maxDist;points.forEach(p=>{const d=(p.sx-x)**2+(p.sy-y)**2;if(d<bestD){best=p;bestD=d;}});return best;}
function showTooltip(id,canvas,x,y,html){
  const tip=$(id),section=canvas.closest("section"),srect=section.getBoundingClientRect();
  tip.innerHTML=html;
  tip.style.display="block";
  const margin=10;
  let left=canvas.offsetLeft+x+16;
  let top=canvas.offsetTop+y+16;
  if(id==="shapeTooltip"){
    left=canvas.offsetLeft+x+18;
    top=canvas.offsetTop+y-tip.offsetHeight-18;
  }
  if(left+tip.offsetWidth>srect.width-margin)left=canvas.offsetLeft+x-tip.offsetWidth-18;
  if(top+tip.offsetHeight>srect.height-margin)top=srect.height-tip.offsetHeight-margin;
  if(top<margin)top=canvas.offsetTop+margin;
  if(left<margin)left=margin;
  tip.style.left=`${left}px`;
  tip.style.top=`${top}px`;
}
function hideTooltip(id){$(id).style.display="none";}
function handleShapeHover(e){const canvas=$("shapeCanvas"),rect=canvas.getBoundingClientRect(),p=nearestPoint(state.shapeScreen,e.clientX-rect.left,e.clientY-rect.top);if(!p){hideTooltip("shapeTooltip");return;}const augmented=Number(p.is_augmented)===1||p.point_source==="augmented";const hasAnomaly=state.anomalies&&state.anomalies.length>0;showTooltip("shapeTooltip",canvas,p.sx,p.sy,`point_order: ${p.point_order}<br>x: ${num(p.x,5)}<br>y: ${num(p.y,5)}<br>surface（正/反面）: ${escapeHtml(p.surface)}<br>source: ${escapeHtml(p.point_source)}<br>is_augmented（增强点）: ${augmented?"yes":"no"}<br>method: ${escapeHtml(p.augmentation_method||"-")}${hasAnomaly?"<br><span class='danger'>当前翼型版本存在异常性能记录</span>":""}`);}
function handlePerfHover(e){const canvas=$("perfCanvas"),rect=canvas.getBoundingClientRect(),p=nearestPoint(state.perfScreen,e.clientX-rect.left,e.clientY-rect.top);if(!p){hideTooltip("perfTooltip");return;}showTooltip("perfTooltip",canvas,p.sx,p.sy,`alpha（攻角）: ${num(p.alpha_deg,2)} deg<br>Re（雷诺数）: ${Number(p.reynolds_number).toLocaleString()}<br>CL（升力系数）: ${num(p.cl,4)}<br>CD（阻力系数）: ${num(p.cd,5)}<br>CM（力矩系数）: ${num(p.cm,4)}${Number(p.is_anomaly)===1?"<br>anomaly: yes":""}`);}
function handleSeriesHover(e,canvasId,tipId,points){const canvas=$(canvasId),rect=canvas.getBoundingClientRect(),p=nearestPoint(points,e.clientX-rect.left,e.clientY-rect.top);if(!p){hideTooltip(tipId);return;}showTooltip(tipId,canvas,p.sx,p.sy,`${escapeHtml(p.label||"point")}<br>alpha（攻角）: ${num(p.alpha_deg,2)} deg<br>value（指标值）: ${num(p.value,5)}<br>Re（雷诺数）: ${Number(p.reynolds_number).toLocaleString()}`);}
function handleCompareHover(e){const canvas=$("compareCanvas"),scroll=$("compareScroll"),rect=canvas.getBoundingClientRect(),x=e.clientX-rect.left,y=e.clientY-rect.top;const p=state.compareScreen.find(b=>x>=b.x&&x<=b.x+b.w&&y>=b.y&&y<=b.y+b.h);if(!p){hideTooltip("compareTooltip");return;}const visibleY=p.y-(scroll?scroll.scrollTop:0);showTooltip("compareTooltip",canvas,p.x+p.w/2,visibleY,`${escapeHtml(p.airfoil_id)}<br>${escapeHtml(p.name)}<br>${metricLabel(state.compareMetric)}: ${num(p.value,5)}`);}
function handleVersionDiffHover(e){const canvas=$("versionDiffCanvas"),scroll=$("versionDiffScroll"),rect=canvas.getBoundingClientRect(),x=e.clientX-rect.left,y=e.clientY-rect.top;const p=state.versionDiffScreen.find(b=>x>=b.x&&x<=b.x+b.w&&y>=b.y&&y<=b.y+b.h);if(!p){hideTooltip("versionDiffTooltip");return;}const visibleY=p.y-(scroll?scroll.scrollTop:0);showTooltip("versionDiffTooltip",canvas,p.x+p.w/2,visibleY,`${escapeHtml(p.label||"version")}<br>${escapeHtml(p.name||"")}<br>${escapeHtml(p.version_type||"")}<br>最大 CL/CD（升阻比）: ${num(p.value,5)}`);}
function drawLineSeries(canvasId,rows,valueFn,screenKey,label){const {ctx,width:w,height:h}=setupCanvas($(canvasId));ctx.clearRect(0,0,w,h);state[screenKey]=[];const pts=rows.filter(r=>Number.isFinite(valueFn(r))).map(r=>({...r,alpha_deg:Number(r.alpha_deg),reynolds_number:Number(r.reynolds_number),value:valueFn(r),label}));if(!pts.length){drawAxes(ctx,w,h);return;}const minA=Math.min(...pts.map(r=>r.alpha_deg)),maxA=Math.max(...pts.map(r=>r.alpha_deg)),minV=Math.min(...pts.map(r=>r.value)),maxV=Math.max(...pts.map(r=>r.value));const ax=drawAxes(ctx,w,h,minA,maxA,minV,maxV);const sx=x=>ax.left+(x-minA)/(maxA-minA||1)*ax.plotW,sy=y=>ax.top+ax.plotH-(y-minV)/(maxV-minV||1)*ax.plotH;ctx.strokeStyle="#1f766f";ctx.lineWidth=2;ctx.beginPath();pts.forEach((r,i)=>{const px=sx(r.alpha_deg),py=sy(r.value);state[screenKey].push({...r,sx:px,sy:py});if(i===0)ctx.moveTo(px,py);else ctx.lineTo(px,py);});ctx.stroke();state[screenKey].forEach(r=>{ctx.fillStyle=Number(r.is_anomaly)===1?"#b42318":"#1f766f";ctx.beginPath();ctx.arc(r.sx,r.sy,3,0,Math.PI*2);ctx.fill();});}
function drawCd(){const rows=state.performance.filter(r=>Number(r.reynolds_number)===state.selectedRe);drawLineSeries("cdCanvas",rows,r=>Number(r.cd),"cdScreen","CD（阻力系数）-alpha（攻角）");}
function drawLd(){const rows=state.performance.filter(r=>Number(r.reynolds_number)===state.selectedRe);drawLineSeries("ldCanvas",rows,r=>Number(r.cd)?Number(r.cl)/Number(r.cd):NaN,"ldScreen","CL/CD（升阻比）-alpha（攻角）");}
async function drawCompare(){
  const canvas=$("compareCanvas");
  const scroll=$("compareScroll");
  canvas.style.height="100%";
  let {ctx,width:w,height:h}=setupCanvas(canvas);
  ctx.clearRect(0,0,w,h);
  state.compareScreen=[];
  const re=Number($("compareReSelect").value||50000);
  let rows=[];
  try{
    rows=await getJson(`/api/performance_compare?reynolds_number=${re}&metric=${encodeURIComponent(state.compareMetric)}&limit=80`);
  }catch(e){
    drawAxes(ctx,w,h);
    ctx.fillStyle="#b42318";
    ctx.font="13px Consolas";
    ctx.fillText(`compare load failed: ${String(e.error||e.message||"unknown error").slice(0,90)}`,60,42);
    return;
  }
  rows=rows.map(r=>({...r,value:Number(r.value)})).filter(r=>Number.isFinite(r.value));
  if(!rows.length){
    drawAxes(ctx,w,h);
    ctx.fillStyle="#62708a";
    ctx.font="13px Consolas";
    ctx.fillText("No comparable performance records for this Re.",60,42);
    return;
  }
  const visibleH=Math.max(260,scroll?scroll.clientHeight:300);
  const fixedRowH=26;
  const canvasH=Math.max(visibleH,92+rows.length*fixedRowH);
  canvas.style.height=`${canvasH}px`;
  ({ctx,width:w,height:h}=setupCanvas(canvas));
  ctx.clearRect(0,0,w,h);

  const labelX=24,barX=178,top=20,bottom=54,right=40;
  const plotW=Math.max(120,w-barX-right);
  const rowH=fixedRowH;
  const barH=16;
  const values=rows.map(r=>r.value);
  const minV=Math.min(0,...values),maxV=Math.max(...values);
  const scale=v=>(v-minV)/(maxV-minV||1)*plotW;
  const baseline=barX+scale(0);

  ctx.strokeStyle="#e7ebf2";
  ctx.lineWidth=1;
  ctx.font="12px Consolas";
  ctx.fillStyle="#62708a";
  for(let i=0;i<=4;i++){
    const x=barX+plotW*i/4;
    ctx.beginPath();ctx.moveTo(x,top-8);ctx.lineTo(x,h-bottom);ctx.stroke();
    const tick=minV+(maxV-minV)*i/4;
    ctx.textAlign="center";
    ctx.fillText(num(tick,2),x,h-18);
  }
  ctx.strokeStyle="#9aa7bb";
  ctx.beginPath();ctx.moveTo(baseline,top-8);ctx.lineTo(baseline,h-bottom);ctx.stroke();
  ctx.textAlign="left";

  rows.forEach((r,i)=>{
    const y=top+i*rowH+rowH/2;
    const value=r.value;
    const x0=value>=0?baseline:barX+scale(value);
    const x1=value>=0?barX+scale(value):baseline;
    const barW=Math.max(2,Math.abs(x1-x0));
    const airfoil=String(r.airfoil_id||"");
    const label=airfoil.length>18?`${airfoil.slice(0,17)}…`:airfoil;

    ctx.fillStyle=i===0?"#1f766f":"#2d8a82";
    ctx.fillRect(x0,y-barH/2,barW,barH);
    ctx.fillStyle="#172033";
    ctx.font="600 12px Consolas";
    ctx.fillText(label,labelX,y+4);
    ctx.font="12px Consolas";
    ctx.fillStyle="#44536a";
    const valueText=num(value,state.compareMetric==="min_cd"?5:3);
    const tx=value>=0?Math.min(x0+barW+6,w-88):Math.max(x0-54,barX);
    ctx.fillText(valueText,tx,y+4);
    state.compareScreen.push({...r,value,x:x0,y:y-barH/2,w:barW,h:barH});
  });
}
function scheduleSecondaryCharts(){clearTimeout(state.secondaryChartTimer);state.secondaryChartTimer=setTimeout(()=>{if($("pageOverview").classList.contains("active")){drawCompare();drawVersionDiff();}},250);}
async function drawVersionDiff(){
  const canvas=$("versionDiffCanvas");
  const scroll=$("versionDiffScroll");
  canvas.style.height="100%";
  let {ctx,width:w,height:h}=setupCanvas(canvas);
  ctx.clearRect(0,0,w,h);
  state.versionDiffScreen=[];
  const re=Number(state.selectedRe||$("compareReSelect").value||50000);
  let rows=[];
  try{
    rows=await getJson(`/api/version_compare?reynolds_number=${re}&limit=200`);
  }catch(e){return;}
  rows=rows.map(r=>({...r,value:Number(r.value)})).filter(r=>Number.isFinite(r.value));
  $("versionDiffStatus").textContent=`Re（雷诺数） ${Number(re).toLocaleString()} · 全库版本最大 CL/CD（升阻比）对比`;
  if(!rows.length){
    drawAxes(ctx,w,h);
    ctx.fillStyle="#62708a";
    ctx.font="14px Segoe UI";
    ctx.fillText("No version performance records at this Reynolds number.",44,44);
    return;
  }
  const visibleH=Math.max(260,scroll?scroll.clientHeight:300);
  const fixedRowH=26;
  const canvasH=Math.max(visibleH,92+rows.length*fixedRowH);
  canvas.style.height=`${canvasH}px`;
  ({ctx,width:w,height:h}=setupCanvas(canvas));
  ctx.clearRect(0,0,w,h);

  const labelX=24,barX=210,top=20,bottom=54,right=40;
  const plotW=Math.max(120,w-barX-right);
  const rowH=fixedRowH;
  const barH=16;
  const maxV=Math.max(...rows.map(r=>r.value))||1;

  ctx.strokeStyle="#e7ebf2";
  ctx.lineWidth=1;
  ctx.font="12px Consolas";
  ctx.fillStyle="#62708a";
  for(let i=0;i<=4;i++){
    const x=barX+plotW*i/4;
    ctx.beginPath();ctx.moveTo(x,top-8);ctx.lineTo(x,h-bottom);ctx.stroke();
    ctx.textAlign="center";
    ctx.fillText(num(maxV*i/4,2),x,h-18);
  }
  ctx.textAlign="left";

  rows.forEach((r,i)=>{
    const y=top+i*rowH+rowH/2;
    const value=r.value;
    const barW=Math.max(2,value/maxV*plotW);
    const rawLabel=`${r.airfoil_id} v${r.version_id}`;
    const label=rawLabel.length>22?`${rawLabel.slice(0,21)}…`:rawLabel;
    ctx.fillStyle=r.version_type==="augmented_from_raw"?"#b25d2a":"#1f766f";
    ctx.fillRect(barX,y-barH/2,barW,barH);
    ctx.fillStyle="#172033";
    ctx.font="600 12px Consolas";
    ctx.fillText(label,labelX,y+4);
    ctx.font="12px Consolas";
    ctx.fillStyle="#44536a";
    ctx.fillText(num(value,3),Math.min(barX+barW+6,w-88),y+4);
    state.versionDiffScreen.push({...r,label:rawLabel,value,x:barX,y:y-barH/2,w:barW,h:barH});
  });
}
function drawShape(){
  const {ctx,width:w,height:h}=setupCanvas($("shapeCanvas"));
  ctx.clearRect(0,0,w,h);
  const pts=state.coordinates.map(p=>({...p,x:Number(p.x),y:Number(p.y)})).filter(p=>Number.isFinite(p.x)&&Number.isFinite(p.y));
  state.shapeScreen=[];
  if(!pts.length){drawAxes(ctx,w,h);return;}
  const minX=Math.min(...pts.map(p=>p.x)),maxX=Math.max(...pts.map(p=>p.x)),minY=Math.min(...pts.map(p=>p.y)),maxY=Math.max(...pts.map(p=>p.y));
  const rawXRange=maxX-minX||1;
  const rawYRange=maxY-minY||1;
  const ax=drawAxes(ctx,w,h,minX,maxX,minY,maxY);
  const scale=Math.min(ax.plotW/rawXRange,ax.plotH/rawYRange);
  const drawnW=rawXRange*scale;
  const drawnH=rawYRange*scale;
  const offsetX=ax.left+(ax.plotW-drawnW)/2;
  const offsetY=ax.top+(ax.plotH-drawnH)/2;
  const sx=x=>offsetX+(x-minX)*scale;
  const sy=y=>offsetY+drawnH-(y-minY)*scale;
  const colors={upper:"#1f766f",lower:"#2563a6",unknown:"#526071"};
  const hasAnomaly=state.anomalies&&state.anomalies.length>0;
  pts.forEach(p=>state.shapeScreen.push({...p,sx:sx(p.x),sy:sy(p.y)}));
  ["upper","lower"].forEach(surface=>{
    const rows=state.shapeScreen.filter(p=>p.surface===surface).sort((a,b)=>Number(a.point_order)-Number(b.point_order));
    if(!rows.length)return;
    ctx.strokeStyle=colors[surface];
    ctx.lineWidth=2.4;
    ctx.beginPath();
    rows.forEach((p,i)=>{if(i===0)ctx.moveTo(p.sx,p.sy);else ctx.lineTo(p.sx,p.sy);});
    ctx.stroke();
  });
  state.shapeScreen.filter(p=>!["upper","lower"].includes(p.surface)).forEach((p,i)=>{
    if(i===0){ctx.strokeStyle=colors.unknown;ctx.lineWidth=1.6;ctx.beginPath();}
    ctx.lineTo(p.sx,p.sy);
  });
  state.shapeScreen.forEach((p,i)=>{
    const augmented=Number(p.is_augmented)===1||p.point_source==="augmented";
    const surfaceColor=colors[p.surface]||colors.unknown;
    if(augmented){
      ctx.save();
      ctx.translate(p.sx,p.sy);
      ctx.rotate(Math.PI/4);
      ctx.fillStyle="#b25d2a";
      ctx.strokeStyle="#fff7ed";
      ctx.lineWidth=1.2;
      ctx.fillRect(-3.5,-3.5,7,7);
      ctx.strokeRect(-3.5,-3.5,7,7);
      ctx.restore();
    }else if(i%8===0||p.surface!==state.shapeScreen[i-1]?.surface){
      ctx.fillStyle=surfaceColor;
      ctx.beginPath();
      ctx.arc(p.sx,p.sy,2.4,0,Math.PI*2);
      ctx.fill();
    }
    if(hasAnomaly&&i%18===0){
      ctx.strokeStyle="#b42318";
      ctx.lineWidth=1.3;
      ctx.beginPath();
      ctx.arc(p.sx,p.sy,5.2,0,Math.PI*2);
      ctx.stroke();
    }
  });

}
function drawPerformance(){const {ctx,width:w,height:h}=setupCanvas($("perfCanvas"));ctx.clearRect(0,0,w,h);const rows=state.performance.filter(r=>Number(r.reynolds_number)===state.selectedRe).map(r=>({...r,a:Number(r.alpha_deg),cln:Number(r.cl),anom:Number(r.is_anomaly)===1}));state.perfScreen=[];if(!rows.length){drawAxes(ctx,w,h);return;}const minA=Math.min(...rows.map(r=>r.a)),maxA=Math.max(...rows.map(r=>r.a)),minC=Math.min(...rows.map(r=>r.cln)),maxC=Math.max(...rows.map(r=>r.cln));const ax=drawAxes(ctx,w,h,minA,maxA,minC,maxC);const sx=x=>ax.left+(x-minA)/(maxA-minA||1)*ax.plotW,sy=y=>ax.top+ax.plotH-(y-minC)/(maxC-minC||1)*ax.plotH;ctx.strokeStyle="#1f766f";ctx.lineWidth=2;ctx.beginPath();rows.forEach((r,i)=>{const px=sx(r.a),py=sy(r.cln);state.perfScreen.push({...r,sx:px,sy:py});if(i===0)ctx.moveTo(px,py);else ctx.lineTo(px,py);});ctx.stroke();state.perfScreen.forEach(r=>{ctx.fillStyle=r.anom?"#b42318":"#1f766f";ctx.beginPath();ctx.arc(r.sx,r.sy,r.anom?4:3,0,Math.PI*2);ctx.fill();});}
init().catch(err=>{$("summary").textContent="Frontend failed. Check Flask/MySQL.";console.error(err);});
</script>
</body>
</html>
"""


if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
    )

