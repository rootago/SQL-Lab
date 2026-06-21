from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path
from typing import Any

from werkzeug.security import generate_password_hash


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data" / "data_process" / "output_uiuc_dat_weak_version"
DEFAULT_DATABASE = "airfoil_engineering_db"


CREATE_TABLES_SQL = [
    """
    CREATE TABLE data_sources (
        source_type VARCHAR(64) PRIMARY KEY,
        description TEXT NOT NULL,
        CHECK (
            source_type IN (
                'uiuc_raw',
                'uiuc_raw_with_tracked_augmentation',
                'generated_synthetic',
                'injected_anomaly'
            )
        )
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE airfoils (
        airfoil_id VARCHAR(64) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        source VARCHAR(255) NOT NULL,
        family VARCHAR(64) NOT NULL,
        is_generated TINYINT NOT NULL,
        source_type VARCHAR(64) NOT NULL,
        source_file VARCHAR(255) NOT NULL,
        has_augmented_coordinates TINYINT NOT NULL,
        original_point_count INT NOT NULL,
        final_point_count INT NOT NULL,
        UNIQUE KEY uq_airfoils_id_source_file (airfoil_id, source_file),
        CONSTRAINT fk_airfoils_source_type
            FOREIGN KEY (source_type) REFERENCES data_sources(source_type),
        CHECK (is_generated IN (0, 1)),
        CHECK (has_augmented_coordinates IN (0, 1)),
        CHECK (original_point_count > 0),
        CHECK (final_point_count > 0),
        CHECK (final_point_count >= original_point_count)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE data_versions (
        airfoil_id VARCHAR(64) NOT NULL,
        version_id INT NOT NULL,
        version_type VARCHAR(64) NOT NULL,
        coordinate_source_type VARCHAR(64) NOT NULL,
        description TEXT,
        PRIMARY KEY (airfoil_id, version_id),
        CONSTRAINT fk_data_versions_airfoil
            FOREIGN KEY (airfoil_id) REFERENCES airfoils(airfoil_id)
            ON UPDATE CASCADE
            ON DELETE CASCADE,
        CHECK (version_type IN ('imported_raw', 'augmented_from_raw')),
        CHECK (coordinate_source_type IN ('real_only', 'mixed_real_and_augmented'))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE coordinate_points (
        airfoil_id VARCHAR(64) NOT NULL,
        version_id INT NOT NULL,
        point_order INT NOT NULL,
        x DOUBLE NOT NULL,
        y DOUBLE NOT NULL,
        surface VARCHAR(16) NOT NULL,
        point_source VARCHAR(16) NOT NULL,
        is_augmented TINYINT NOT NULL,
        original_order INT NULL,
        augmentation_method VARCHAR(64) NOT NULL,
        PRIMARY KEY (airfoil_id, version_id, point_order),
        CONSTRAINT fk_coordinate_points_version
            FOREIGN KEY (airfoil_id, version_id)
            REFERENCES data_versions(airfoil_id, version_id)
            ON UPDATE CASCADE
            ON DELETE CASCADE,
        CHECK (point_order >= 1),
        CHECK (x >= -0.001 AND x <= 1.001),
        CHECK (surface IN ('upper', 'lower')),
        CHECK (point_source IN ('real', 'augmented')),
        CHECK (is_augmented IN (0, 1)),
        CHECK (augmentation_method IN ('original_coordinate', 'linear_interpolation')),
        CHECK (
            (
                point_source = 'real'
                AND is_augmented = 0
                AND augmentation_method = 'original_coordinate'
            )
            OR
            (
                point_source = 'augmented'
                AND is_augmented = 1
                AND augmentation_method = 'linear_interpolation'
            )
        )
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE performance_records (
        perf_id INT PRIMARY KEY,
        airfoil_id VARCHAR(64) NOT NULL,
        version_id INT NOT NULL,
        alpha_deg DOUBLE NOT NULL,
        reynolds_number INT NOT NULL,
        cl DOUBLE NOT NULL,
        cd DOUBLE NOT NULL,
        cm DOUBLE NOT NULL,
        source_type VARCHAR(64) NOT NULL,
        is_anomaly TINYINT NOT NULL,
        UNIQUE KEY uq_performance_condition (
            airfoil_id,
            version_id,
            alpha_deg,
            reynolds_number
        ),
        UNIQUE KEY uq_performance_record_version (
            perf_id,
            airfoil_id,
            version_id
        ),
        CONSTRAINT fk_performance_records_version
            FOREIGN KEY (airfoil_id, version_id)
            REFERENCES data_versions(airfoil_id, version_id)
            ON UPDATE CASCADE
            ON DELETE CASCADE,
        CONSTRAINT fk_performance_records_source_type
            FOREIGN KEY (source_type) REFERENCES data_sources(source_type),
        CHECK (alpha_deg >= -20 AND alpha_deg <= 25),
        CHECK (reynolds_number > 0),
        CHECK (source_type IN ('generated_synthetic')),
        CHECK (is_anomaly IN (0, 1))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE anomaly_records (
        anomaly_id INT PRIMARY KEY,
        perf_id INT NOT NULL,
        airfoil_id VARCHAR(64) NOT NULL,
        version_id INT NOT NULL,
        rule_type VARCHAR(64) NOT NULL,
        detail TEXT NOT NULL,
        UNIQUE KEY uq_anomaly_perf (perf_id),
        CONSTRAINT fk_anomaly_records_performance
            FOREIGN KEY (perf_id, airfoil_id, version_id)
            REFERENCES performance_records(perf_id, airfoil_id, version_id)
            ON UPDATE CASCADE
            ON DELETE CASCADE,
        CONSTRAINT fk_anomaly_records_version
            FOREIGN KEY (airfoil_id, version_id)
            REFERENCES data_versions(airfoil_id, version_id)
            ON UPDATE CASCADE
            ON DELETE CASCADE,
        CHECK (rule_type IN ('negative_cd', 'extreme_cl', 'extreme_ld_ratio'))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE users (
        user_id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(64) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        email VARCHAR(255),
        role VARCHAR(32) NOT NULL DEFAULT 'viewer',
        is_active TINYINT NOT NULL DEFAULT 1,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_users_username (username),
        UNIQUE KEY uq_users_email (email),
        CHECK (role IN ('admin', 'engineer', 'analyst', 'viewer')),
        CHECK (is_active IN (0, 1))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE query_logs (
        log_id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        natural_language TEXT,
        sql_text TEXT NOT NULL,
        is_ai_generated TINYINT NOT NULL DEFAULT 0,
        is_valid TINYINT NOT NULL DEFAULT 1,
        execution_time_ms INT,
        executed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_query_logs_user
            FOREIGN KEY (user_id) REFERENCES users(user_id),
        CHECK (is_ai_generated IN (0, 1)),
        CHECK (is_valid IN (0, 1)),
        CHECK (execution_time_ms IS NULL OR execution_time_ms >= 0)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE saved_transactions (
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
    """,
    """
    CREATE TABLE audit_logs (
        audit_id INT AUTO_INCREMENT PRIMARY KEY,
        table_name VARCHAR(64) NOT NULL,
        operation_type VARCHAR(16) NOT NULL,
        record_pk VARCHAR(128) NOT NULL,
        previous_record_version_id INT NULL,
        record_version_id INT NOT NULL DEFAULT 0,
        old_values JSON,
        new_values JSON,
        changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CHECK (operation_type IN ('INSERT', 'UPDATE', 'DELETE'))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE data_record_lineage (
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
        INDEX idx_data_record_lineage_version (table_name, record_pk, record_version_id),
        CHECK (is_modified IN (0, 1)),
        CHECK (modified_count >= 0),
        CHECK (last_operation IN ('INSERT', 'UPDATE', 'DELETE'))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE data_import_records (
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
        previous_record_version_id INT NULL,
        record_version_id INT NOT NULL DEFAULT 0,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_data_import_record_method (target_table, record_pk, entry_method),
        INDEX idx_data_import_target (target_table),
        INDEX idx_data_import_airfoil (airfoil_id),
        INDEX idx_data_import_user (created_by_user_id),
        CHECK (entry_method IN ('system', 'frontend', 'sql'))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE performance_import_staging (
        staging_id INT AUTO_INCREMENT PRIMARY KEY,
        batch_id VARCHAR(64) NOT NULL,
        perf_id INT,
        airfoil_id VARCHAR(64),
        version_id INT,
        alpha_deg DOUBLE,
        reynolds_number INT,
        cl DOUBLE,
        cd DOUBLE,
        cm DOUBLE,
        source_type VARCHAR(64),
        is_anomaly TINYINT,
        validation_error TEXT,
        imported TINYINT NOT NULL DEFAULT 0,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_perf_import_batch (batch_id),
        CHECK (imported IN (0, 1))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
]


TRIGGERS_SQL = [
    """
    CREATE TRIGGER trg_lineage_airfoils_insert
    AFTER INSERT ON airfoils
    FOR EACH ROW
    BEGIN
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, is_modified, last_operation)
        VALUES
            ('airfoils', NEW.airfoil_id, NEW.airfoil_id, 'master', 0, 'INSERT')
        ON DUPLICATE KEY UPDATE
            last_operation = 'INSERT';
    END
    """,
    """
    CREATE TRIGGER trg_lineage_airfoils_update
    AFTER UPDATE ON airfoils
    FOR EACH ROW
    BEGIN
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, is_modified, last_modified_at, modified_count, last_operation)
        VALUES
            ('airfoils', NEW.airfoil_id, NEW.airfoil_id, 'master', 1, CURRENT_TIMESTAMP, 1, 'UPDATE')
        ON DUPLICATE KEY UPDATE
            airfoil_id = NEW.airfoil_id,
            is_modified = 1,
            last_modified_at = CURRENT_TIMESTAMP,
            modified_count = modified_count + 1,
            last_operation = 'UPDATE';
    END
    """,
    """
    CREATE TRIGGER trg_audit_airfoils_update
        AFTER UPDATE ON airfoils
        FOR EACH ROW
        FOLLOWS trg_lineage_airfoils_update
        BEGIN
            INSERT INTO audit_logs
                (table_name, operation_type, record_pk, previous_record_version_id, record_version_id, old_values, new_values)
            VALUES
                (
                    'airfoils',
                    'UPDATE',
                    NEW.airfoil_id,
                    COALESCE(
                        (SELECT previous_record_version_id FROM data_record_lineage
                         WHERE table_name = 'airfoils' AND record_pk = NEW.airfoil_id LIMIT 1),
                        0
                    ),
                    COALESCE(
                        (SELECT record_version_id FROM data_record_lineage
                         WHERE table_name = 'airfoils' AND record_pk = NEW.airfoil_id LIMIT 1),
                        1
                    ),
                    JSON_OBJECT(
                        'airfoil_id', OLD.airfoil_id,
                        'name', OLD.name,
                        'source', OLD.source,
                        'family', OLD.family,
                        'is_generated', OLD.is_generated,
                        'source_type', OLD.source_type,
                        'source_file', OLD.source_file,
                        'has_augmented_coordinates', OLD.has_augmented_coordinates,
                        'original_point_count', OLD.original_point_count,
                        'final_point_count', OLD.final_point_count
                    ),
                    JSON_OBJECT(
                        'airfoil_id', NEW.airfoil_id,
                        'name', NEW.name,
                        'source', NEW.source,
                        'family', NEW.family,
                        'is_generated', NEW.is_generated,
                        'source_type', NEW.source_type,
                        'source_file', NEW.source_file,
                        'has_augmented_coordinates', NEW.has_augmented_coordinates,
                        'original_point_count', NEW.original_point_count,
                        'final_point_count', NEW.final_point_count
                    )
                );
        END
        """,
        """
    CREATE TRIGGER trg_lineage_data_versions_insert
    AFTER INSERT ON data_versions
    FOR EACH ROW
    BEGIN
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, is_modified, last_operation)
        VALUES
            ('data_versions', CONCAT(NEW.airfoil_id, '#', NEW.version_id), NEW.airfoil_id, CONCAT('version ', NEW.version_id), 0, 'INSERT')
        ON DUPLICATE KEY UPDATE
            last_operation = 'INSERT';
    END
    """,
    """
    CREATE TRIGGER trg_lineage_data_versions_update
    AFTER UPDATE ON data_versions
    FOR EACH ROW
    BEGIN
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, is_modified, last_modified_at, modified_count, last_operation)
        VALUES
            ('data_versions', CONCAT(NEW.airfoil_id, '#', NEW.version_id), NEW.airfoil_id, CONCAT('version ', NEW.version_id), 1, CURRENT_TIMESTAMP, 1, 'UPDATE')
        ON DUPLICATE KEY UPDATE
            airfoil_id = NEW.airfoil_id,
            source_version = CONCAT('version ', NEW.version_id),
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
            (table_name, record_pk, airfoil_id, source_version, is_modified, last_operation)
        VALUES
            ('coordinate_points', CONCAT(NEW.airfoil_id, '#', NEW.version_id, '#', NEW.point_order), NEW.airfoil_id, CONCAT('version ', NEW.version_id), 0, 'INSERT')
        ON DUPLICATE KEY UPDATE
            last_operation = 'INSERT';
    END
    """,
    """
    CREATE TRIGGER trg_lineage_coordinates_update
    AFTER UPDATE ON coordinate_points
    FOR EACH ROW
    BEGIN
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, is_modified, last_modified_at, modified_count, last_operation)
        VALUES
            ('coordinate_points', CONCAT(NEW.airfoil_id, '#', NEW.version_id, '#', NEW.point_order), NEW.airfoil_id, CONCAT('version ', NEW.version_id), 1, CURRENT_TIMESTAMP, 1, 'UPDATE')
        ON DUPLICATE KEY UPDATE
            airfoil_id = NEW.airfoil_id,
            source_version = CONCAT('version ', NEW.version_id),
            is_modified = 1,
            last_modified_at = CURRENT_TIMESTAMP,
            modified_count = modified_count + 1,
            last_operation = 'UPDATE';
    END
    """,
    """
    CREATE TRIGGER trg_lineage_performance_insert
    AFTER INSERT ON performance_records
    FOR EACH ROW
    BEGIN
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, is_modified, last_operation)
        VALUES
            ('performance_records', CAST(NEW.perf_id AS CHAR), NEW.airfoil_id, CONCAT('version ', NEW.version_id), 0, 'INSERT')
        ON DUPLICATE KEY UPDATE
            last_operation = 'INSERT';
    END
    """,
    """
    CREATE TRIGGER trg_lineage_performance_update
    AFTER UPDATE ON performance_records
    FOR EACH ROW
    BEGIN
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, is_modified, last_modified_at, modified_count, last_operation)
        VALUES
            ('performance_records', CAST(NEW.perf_id AS CHAR), NEW.airfoil_id, CONCAT('version ', NEW.version_id), 1, CURRENT_TIMESTAMP, 1, 'UPDATE')
        ON DUPLICATE KEY UPDATE
            airfoil_id = NEW.airfoil_id,
            source_version = CONCAT('version ', NEW.version_id),
            is_modified = 1,
            last_modified_at = CURRENT_TIMESTAMP,
            modified_count = modified_count + 1,
            last_operation = 'UPDATE';
    END
    """,
    """
    CREATE TRIGGER trg_lineage_anomalies_insert
    AFTER INSERT ON anomaly_records
    FOR EACH ROW
    BEGIN
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, is_modified, last_operation)
        VALUES
            ('anomaly_records', CAST(NEW.anomaly_id AS CHAR), NEW.airfoil_id, CONCAT('version ', NEW.version_id), 0, 'INSERT')
        ON DUPLICATE KEY UPDATE
            last_operation = 'INSERT';
    END
    """,
    """
    CREATE TRIGGER trg_lineage_anomalies_update
    AFTER UPDATE ON anomaly_records
    FOR EACH ROW
    BEGIN
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, is_modified, last_modified_at, modified_count, last_operation)
        VALUES
            ('anomaly_records', CAST(NEW.anomaly_id AS CHAR), NEW.airfoil_id, CONCAT('version ', NEW.version_id), 1, CURRENT_TIMESTAMP, 1, 'UPDATE')
        ON DUPLICATE KEY UPDATE
            airfoil_id = NEW.airfoil_id,
            source_version = CONCAT('version ', NEW.version_id),
            is_modified = 1,
            last_modified_at = CURRENT_TIMESTAMP,
            modified_count = modified_count + 1,
            last_operation = 'UPDATE';
    END
    """,
    """
    CREATE TRIGGER trg_anomaly_requires_flag_insert
    BEFORE INSERT ON anomaly_records
    FOR EACH ROW
    BEGIN
        IF (
            SELECT is_anomaly
            FROM performance_records
            WHERE perf_id = NEW.perf_id
        ) <> 1 THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'AnomalyRecord must reference a PerformanceRecord with is_anomaly = 1';
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
        ) <> 1 THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'AnomalyRecord must reference a PerformanceRecord with is_anomaly = 1';
        END IF;
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


VIEWS_SQL = [
    """
    CREATE VIEW v_airfoil_overview AS
    SELECT
        a.airfoil_id,
        a.name,
        a.family,
        a.source_type,
        a.original_point_count,
        a.final_point_count,
        a.has_augmented_coordinates,
        COUNT(DISTINCT dv.version_id) AS version_count,
        COUNT(DISTINCT cp.point_order) AS coordinate_count,
        COUNT(DISTINCT pr.perf_id) AS performance_count,
        COUNT(DISTINCT ar.anomaly_id) AS anomaly_count
    FROM airfoils a
    LEFT JOIN data_versions dv
        ON dv.airfoil_id = a.airfoil_id
    LEFT JOIN coordinate_points cp
        ON cp.airfoil_id = dv.airfoil_id
       AND cp.version_id = dv.version_id
    LEFT JOIN performance_records pr
        ON pr.airfoil_id = dv.airfoil_id
       AND pr.version_id = dv.version_id
    LEFT JOIN anomaly_records ar
        ON ar.perf_id = pr.perf_id
    GROUP BY
        a.airfoil_id,
        a.name,
        a.family,
        a.source_type,
        a.original_point_count,
        a.final_point_count,
        a.has_augmented_coordinates
    """,
    """
    CREATE VIEW v_performance_with_ld AS
    SELECT
        p.perf_id,
        p.airfoil_id,
        a.name AS airfoil_name,
        p.version_id,
        p.alpha_deg,
        p.reynolds_number,
        p.cl,
        p.cd,
        p.cm,
        CASE
            WHEN p.cd = 0 THEN NULL
            ELSE p.cl / p.cd
        END AS lift_drag_ratio,
        p.is_anomaly
    FROM performance_records p
    JOIN airfoils a
        ON a.airfoil_id = p.airfoil_id
    """,
    """
    CREATE VIEW v_anomaly_details AS
    SELECT
        ar.anomaly_id,
        ar.rule_type,
        ar.detail,
        p.perf_id,
        p.airfoil_id,
        a.name AS airfoil_name,
        p.version_id,
        p.alpha_deg,
        p.reynolds_number,
        p.cl,
        p.cd,
        p.cm,
        CASE
            WHEN p.cd = 0 THEN NULL
            ELSE p.cl / p.cd
        END AS lift_drag_ratio
    FROM anomaly_records ar
    JOIN performance_records p
        ON p.perf_id = ar.perf_id
    JOIN airfoils a
        ON a.airfoil_id = p.airfoil_id
    """,
]


STORED_PROCEDURES_SQL = [
    """
    CREATE PROCEDURE sp_airfoil_performance_summary(
        IN p_airfoil_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
        IN p_version_id INT
    )
    BEGIN
        SELECT
            p.airfoil_id,
            a.name AS airfoil_name,
            p.version_id,
            p.reynolds_number,
            COUNT(*) AS sample_count,
            ROUND(MIN(p.cd), 6) AS min_cd,
            ROUND(MAX(p.cl), 6) AS max_cl,
            ROUND(AVG(p.cl), 6) AS avg_cl,
            ROUND(MAX(p.cl / NULLIF(p.cd, 0)), 6) AS max_lift_drag_ratio,
            SUM(p.is_anomaly) AS anomaly_count
        FROM performance_records p
        JOIN airfoils a
            ON a.airfoil_id = p.airfoil_id
        WHERE p.airfoil_id COLLATE utf8mb4_unicode_ci = p_airfoil_id COLLATE utf8mb4_unicode_ci
          AND p.version_id = p_version_id
        GROUP BY
            p.airfoil_id,
            a.name,
            p.version_id,
            p.reynolds_number
        ORDER BY p.reynolds_number;
    END
    """,
    """
    CREATE PROCEDURE sp_compare_airfoils_by_re(
        IN p_reynolds_number INT,
        IN p_metric VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
        IN p_limit_count INT
    )
    BEGIN
        SELECT
            ranked.airfoil_id,
            ranked.airfoil_name,
            ranked.metric_name,
            ranked.metric_value
        FROM (
            SELECT
                p.airfoil_id,
                a.name AS airfoil_name,
                CASE
                    WHEN p_metric COLLATE utf8mb4_unicode_ci = 'min_cd' COLLATE utf8mb4_unicode_ci THEN 'min_cd'
                    WHEN p_metric COLLATE utf8mb4_unicode_ci = 'max_ld' COLLATE utf8mb4_unicode_ci THEN 'max_lift_drag_ratio'
                    WHEN p_metric COLLATE utf8mb4_unicode_ci = 'avg_cl' COLLATE utf8mb4_unicode_ci THEN 'avg_cl'
                    ELSE 'max_cl'
                END AS metric_name,
                CASE
                    WHEN p_metric COLLATE utf8mb4_unicode_ci = 'min_cd' COLLATE utf8mb4_unicode_ci THEN ROUND(MIN(p.cd), 6)
                    WHEN p_metric COLLATE utf8mb4_unicode_ci = 'max_ld' COLLATE utf8mb4_unicode_ci THEN ROUND(MAX(p.cl / NULLIF(p.cd, 0)), 6)
                    WHEN p_metric COLLATE utf8mb4_unicode_ci = 'avg_cl' COLLATE utf8mb4_unicode_ci THEN ROUND(AVG(p.cl), 6)
                    ELSE ROUND(MAX(p.cl), 6)
                END AS metric_value
            FROM performance_records p
            JOIN airfoils a
                ON a.airfoil_id = p.airfoil_id
            WHERE p.reynolds_number = p_reynolds_number
            GROUP BY p.airfoil_id, a.name
        ) ranked
        ORDER BY
            CASE WHEN p_metric COLLATE utf8mb4_unicode_ci = 'min_cd' COLLATE utf8mb4_unicode_ci THEN ranked.metric_value END ASC,
            CASE
                WHEN p_metric COLLATE utf8mb4_unicode_ci <> 'min_cd' COLLATE utf8mb4_unicode_ci
                  OR p_metric IS NULL
                THEN ranked.metric_value
            END DESC
        LIMIT p_limit_count;
    END
    """,
    """
    CREATE PROCEDURE sp_validate_performance_import_batch(
        IN p_batch_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    )
    BEGIN
        UPDATE performance_import_staging s
        LEFT JOIN (
            SELECT batch_id, perf_id
            FROM performance_import_staging
            WHERE batch_id COLLATE utf8mb4_unicode_ci = p_batch_id COLLATE utf8mb4_unicode_ci
              AND perf_id IS NOT NULL
              AND imported = 0
            GROUP BY batch_id, perf_id
            HAVING COUNT(*) > 1
        ) dup_perf
            ON dup_perf.batch_id COLLATE utf8mb4_unicode_ci = s.batch_id COLLATE utf8mb4_unicode_ci
           AND dup_perf.perf_id = s.perf_id
        LEFT JOIN (
            SELECT batch_id, airfoil_id, version_id, alpha_deg, reynolds_number
            FROM performance_import_staging
            WHERE batch_id COLLATE utf8mb4_unicode_ci = p_batch_id COLLATE utf8mb4_unicode_ci
              AND airfoil_id IS NOT NULL
              AND version_id IS NOT NULL
              AND alpha_deg IS NOT NULL
              AND reynolds_number IS NOT NULL
              AND imported = 0
            GROUP BY batch_id, airfoil_id, version_id, alpha_deg, reynolds_number
            HAVING COUNT(*) > 1
        ) dup_condition
            ON dup_condition.batch_id COLLATE utf8mb4_unicode_ci = s.batch_id COLLATE utf8mb4_unicode_ci
           AND dup_condition.airfoil_id COLLATE utf8mb4_unicode_ci = s.airfoil_id COLLATE utf8mb4_unicode_ci
           AND dup_condition.version_id = s.version_id
           AND dup_condition.alpha_deg = s.alpha_deg
           AND dup_condition.reynolds_number = s.reynolds_number
        SET validation_error = NULLIF(
            CONCAT_WS(
                '; ',
                CASE WHEN s.perf_id IS NULL THEN 'perf_id is required' END,
                CASE WHEN s.airfoil_id IS NULL THEN 'airfoil_id is required' END,
                CASE WHEN s.version_id IS NULL THEN 'version_id is required' END,
                CASE WHEN s.alpha_deg IS NULL THEN 'alpha_deg is required' END,
                CASE WHEN s.reynolds_number IS NULL THEN 'reynolds_number is required' END,
                CASE WHEN s.cl IS NULL THEN 'cl is required' END,
                CASE WHEN s.cd IS NULL THEN 'cd is required' END,
                CASE WHEN s.cm IS NULL THEN 'cm is required' END,
                CASE WHEN s.source_type IS NULL THEN 'source_type is required' END,
                CASE WHEN s.is_anomaly IS NULL THEN 'is_anomaly is required' END,
                CASE
                    WHEN s.alpha_deg IS NOT NULL
                     AND (s.alpha_deg < -20 OR s.alpha_deg > 25)
                    THEN 'alpha_deg out of range [-20, 25]'
                END,
                CASE
                    WHEN s.reynolds_number IS NOT NULL
                     AND s.reynolds_number <= 0
                    THEN 'reynolds_number must be positive'
                END,
                CASE
                    WHEN s.source_type IS NOT NULL
                     AND s.source_type COLLATE utf8mb4_unicode_ci <> 'generated_synthetic' COLLATE utf8mb4_unicode_ci
                    THEN 'source_type must be generated_synthetic'
                END,
                CASE
                    WHEN s.is_anomaly IS NOT NULL
                     AND s.is_anomaly NOT IN (0, 1)
                    THEN 'is_anomaly must be 0 or 1'
                END,
                CASE
                    WHEN s.airfoil_id IS NOT NULL
                     AND s.version_id IS NOT NULL
                     AND NOT EXISTS (
                         SELECT 1
                         FROM data_versions dv
                         WHERE dv.airfoil_id COLLATE utf8mb4_unicode_ci = s.airfoil_id COLLATE utf8mb4_unicode_ci
                           AND dv.version_id = s.version_id
                     )
                    THEN 'referenced data version does not exist'
                END,
                CASE
                    WHEN s.perf_id IS NOT NULL
                     AND EXISTS (
                         SELECT 1
                         FROM performance_records p
                         WHERE p.perf_id = s.perf_id
                     )
                    THEN 'perf_id already exists'
                END,
                CASE
                    WHEN s.airfoil_id IS NOT NULL
                     AND s.version_id IS NOT NULL
                     AND s.alpha_deg IS NOT NULL
                     AND s.reynolds_number IS NOT NULL
                     AND EXISTS (
                         SELECT 1
                         FROM performance_records p
                         WHERE p.airfoil_id COLLATE utf8mb4_unicode_ci = s.airfoil_id COLLATE utf8mb4_unicode_ci
                           AND p.version_id = s.version_id
                           AND p.alpha_deg = s.alpha_deg
                           AND p.reynolds_number = s.reynolds_number
                     )
                    THEN 'same airfoil/version/alpha/Re condition already exists'
                END,
                CASE
                    WHEN dup_perf.perf_id IS NOT NULL
                    THEN 'duplicate perf_id inside batch'
                END,
                CASE
                    WHEN dup_condition.batch_id IS NOT NULL
                    THEN 'duplicate condition inside batch'
                END
            ),
            ''
        )
        WHERE s.batch_id COLLATE utf8mb4_unicode_ci = p_batch_id COLLATE utf8mb4_unicode_ci
          AND s.imported = 0;

        SELECT
            staging_id,
            batch_id,
            perf_id,
            airfoil_id,
            version_id,
            alpha_deg,
            reynolds_number,
            validation_error
        FROM performance_import_staging
        WHERE batch_id COLLATE utf8mb4_unicode_ci = p_batch_id COLLATE utf8mb4_unicode_ci
        ORDER BY staging_id;
    END
    """,
    """
    CREATE PROCEDURE sp_import_performance_batch(
        IN p_batch_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    )
    BEGIN
        DECLARE v_invalid_count INT DEFAULT 0;
        DECLARE v_imported_count INT DEFAULT 0;

        DECLARE EXIT HANDLER FOR SQLEXCEPTION
        BEGIN
            ROLLBACK;
            RESIGNAL;
        END;

        START TRANSACTION;

        UPDATE performance_import_staging s
        LEFT JOIN (
            SELECT batch_id, perf_id
            FROM performance_import_staging
            WHERE batch_id COLLATE utf8mb4_unicode_ci = p_batch_id COLLATE utf8mb4_unicode_ci
              AND perf_id IS NOT NULL
              AND imported = 0
            GROUP BY batch_id, perf_id
            HAVING COUNT(*) > 1
        ) dup_perf
            ON dup_perf.batch_id COLLATE utf8mb4_unicode_ci = s.batch_id COLLATE utf8mb4_unicode_ci
           AND dup_perf.perf_id = s.perf_id
        LEFT JOIN (
            SELECT batch_id, airfoil_id, version_id, alpha_deg, reynolds_number
            FROM performance_import_staging
            WHERE batch_id COLLATE utf8mb4_unicode_ci = p_batch_id COLLATE utf8mb4_unicode_ci
              AND airfoil_id IS NOT NULL
              AND version_id IS NOT NULL
              AND alpha_deg IS NOT NULL
              AND reynolds_number IS NOT NULL
              AND imported = 0
            GROUP BY batch_id, airfoil_id, version_id, alpha_deg, reynolds_number
            HAVING COUNT(*) > 1
        ) dup_condition
            ON dup_condition.batch_id COLLATE utf8mb4_unicode_ci = s.batch_id COLLATE utf8mb4_unicode_ci
           AND dup_condition.airfoil_id COLLATE utf8mb4_unicode_ci = s.airfoil_id COLLATE utf8mb4_unicode_ci
           AND dup_condition.version_id = s.version_id
           AND dup_condition.alpha_deg = s.alpha_deg
           AND dup_condition.reynolds_number = s.reynolds_number
        SET validation_error = NULLIF(
            CONCAT_WS(
                '; ',
                CASE WHEN s.perf_id IS NULL THEN 'perf_id is required' END,
                CASE WHEN s.airfoil_id IS NULL THEN 'airfoil_id is required' END,
                CASE WHEN s.version_id IS NULL THEN 'version_id is required' END,
                CASE WHEN s.alpha_deg IS NULL THEN 'alpha_deg is required' END,
                CASE WHEN s.reynolds_number IS NULL THEN 'reynolds_number is required' END,
                CASE WHEN s.cl IS NULL THEN 'cl is required' END,
                CASE WHEN s.cd IS NULL THEN 'cd is required' END,
                CASE WHEN s.cm IS NULL THEN 'cm is required' END,
                CASE WHEN s.source_type IS NULL THEN 'source_type is required' END,
                CASE WHEN s.is_anomaly IS NULL THEN 'is_anomaly is required' END,
                CASE
                    WHEN s.alpha_deg IS NOT NULL
                     AND (s.alpha_deg < -20 OR s.alpha_deg > 25)
                    THEN 'alpha_deg out of range [-20, 25]'
                END,
                CASE
                    WHEN s.reynolds_number IS NOT NULL
                     AND s.reynolds_number <= 0
                    THEN 'reynolds_number must be positive'
                END,
                CASE
                    WHEN s.source_type IS NOT NULL
                     AND s.source_type COLLATE utf8mb4_unicode_ci <> 'generated_synthetic' COLLATE utf8mb4_unicode_ci
                    THEN 'source_type must be generated_synthetic'
                END,
                CASE
                    WHEN s.is_anomaly IS NOT NULL
                     AND s.is_anomaly NOT IN (0, 1)
                    THEN 'is_anomaly must be 0 or 1'
                END,
                CASE
                    WHEN s.airfoil_id IS NOT NULL
                     AND s.version_id IS NOT NULL
                     AND NOT EXISTS (
                         SELECT 1
                         FROM data_versions dv
                         WHERE dv.airfoil_id COLLATE utf8mb4_unicode_ci = s.airfoil_id COLLATE utf8mb4_unicode_ci
                           AND dv.version_id = s.version_id
                     )
                    THEN 'referenced data version does not exist'
                END,
                CASE
                    WHEN s.perf_id IS NOT NULL
                     AND EXISTS (
                         SELECT 1
                         FROM performance_records p
                         WHERE p.perf_id = s.perf_id
                     )
                    THEN 'perf_id already exists'
                END,
                CASE
                    WHEN s.airfoil_id IS NOT NULL
                     AND s.version_id IS NOT NULL
                     AND s.alpha_deg IS NOT NULL
                     AND s.reynolds_number IS NOT NULL
                     AND EXISTS (
                         SELECT 1
                         FROM performance_records p
                         WHERE p.airfoil_id COLLATE utf8mb4_unicode_ci = s.airfoil_id COLLATE utf8mb4_unicode_ci
                           AND p.version_id = s.version_id
                           AND p.alpha_deg = s.alpha_deg
                           AND p.reynolds_number = s.reynolds_number
                     )
                    THEN 'same airfoil/version/alpha/Re condition already exists'
                END,
                CASE
                    WHEN dup_perf.perf_id IS NOT NULL
                    THEN 'duplicate perf_id inside batch'
                END,
                CASE
                    WHEN dup_condition.batch_id IS NOT NULL
                    THEN 'duplicate condition inside batch'
                END
            ),
            ''
        )
        WHERE s.batch_id COLLATE utf8mb4_unicode_ci = p_batch_id COLLATE utf8mb4_unicode_ci
          AND s.imported = 0;

        SELECT COUNT(*) INTO v_invalid_count
        FROM performance_import_staging
        WHERE batch_id COLLATE utf8mb4_unicode_ci = p_batch_id COLLATE utf8mb4_unicode_ci
          AND imported = 0
          AND validation_error IS NOT NULL;

        IF v_invalid_count > 0 THEN
            COMMIT;

            SELECT 'rejected' AS status, v_invalid_count AS invalid_count, 0 AS imported_count;

            SELECT
                staging_id,
                perf_id,
                airfoil_id,
                version_id,
                alpha_deg,
                reynolds_number,
                validation_error
            FROM performance_import_staging
            WHERE batch_id COLLATE utf8mb4_unicode_ci = p_batch_id COLLATE utf8mb4_unicode_ci
              AND imported = 0
              AND validation_error IS NOT NULL
            ORDER BY staging_id;
        ELSE
            INSERT INTO performance_records
                (perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
            SELECT
                perf_id,
                airfoil_id,
                version_id,
                alpha_deg,
                reynolds_number,
                cl,
                cd,
                cm,
                source_type,
                is_anomaly
            FROM performance_import_staging
            WHERE batch_id COLLATE utf8mb4_unicode_ci = p_batch_id COLLATE utf8mb4_unicode_ci
              AND imported = 0;

            SET v_imported_count = ROW_COUNT();

            UPDATE performance_import_staging
            SET imported = 1
            WHERE batch_id COLLATE utf8mb4_unicode_ci = p_batch_id COLLATE utf8mb4_unicode_ci
              AND imported = 0;

            COMMIT;

            SELECT 'imported' AS status, 0 AS invalid_count, v_imported_count AS imported_count;
        END IF;
    END
    """,
]


IMPORT_ORDER = [
    (
        "data_sources",
        "data_sources.csv",
        ["source_type", "description"],
    ),
    (
        "airfoils",
        "airfoils.csv",
        [
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
    ),
    (
        "data_versions",
        "data_versions.csv",
        ["airfoil_id", "version_id", "version_type", "coordinate_source_type", "description"],
    ),
    (
        "coordinate_points",
        "coordinates.csv",
        [
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
    ),
    (
        "performance_records",
        "performance.csv",
        [
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
    ),
    (
        "anomaly_records",
        "anomalies.csv",
        ["anomaly_id", "perf_id", "airfoil_id", "version_id", "rule_type", "detail"],
    ),
]


def load_driver() -> Any:
    try:
        import pymysql

        return "pymysql", pymysql
    except ImportError:
        pass

    try:
        import mysql.connector

        return "mysql.connector", mysql.connector
    except ImportError:
        pass

    print(
        "Missing MySQL Python driver. Install one of these first:\n"
        "  python -m pip install pymysql\n"
        "or\n"
        "  python -m pip install mysql-connector-python",
        file=sys.stderr,
    )
    raise SystemExit(1)


def connect(driver_name: str, driver: Any, args: argparse.Namespace, database: str | None = None) -> Any:
    config = {
        "host": args.host,
        "port": args.port,
        "user": args.user,
        "password": args.password,
        "charset": "utf8mb4",
    }
    if database:
        config["database"] = database

    if driver_name == "pymysql":
        return driver.connect(**config, autocommit=False)

    return driver.connect(**config)


def execute_statements(cursor: Any, statements: list[str]) -> None:
    for statement in statements:
        cursor.execute(statement)


def normalize_value(value: str) -> str | None:
    return None if value == "" else value


def read_rows(csv_path: Path, columns: list[str]) -> list[tuple[str | None, ...]]:
    with csv_path.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        return [tuple(normalize_value(row[column]) for column in columns) for row in reader]


def insert_csv(cursor: Any, table_name: str, csv_name: str, columns: list[str]) -> int:
    rows = read_rows(DATA_DIR / csv_name, columns)
    placeholders = ", ".join(["%s"] * len(columns))
    column_sql = ", ".join(f"`{column}`" for column in columns)
    sql = f"INSERT INTO `{table_name}` ({column_sql}) VALUES ({placeholders})"
    cursor.executemany(sql, rows)
    return len(rows)


def initialize_lineage(cursor: Any) -> None:
    statements = [
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, is_modified, last_operation)
        SELECT 'airfoils', airfoil_id, airfoil_id, 'master', 0, 'INSERT'
        FROM airfoils
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, is_modified, last_operation)
        SELECT 'data_versions', CONCAT(airfoil_id, '#', version_id), airfoil_id, CONCAT('version ', version_id), 0, 'INSERT'
        FROM data_versions
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, is_modified, last_operation)
        SELECT 'coordinate_points', CONCAT(airfoil_id, '#', version_id, '#', point_order), airfoil_id, CONCAT('version ', version_id), 0, 'INSERT'
        FROM coordinate_points
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, is_modified, last_operation)
        SELECT 'performance_records', CAST(perf_id AS CHAR), airfoil_id, CONCAT('version ', version_id), 0, 'INSERT'
        FROM performance_records
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
        """
        INSERT INTO data_record_lineage
            (table_name, record_pk, airfoil_id, source_version, is_modified, last_operation)
        SELECT 'anomaly_records', CAST(anomaly_id AS CHAR), airfoil_id, CONCAT('version ', version_id), 0, 'INSERT'
        FROM anomaly_records
        ON DUPLICATE KEY UPDATE table_name = VALUES(table_name)
        """,
    ]
    execute_statements(cursor, statements)


def initialize_import_records(cursor: Any) -> None:
    statements = [
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
    ]
    execute_statements(cursor, statements)


def create_database(args: argparse.Namespace) -> None:
    driver_name, driver = load_driver()
    connection = connect(driver_name, driver, args)
    try:
        cursor = connection.cursor()
        if args.reset:
            cursor.execute(f"DROP DATABASE IF EXISTS `{args.database}`")
        cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{args.database}` "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        connection.commit()
    finally:
        connection.close()

    connection = connect(driver_name, driver, args, args.database)
    try:
        cursor = connection.cursor()
        cursor.execute("SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci")
        execute_statements(cursor, CREATE_TABLES_SQL)
        execute_statements(cursor, TRIGGERS_SQL)

        inserted_counts = {}
        for table_name, csv_name, columns in IMPORT_ORDER:
            inserted_counts[table_name] = insert_csv(cursor, table_name, csv_name, columns)
        initialize_lineage(cursor)
        initialize_import_records(cursor)

        admin_username = os.getenv("ADMIN_USERNAME", "admin")
        admin_password = os.getenv("ADMIN_PASSWORD", "admin123456")
        admin_role = os.getenv("ADMIN_ROLE", "admin")
        cursor.execute(
            "INSERT INTO users (username, password_hash, email, role) VALUES (%s, %s, %s, %s)",
            (
                admin_username,
                generate_password_hash(admin_password),
                os.getenv("ADMIN_EMAIL", "admin@example.com"),
                admin_role,
            ),
        )
        cursor.execute(
            """
            INSERT INTO query_logs
                (user_id, natural_language, sql_text, is_ai_generated, is_valid, execution_time_ms)
            VALUES
                (1, %s, %s, 1, 1, 0)
            """,
            (
                "Server initialized editable administrator account",
                f"INSERT INTO users (username, role) VALUES ('{admin_username}', '{admin_role}')",
            ),
        )
        execute_statements(cursor, VIEWS_SQL)
        execute_statements(cursor, STORED_PROCEDURES_SQL)

        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    for table_name, count in inserted_counts.items():
        print(f"{table_name}={count}")
    print("users=1")
    print("query_logs=1")
    print(f"database={args.database}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create the local MySQL airfoil database and import weak-version CSV data."
    )
    parser.add_argument("--host", default=os.getenv("MYSQL_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("MYSQL_PORT", "3306")))
    parser.add_argument("--user", default=os.getenv("MYSQL_USER", "root"))
    parser.add_argument("--password", default=os.getenv("MYSQL_PASSWORD", ""))
    parser.add_argument("--database", default=os.getenv("MYSQL_DATABASE", DEFAULT_DATABASE))
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Drop the target database before recreating it.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    create_database(parse_args())
