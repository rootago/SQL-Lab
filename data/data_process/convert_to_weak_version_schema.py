from __future__ import annotations

import csv
import re
import shutil
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
SOURCE_DIR = BASE_DIR / "output_uiuc_dat"
TARGET_DIR = BASE_DIR / "output_uiuc_dat_weak_version"

VERSION_ID_PATTERN = re.compile(r"^(?P<airfoil_id>.+)_v(?P<version_no>\d+)$")


def split_version_id(value: str) -> tuple[str, int]:
    match = VERSION_ID_PATTERN.match(value)
    if not match:
        raise ValueError(f"Unexpected version_id format: {value!r}")
    return match.group("airfoil_id"), int(match.group("version_no"))


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def convert_data_versions() -> None:
    rows = read_csv(SOURCE_DIR / "data_versions.csv")
    converted: list[dict[str, str]] = []

    for row in rows:
        airfoil_id, version_no = split_version_id(row["version_id"])
        if airfoil_id != row["airfoil_id"]:
            raise ValueError(
                f"version_id/airfoil_id mismatch: {row['version_id']} vs {row['airfoil_id']}"
            )
        if version_no != int(row["version_no"]):
            raise ValueError(
                f"version_id/version_no mismatch: {row['version_id']} vs {row['version_no']}"
            )

        converted.append(
            {
                "airfoil_id": row["airfoil_id"],
                "version_id": str(version_no),
                "version_type": row["version_type"],
                "coordinate_source_type": row["coordinate_source_type"],
                "description": row["description"],
            }
        )

    write_csv(
        TARGET_DIR / "data_versions.csv",
        ["airfoil_id", "version_id", "version_type", "coordinate_source_type", "description"],
        converted,
    )


def convert_version_references(file_name: str, fieldnames: list[str]) -> None:
    rows = read_csv(SOURCE_DIR / file_name)
    converted: list[dict[str, str]] = []

    for row in rows:
        airfoil_id, version_no = split_version_id(row["version_id"])
        if airfoil_id != row["airfoil_id"]:
            raise ValueError(
                f"{file_name} version reference mismatch: {row['version_id']} vs {row['airfoil_id']}"
            )

        new_row = dict(row)
        new_row["version_id"] = str(version_no)
        converted.append(new_row)

    write_csv(TARGET_DIR / file_name, fieldnames, converted)


def validate_output() -> dict[str, int]:
    data_versions = read_csv(TARGET_DIR / "data_versions.csv")
    version_keys: set[tuple[str, str]] = set()
    for row in data_versions:
        key = (row["airfoil_id"], row["version_id"])
        if key in version_keys:
            raise ValueError(f"Duplicate data version key: {key}")
        version_keys.add(key)

    coordinate_keys: set[tuple[str, str, str]] = set()
    for row in read_csv(TARGET_DIR / "coordinates.csv"):
        version_key = (row["airfoil_id"], row["version_id"])
        if version_key not in version_keys:
            raise ValueError(f"Missing coordinate version FK: {version_key}")

        key = (row["airfoil_id"], row["version_id"], row["point_order"])
        if key in coordinate_keys:
            raise ValueError(f"Duplicate coordinate key: {key}")
        coordinate_keys.add(key)

    performance_keys: set[tuple[str, str, str, str]] = set()
    for row in read_csv(TARGET_DIR / "performance.csv"):
        version_key = (row["airfoil_id"], row["version_id"])
        if version_key not in version_keys:
            raise ValueError(f"Missing performance version FK: {version_key}")

        key = (
            row["airfoil_id"],
            row["version_id"],
            row["alpha_deg"],
            row["reynolds_number"],
        )
        if key in performance_keys:
            raise ValueError(f"Duplicate performance condition key: {key}")
        performance_keys.add(key)

    performance_ids = {row["perf_id"] for row in read_csv(TARGET_DIR / "performance.csv")}
    for row in read_csv(TARGET_DIR / "anomalies.csv"):
        version_key = (row["airfoil_id"], row["version_id"])
        if version_key not in version_keys:
            raise ValueError(f"Missing anomaly version FK: {version_key}")
        if row["perf_id"] not in performance_ids:
            raise ValueError(f"Missing anomaly performance FK: {row['perf_id']}")

    return {
        "airfoil_count": len(read_csv(TARGET_DIR / "airfoils.csv")),
        "data_version_count": len(data_versions),
        "coordinate_count": len(read_csv(TARGET_DIR / "coordinates.csv")),
        "performance_count": len(read_csv(TARGET_DIR / "performance.csv")),
        "anomaly_count": len(read_csv(TARGET_DIR / "anomalies.csv")),
        "data_source_count": len(read_csv(TARGET_DIR / "data_sources.csv")),
    }


def write_report() -> None:
    original_report = (SOURCE_DIR / "processing_report.txt").read_text(encoding="utf-8")
    conversion_report = """

Weak-entity version conversion
output_directory=output_uiuc_dat_weak_version
version_id_conversion=old string IDs such as ag03_v1 are split into airfoil_id=ag03 and version_id=1
data_versions_primary_key=(airfoil_id, version_id)
coordinate_points_foreign_key=(airfoil_id, version_id) -> data_versions(airfoil_id, version_id)
performance_records_foreign_key=(airfoil_id, version_id) -> data_versions(airfoil_id, version_id)
original_output_directory=output_uiuc_dat remains unchanged.
"""
    (TARGET_DIR / "processing_report.txt").write_text(
        original_report + conversion_report,
        encoding="utf-8",
    )


def write_schema_constraints() -> None:
    constraints = """# Weak-Version Schema Constraints

## DataSource

DataSource(source_type, description)

PK: source_type

NOT NULL: source_type, description

UNIQUE: source_type

CHECK:
- source_type IN ('uiuc_raw', 'uiuc_raw_with_tracked_augmentation', 'generated_synthetic', 'injected_anomaly')

## Airfoils

Airfoils(airfoil_id, name, source, family, is_generated, source_type, source_file, has_augmented_coordinates, original_point_count, final_point_count)

PK: airfoil_id

FK:
- source_type -> DataSource(source_type)

NOT NULL:
- airfoil_id, name, source, family, is_generated, source_type, source_file, has_augmented_coordinates, original_point_count, final_point_count

UNIQUE:
- airfoil_id
- source_file

CHECK:
- is_generated IN (0, 1)
- has_augmented_coordinates IN (0, 1)
- original_point_count > 0
- final_point_count > 0
- final_point_count >= original_point_count

## DataVersion

DataVersion(airfoil_id, version_id, version_type, coordinate_source_type, description)

PK: (airfoil_id, version_id)

FK:
- airfoil_id -> Airfoils(airfoil_id)

NOT NULL:
- airfoil_id, version_id, version_type, coordinate_source_type

UNIQUE:
- (airfoil_id, version_id)

CHECK:
- version_id >= 1
- version_type IN ('imported_raw', 'augmented_from_raw')
- coordinate_source_type IN ('real_only', 'mixed_real_and_augmented')

## CoordinatePoint

CoordinatePoint(airfoil_id, version_id, point_order, x, y, surface, point_source, is_augmented, original_order, augmentation_method)

PK: (airfoil_id, version_id, point_order)

FK:
- (airfoil_id, version_id) -> DataVersion(airfoil_id, version_id)

NOT NULL:
- airfoil_id, version_id, point_order, x, y, surface, point_source, is_augmented, augmentation_method

Nullable:
- original_order

UNIQUE:
- (airfoil_id, version_id, point_order)

CHECK:
- version_id >= 1
- point_order >= 1
- x >= -0.001 AND x <= 1.001
- surface IN ('upper', 'lower')
- point_source IN ('real', 'augmented')
- is_augmented IN (0, 1)
- augmentation_method IN ('original_coordinate', 'linear_interpolation')
- (point_source = 'real' AND is_augmented = 0 AND augmentation_method = 'original_coordinate')
  OR (point_source = 'augmented' AND is_augmented = 1 AND augmentation_method = 'linear_interpolation')

## PerformanceRecord

PerformanceRecord(perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)

PK: perf_id

FK:
- (airfoil_id, version_id) -> DataVersion(airfoil_id, version_id)
- source_type -> DataSource(source_type)

NOT NULL:
- perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly

UNIQUE:
- perf_id
- (airfoil_id, version_id, alpha_deg, reynolds_number)

CHECK:
- version_id >= 1
- alpha_deg >= -20 AND alpha_deg <= 25
- reynolds_number > 0
- source_type IN ('generated_synthetic')
- is_anomaly IN (0, 1)

Note:
- Do not use CHECK (cd >= 0) if negative_cd anomaly records must be stored.
- negative_cd is handled by AnomalyRecord rather than rejected by the database.

## AnomalyRecord

AnomalyRecord(anomaly_id, perf_id, airfoil_id, version_id, rule_type, detail)

PK: anomaly_id

FK:
- perf_id -> PerformanceRecord(perf_id)
- (airfoil_id, version_id) -> DataVersion(airfoil_id, version_id)

NOT NULL:
- anomaly_id, perf_id, airfoil_id, version_id, rule_type, detail

UNIQUE:
- anomaly_id
- perf_id

CHECK:
- version_id >= 1
- rule_type IN ('negative_cd', 'extreme_cl', 'extreme_ld_ratio')

Cross-table consistency constraints:
- AnomalyRecord.perf_id should reference a PerformanceRecord whose is_anomaly = 1.
- AnomalyRecord.airfoil_id and version_id should match the referenced PerformanceRecord.
- These two constraints usually require a trigger, assertion, or application-level validation.
"""
    (TARGET_DIR / "schema_constraints.md").write_text(constraints, encoding="utf-8")


def main() -> None:
    TARGET_DIR.mkdir(parents=True, exist_ok=True)

    for unchanged_file in ["airfoils.csv", "data_sources.csv"]:
        shutil.copy2(SOURCE_DIR / unchanged_file, TARGET_DIR / unchanged_file)

    convert_data_versions()
    convert_version_references(
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
    )
    convert_version_references(
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
    )
    convert_version_references(
        "anomalies.csv",
        ["anomaly_id", "perf_id", "airfoil_id", "version_id", "rule_type", "detail"],
    )
    write_report()
    write_schema_constraints()

    for key, value in validate_output().items():
        print(f"{key}={value}")
    print(f"output={TARGET_DIR}")


if __name__ == "__main__":
    main()
