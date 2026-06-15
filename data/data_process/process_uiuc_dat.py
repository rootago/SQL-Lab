from __future__ import annotations

import csv
import math
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


RAW_DIR = Path(__file__).resolve().parents[1] / "data"
OUT_DIR = Path(__file__).resolve().parent / "output_uiuc_dat"

RANDOM_SEED = 2026
MIN_COORDINATE_POINTS = 80
ALPHA_LIST = list(range(-10, 20, 2))
REYNOLDS_LIST = [50_000, 100_000, 200_000, 500_000]
ANOMALY_PROBABILITY = 0.01


@dataclass
class DatPoint:
    x: float
    y: float
    point_source: str
    original_order: int | None
    augmentation_method: str


@dataclass
class ParsedAirfoil:
    airfoil_id: str
    name: str
    source_file: str
    points: list[DatPoint]
    has_augmented_points: bool
    original_point_count: int | None
    final_point_count: int | None


@dataclass
class PerformanceRecord:
    perf_id: int
    airfoil_id: str
    version_id: str
    alpha_deg: float
    reynolds_number: int
    cl: float
    cd: float
    cm: float
    source_type: str
    is_anomaly: bool
    anomaly_type: str


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", value.strip().lower()).strip("_")
    return slug or "unknown_airfoil"


def parse_metadata_int(line: str, key: str) -> int | None:
    prefix = f"# {key}:"
    if not line.startswith(prefix):
        return None
    try:
        return int(line.split(":", 1)[1].strip())
    except ValueError:
        return None


def parse_point_comment(line: str) -> tuple[str, int | None, str] | None:
    if not line.startswith("# point_type:"):
        return None

    lower = line.lower()
    point_source = "augmented" if "augmented" in lower else "real"

    order_match = re.search(r"original_order:\s*(\d+)", line)
    original_order = int(order_match.group(1)) if order_match else None

    if "linear_interpolation" in lower:
        method = "linear_interpolation"
    elif point_source == "real":
        method = "original_coordinate"
    else:
        method = "unknown_augmentation"

    return point_source, original_order, method


def parse_dat_file(file_path: Path) -> ParsedAirfoil:
    title = ""
    points: list[DatPoint] = []
    pending_label: tuple[str, int | None, str] | None = None
    original_point_count: int | None = None
    final_point_count: int | None = None

    with file_path.open("r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith("#"):
                parsed_label = parse_point_comment(line)
                if parsed_label is not None:
                    pending_label = parsed_label
                    continue

                original_point_count = (
                    parse_metadata_int(line, "original_point_count")
                    if parse_metadata_int(line, "original_point_count") is not None
                    else original_point_count
                )
                final_point_count = (
                    parse_metadata_int(line, "final_point_count")
                    if parse_metadata_int(line, "final_point_count") is not None
                    else final_point_count
                )
                continue

            parts = line.replace(",", " ").split()
            if len(parts) >= 2:
                try:
                    x = float(parts[0])
                    y = float(parts[1])
                except ValueError:
                    if not title:
                        title = line
                    continue

                if pending_label is None:
                    point_source, original_order, method = "real", len(points) + 1, "original_coordinate"
                else:
                    point_source, original_order, method = pending_label

                points.append(
                    DatPoint(
                        x=x,
                        y=y,
                        point_source=point_source,
                        original_order=original_order,
                        augmentation_method=method,
                    )
                )
                pending_label = None
                continue

            if not title:
                title = line

    if not title:
        title = file_path.stem

    if len(points) < MIN_COORDINATE_POINTS:
        raise ValueError(
            f"{file_path.name} only has {len(points)} coordinate points; "
            f"expected at least {MIN_COORDINATE_POINTS}"
        )

    has_augmented_points = any(p.point_source == "augmented" for p in points)
    return ParsedAirfoil(
        airfoil_id=slugify(file_path.stem),
        name=title,
        source_file=str(file_path.relative_to(RAW_DIR.parent)),
        points=points,
        has_augmented_points=has_augmented_points,
        original_point_count=original_point_count,
        final_point_count=final_point_count or len(points),
    )


def infer_surface(point_index: int, points: list[DatPoint]) -> str:
    leading_edge_index = min(range(len(points)), key=lambda i: points[i].x)
    return "upper" if point_index <= leading_edge_index else "lower"


def synthetic_aero_model(alpha_deg: float, reynolds_number: int) -> tuple[float, float, float]:
    alpha_rad = math.radians(alpha_deg)
    re_factor = (reynolds_number / 1_000_000) ** 0.05

    cl = 2 * math.pi * alpha_rad * re_factor
    if alpha_deg > 12:
        cl *= max(0.60, 1.0 - 0.08 * (alpha_deg - 12))

    cd = 0.008 + 0.01 * (cl**2) + 0.00015 * (alpha_deg**2)
    cm = -0.035 - 0.002 * alpha_deg

    cl *= random.normalvariate(1.0, 0.02)
    cd *= random.normalvariate(1.0, 0.03)
    cm *= random.normalvariate(1.0, 0.015)

    return cl, max(cd, 0.0001), cm


def maybe_inject_anomaly(cl: float, cd: float, prob: float) -> tuple[float, float, bool, str]:
    if random.random() >= prob:
        return cl, cd, False, ""

    anomaly_type = random.choice(["negative_cd", "extreme_cl", "extreme_ld_ratio"])
    if anomaly_type == "negative_cd":
        return cl, -abs(cd), True, anomaly_type
    if anomaly_type == "extreme_cl":
        return cl * 4.0, cd, True, anomaly_type
    return cl, max(cd * 0.05, 1e-6), True, anomaly_type


def build_performance_rows(airfoils: Iterable[ParsedAirfoil]) -> list[PerformanceRecord]:
    rows: list[PerformanceRecord] = []
    perf_id = 1

    for airfoil in airfoils:
        version_id = f"{airfoil.airfoil_id}_v1"
        for reynolds in REYNOLDS_LIST:
            for alpha in ALPHA_LIST:
                cl, cd, cm = synthetic_aero_model(alpha, reynolds)
                cl, cd, is_anomaly, anomaly_type = maybe_inject_anomaly(
                    cl, cd, ANOMALY_PROBABILITY
                )
                rows.append(
                    PerformanceRecord(
                        perf_id=perf_id,
                        airfoil_id=airfoil.airfoil_id,
                        version_id=version_id,
                        alpha_deg=alpha,
                        reynolds_number=reynolds,
                        cl=cl,
                        cd=cd,
                        cm=cm,
                        source_type="generated_synthetic",
                        is_anomaly=is_anomaly,
                        anomaly_type=anomaly_type,
                    )
                )
                perf_id += 1

    return rows


def write_csv(path: Path, headers: list[str], rows: Iterable[Iterable[object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)


def write_outputs(airfoils: list[ParsedAirfoil], performance_rows: list[PerformanceRecord]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    write_csv(
        OUT_DIR / "airfoils.csv",
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
        (
            [
                a.airfoil_id,
                a.name,
                "UIUC Airfoil Coordinates Database",
                "UIUC",
                0,
                "uiuc_raw_with_tracked_augmentation"
                if a.has_augmented_points
                else "uiuc_raw",
                a.source_file,
                int(a.has_augmented_points),
                a.original_point_count if a.original_point_count is not None else len(a.points),
                len(a.points),
            ]
            for a in airfoils
        ),
    )

    write_csv(
        OUT_DIR / "data_versions.csv",
        [
            "version_id",
            "airfoil_id",
            "version_no",
            "version_type",
            "coordinate_source_type",
            "description",
        ],
        (
            [
                f"{a.airfoil_id}_v1",
                a.airfoil_id,
                1,
                "augmented_from_raw" if a.has_augmented_points else "imported_raw",
                "mixed_real_and_augmented" if a.has_augmented_points else "real_only",
                "Original UIUC coordinates with inserted interpolation points"
                if a.has_augmented_points
                else "Original UIUC coordinate file",
            ]
            for a in airfoils
        ),
    )

    coordinate_rows = []
    for a in airfoils:
        version_id = f"{a.airfoil_id}_v1"
        for idx, point in enumerate(a.points):
            coordinate_rows.append(
                [
                    a.airfoil_id,
                    version_id,
                    idx + 1,
                    f"{point.x:.7f}",
                    f"{point.y:.7f}",
                    infer_surface(idx, a.points),
                    point.point_source,
                    int(point.point_source == "augmented"),
                    point.original_order or "",
                    point.augmentation_method,
                ]
            )

    write_csv(
        OUT_DIR / "coordinates.csv",
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
        coordinate_rows,
    )

    write_csv(
        OUT_DIR / "performance.csv",
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
        (
            [
                r.perf_id,
                r.airfoil_id,
                r.version_id,
                r.alpha_deg,
                r.reynolds_number,
                f"{r.cl:.6f}",
                f"{r.cd:.6f}",
                f"{r.cm:.6f}",
                r.source_type,
                int(r.is_anomaly),
            ]
            for r in performance_rows
        ),
    )

    anomaly_rows = [
        [
            index + 1,
            r.perf_id,
            r.airfoil_id,
            r.version_id,
            r.anomaly_type,
            "Injected synthetic anomaly for data governance experiment",
        ]
        for index, r in enumerate(row for row in performance_rows if row.is_anomaly)
    ]
    write_csv(
        OUT_DIR / "anomalies.csv",
        ["anomaly_id", "perf_id", "airfoil_id", "version_id", "rule_type", "detail"],
        anomaly_rows,
    )

    write_csv(
        OUT_DIR / "data_sources.csv",
        ["source_type", "description"],
        [
            [
                "uiuc_raw",
                "Coordinate rows read from original UIUC .dat files without interpolation.",
            ],
            [
                "uiuc_raw_with_tracked_augmentation",
                "UIUC coordinate files that include explicitly marked interpolation points.",
            ],
            [
                "generated_synthetic",
                "Course-experiment performance records generated by a simplified physical trend model.",
            ],
            [
                "injected_anomaly",
                "Small number of synthetic suspicious records injected for quality-control experiments.",
            ],
        ],
    )

    report_lines = [
        "UIUC .dat processing report",
        f"airfoil_count={len(airfoils)}",
        f"coordinate_count={sum(len(a.points) for a in airfoils)}",
        f"augmented_coordinate_count={sum(1 for a in airfoils for p in a.points if p.point_source == 'augmented')}",
        f"performance_count={len(performance_rows)}",
        f"anomaly_count={sum(1 for r in performance_rows if r.is_anomaly)}",
        f"reynolds_numbers={','.join(str(v) for v in REYNOLDS_LIST)}",
        f"alpha_degrees={','.join(str(v) for v in ALPHA_LIST)}",
        "",
        "Notes:",
        "- Coordinates marked real come from the .dat file's original coordinate rows.",
        "- Coordinates marked augmented are inserted interpolation points already labelled in data/*.dat.",
        "- Performance records are generated for database-course experiments and are not CFD or wind-tunnel data.",
        "- Anomaly rows are intentionally injected and tracked in anomalies.csv.",
    ]
    (OUT_DIR / "processing_report.txt").write_text("\n".join(report_lines) + "\n", encoding="utf-8")


def build_dataset() -> None:
    random.seed(RANDOM_SEED)

    dat_files = sorted(RAW_DIR.glob("*.dat"))
    if not dat_files:
        raise FileNotFoundError(f"No .dat files found in {RAW_DIR}")

    airfoils = [parse_dat_file(path) for path in dat_files]
    performance_rows = build_performance_rows(airfoils)
    write_outputs(airfoils, performance_rows)

    print(f"Processed {len(airfoils)} airfoils from {RAW_DIR}")
    print(f"Wrote CSV files to {OUT_DIR}")
    print(f"Performance rows: {len(performance_rows)}")
    print(f"Anomaly rows: {sum(1 for row in performance_rows if row.is_anomaly)}")


if __name__ == "__main__":
    build_dataset()
