# Weak-Version Schema Constraints

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
