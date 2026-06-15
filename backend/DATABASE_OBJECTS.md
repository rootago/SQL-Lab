# Triggers, Views, And Stored Procedures

This file summarizes the database objects used for the course demo.

## Triggers

### `trg_anomaly_requires_flag_insert`

Runs before inserting into `anomaly_records`.

Purpose: an anomaly record must reference a `performance_records` row whose `is_anomaly = 1`.

Demo SQL:

```sql
INSERT INTO anomaly_records
    (anomaly_id, perf_id, airfoil_id, version_id, rule_type, detail)
VALUES
    (9900001, 1, 'ag03', 1, 'negative_cd', 'demo invalid anomaly');
```

Expected result: the trigger rejects the insert if `performance_records.perf_id = 1` is not marked as an anomaly.

### `trg_anomaly_requires_flag_update`

Runs before updating `anomaly_records`.

Purpose: keeps the same cross-table consistency rule when an anomaly record is edited.

### `trg_audit_performance_update`

Runs after updating `performance_records`.

Purpose: writes old and new `cl`, `cd`, `cm`, and `is_anomaly` values into `audit_logs`.

Demo SQL:

```sql
UPDATE performance_records
SET cl = cl + 0.001
WHERE perf_id = 1;

SELECT *
FROM audit_logs
ORDER BY audit_id DESC
LIMIT 5;
```

## Views

### `v_airfoil_overview`

Aggregates each airfoil's version count, coordinate count, performance count, and anomaly count.

```sql
SELECT *
FROM v_airfoil_overview
ORDER BY anomaly_count DESC, airfoil_id
LIMIT 10;
```

### `v_performance_with_ld`

Adds the derived engineering metric `lift_drag_ratio = cl / cd`.

```sql
SELECT airfoil_id, alpha_deg, reynolds_number, cl, cd, lift_drag_ratio
FROM v_performance_with_ld
WHERE reynolds_number = 50000
ORDER BY lift_drag_ratio DESC
LIMIT 10;
```

### `v_anomaly_details`

Joins anomaly records with performance values and airfoil names.

```sql
SELECT anomaly_id, airfoil_id, airfoil_name, rule_type, cl, cd, lift_drag_ratio
FROM v_anomaly_details
ORDER BY anomaly_id
LIMIT 10;
```

## Stored Procedures

### `sp_airfoil_performance_summary`

Summarizes one airfoil version by Reynolds number.

```sql
CALL sp_airfoil_performance_summary('ag03', 1);
```

### `sp_compare_airfoils_by_re`

Ranks airfoils under one Reynolds number by a selected metric.

Supported metrics:

- `max_cl`
- `min_cd`
- `max_ld`
- `avg_cl`

```sql
CALL sp_compare_airfoils_by_re(50000, 'max_ld', 10);
```

### `sp_validate_performance_import_batch`

Validates staged performance records before importing them into `performance_records`.

Validation rules:

- Required fields cannot be null.
- `alpha_deg` must be in `[-20, 25]`.
- `reynolds_number` must be positive.
- `source_type` must be `generated_synthetic`.
- `is_anomaly` must be `0` or `1`.
- `(airfoil_id, version_id)` must exist in `data_versions`.
- `perf_id` cannot already exist.
- `(airfoil_id, version_id, alpha_deg, reynolds_number)` cannot already exist.
- A batch cannot contain duplicate `perf_id` or duplicate condition rows.

Demo SQL:

```sql
INSERT INTO performance_import_staging
    (batch_id, perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
VALUES
    ('demo_bad_batch', 9900101, 'ag03', 1, 0, 123456, 0.5, 0.01, 0.0, 'generated_synthetic', 0),
    ('demo_bad_batch', 9900102, 'ag03', 1, 99, 123456, 0.6, 0.02, 0.0, 'generated_synthetic', 0);

CALL sp_validate_performance_import_batch('demo_bad_batch');
```

Expected result: the second row shows `alpha_deg out of range [-20, 25]`.

### `sp_import_performance_batch`

Performs all-or-nothing batch import from `performance_import_staging` to `performance_records`.

If any row is invalid, the procedure rejects the import, keeps validation errors in staging, and returns rejected rows.

Invalid batch demo:

```sql
CALL sp_import_performance_batch('demo_bad_batch');

SELECT *
FROM performance_records
WHERE perf_id IN (9900101, 9900102);
```

Expected result: status is `rejected`, and no rows are inserted into `performance_records`.

Valid batch demo:

```sql
INSERT INTO performance_import_staging
    (batch_id, perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
VALUES
    ('demo_good_batch', 9900201, 'ag03', 1, -1, 123457, 0.45, 0.012, 0.0, 'generated_synthetic', 0),
    ('demo_good_batch', 9900202, 'ag03', 1, 1, 123457, 0.55, 0.013, 0.0, 'generated_synthetic', 0);

CALL sp_import_performance_batch('demo_good_batch');

SELECT perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd
FROM performance_records
WHERE perf_id IN (9900201, 9900202);
```

Expected result: status is `imported`, and both rows appear in `performance_records`.
