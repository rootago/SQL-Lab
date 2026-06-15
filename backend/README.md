# MySQL Import Backend

This backend script creates a local MySQL database and imports the weak-version airfoil CSV data.

## Data Source

The script imports CSV files from:

```text
data/data_process/output_uiuc_dat_weak_version
```

The weak entity design is used:

```text
DataVersion PK: (airfoil_id, version_id)
```

For example:

```text
ag03_v1 -> airfoil_id = ag03, version_id = 1
```

## Install Driver

```powershell
python -m pip install -r backend\requirements.txt
```

## Create Database And Import Data

Set the password as an environment variable:

```powershell
$env:MYSQL_PASSWORD="your_password"
$env:ADMIN_USERNAME="your_admin_username"
$env:ADMIN_PASSWORD="your_admin_password"
python backend\import_mysql.py --user root --database airfoil_engineering_db --reset
```

Or pass it directly:

```powershell
python backend\import_mysql.py --user root --password your_password --database airfoil_engineering_db --reset
```

`--reset` drops the target database first, then recreates all tables and reloads data.

## Tables

The script creates:

```text
data_sources
airfoils
data_versions
coordinate_points
performance_records
anomaly_records
users
query_logs
```

It also inserts one server-managed editable administrator account and one initialization query log row. Set the administrator with:

```powershell
$env:ADMIN_USERNAME="your_admin_username"
$env:ADMIN_PASSWORD="your_admin_password"
$env:ADMIN_ROLE="admin"
```

The front-end registration page only creates read-only `viewer` users.

## Important Constraints

```text
data_versions:
PK (airfoil_id, version_id)

coordinate_points:
PK (airfoil_id, version_id, point_order)
FK (airfoil_id, version_id) -> data_versions(airfoil_id, version_id)

performance_records:
PK perf_id
FK (airfoil_id, version_id) -> data_versions(airfoil_id, version_id)
UNIQUE (airfoil_id, version_id, alpha_deg, reynolds_number)

anomaly_records:
FK (perf_id, airfoil_id, version_id)
  -> performance_records(perf_id, airfoil_id, version_id)
```

`cd >= 0` is intentionally not enforced because negative drag coefficient records are stored as anomaly data.

## Share With Teammates

### Option 1: Share The Web UI

This is the recommended way. Teammates only open the browser and do not need the MySQL password.

Start the Flask app on all network interfaces:

```powershell
$env:MYSQL_PASSWORD="your_password"
$env:MYSQL_DATABASE="airfoil_engineering_db"
$env:FLASK_HOST="0.0.0.0"
python backend\app.py
```

Find your LAN IP address:

```powershell
ipconfig
```

Then teammates can open:

```text
http://your_lan_ip:5000
```

Example:

```text
http://192.168.1.23:5000
```

If Windows Firewall blocks the page, allow TCP port 5000.

The web UI also includes an index experiment panel. Teammates can click:

```text
Delete Index -> Run Experiment -> Create Index -> Run Experiment
```

The panel shows query time and `EXPLAIN` output. Because the dataset is small, elapsed time may fluctuate; for presentation, focus on whether `EXPLAIN.key` changes from `NULL` to `idx_perf_reynolds_alpha`.

### Option 2: Let Teammates Connect To MySQL

Create a read-only MySQL user:

```sql
CREATE USER 'airfoil_reader'@'%' IDENTIFIED BY 'change_this_password';
GRANT SELECT ON airfoil_engineering_db.* TO 'airfoil_reader'@'%';
FLUSH PRIVILEGES;
```

Then teammates can connect in Navicat:

```text
Host: your_lan_ip
Port: 3306
User: airfoil_reader
Password: change_this_password
Database: airfoil_engineering_db
```

If remote MySQL access fails, check:

```text
1. MySQL is listening on LAN, not only 127.0.0.1.
2. Windows Firewall allows TCP port 3306.
3. Teammates are on the same LAN.
```
