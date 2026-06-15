# Server Deployment Guide

This guide deploys the airfoil database web UI on a Linux server.

## 1. Upload Project

On your local machine, upload the whole project directory to the server.

Example with `scp`:

```powershell
scp -r "E:\大二下学期\数据库\实验\期末项目" user@server_ip:~/airfoil_project
```

Or use Git / SFTP / VS Code Remote SSH.

## 2. Install Python Dependencies

On the server:

```bash
cd ~/airfoil_project
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

## 3. Prepare MySQL

Install MySQL if the server does not have it.

Create and import the database:

```bash
export MYSQL_PASSWORD='your_mysql_root_password'
python backend/import_mysql.py --user root --database airfoil_engineering_db --reset
```

If root login is not allowed, create a dedicated MySQL user and grant permissions first.

Recommended production user:

```sql
CREATE USER 'airfoil_app'@'localhost' IDENTIFIED BY 'change_this_password';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, TRIGGER
ON airfoil_engineering_db.* TO 'airfoil_app'@'localhost';
FLUSH PRIVILEGES;
```

Then import with:

```bash
export MYSQL_USER='airfoil_app'
export MYSQL_PASSWORD='change_this_password'
export MYSQL_DATABASE='airfoil_engineering_db'
export ADMIN_USERNAME='your_admin_username'
export ADMIN_PASSWORD='your_admin_password'
export ADMIN_ROLE='admin'
python backend/import_mysql.py --reset
```

`ADMIN_USERNAME` / `ADMIN_PASSWORD` create the editable administrator account managed by the server.
The web registration page only creates read-only `viewer` users.

## 4. Start Web UI

For a simple course demo:

```bash
export MYSQL_HOST='127.0.0.1'
export MYSQL_USER='airfoil_app'
export MYSQL_PASSWORD='change_this_password'
export MYSQL_DATABASE='airfoil_engineering_db'
export ADMIN_USERNAME='your_admin_username'
export ADMIN_PASSWORD='your_admin_password'
export FLASK_HOST='0.0.0.0'
export FLASK_PORT='8765'
export FLASK_DEBUG='0'
python backend/app.py
```

Then open:

```text
http://server_ip:8765
```

## 5. Firewall / Security Group

Only open the web port:

```text
TCP 8765
```

Do not expose MySQL port `3306` to the public network.

If using a cloud server, also open TCP `8765` in the cloud provider security group.

## 6. Safer Demo Settings

Recommended:

```text
1. Use a non-default web port such as 8765.
2. Keep MySQL bound to localhost.
3. Do not expose port 3306.
4. Use a dedicated MySQL user instead of root.
5. Set FLASK_DEBUG=0 on the server.
6. Stop the Flask app after the demo if it is not needed.
```

## 7. Quick Health Check

On the server:

```bash
curl http://127.0.0.1:8765/api/summary
```

Expected counts:

```text
airfoils: 70
data_versions: 70
coordinate_points: 8552
performance_records: 4200
anomaly_records: 39
data_sources: 4
```
