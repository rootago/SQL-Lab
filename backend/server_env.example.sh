#!/usr/bin/env bash

# Airfoil database backend environment.
# Copy this file to server_env.sh on the server, then edit passwords if needed:
#   cp backend/server_env.example.sh backend/server_env.sh
#   source backend/server_env.sh

export MYSQL_HOST='127.0.0.1'
export MYSQL_PORT='3306'
export MYSQL_USER='root'
export MYSQL_PASSWORD='cpl20060831'
export MYSQL_DATABASE='airfoil_engineering_db'

export ADMIN_USERNAME='admin'
export ADMIN_PASSWORD='admin123456'
export ADMIN_ROLE='admin'

export FLASK_HOST='0.0.0.0'
export FLASK_PORT='8765'
export FLASK_DEBUG='0'

# Change this before a real public deployment.
export FLASK_SECRET_KEY='airfoil-demo-change-this-secret'
