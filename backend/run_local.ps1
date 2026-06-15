param(
    [Parameter(Mandatory = $true)]
    [string]$MySqlPassword,

    [string]$MySqlUser = "root",
    [string]$Database = "airfoil_engineering_db",
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8765,
    [string]$AdminUsername = "",
    [string]$AdminPassword = ""
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
$pythonExe = if (Test-Path $venvPython) { $venvPython } else { "python" }

$env:MYSQL_USER = $MySqlUser
$env:MYSQL_PASSWORD = $MySqlPassword
$env:MYSQL_DATABASE = $Database
$env:FLASK_HOST = $HostAddress
$env:FLASK_PORT = [string]$Port
$env:FLASK_DEBUG = "0"

if ($AdminUsername -ne "") {
    $env:ADMIN_USERNAME = $AdminUsername
}
if ($AdminPassword -ne "") {
    $env:ADMIN_PASSWORD = $AdminPassword
}

Write-Host "Starting Airfoil Database UI..."
Write-Host "Local URL: http://127.0.0.1:$Port"
if ($HostAddress -eq "0.0.0.0") {
    Write-Host "LAN URL: use http://your_lan_ip:$Port"
}

Set-Location $projectRoot
& $pythonExe "backend\app.py"
