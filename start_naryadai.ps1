$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$pythonExe = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $pythonExe)) {
    Write-Host "[ERROR] Virtual environment not found: $pythonExe" -ForegroundColor Red
    Write-Host "Create .venv or restore dependencies before starting the app." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "Starting НарядAI..." -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Cyan

Start-Process "http://localhost:8000" -ErrorAction SilentlyContinue
& $pythonExe app.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "The app did not start correctly." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit $LASTEXITCODE
}
