$ErrorActionPreference = "Stop"
if (-not (Test-Path .\.venv\Scripts\Activate.ps1)) { throw "Virtual environment not found. Run scripts\install_dev.ps1 first." }
. .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pyinstaller
pyinstaller --name WinSecLite --onefile --console --paths src --add-data "rules;rules" --add-data "src\winseclite\storage\schema.sql;winseclite\storage" src\winseclite\cli.py
Write-Host "Build completed: dist\WinSecLite.exe"
