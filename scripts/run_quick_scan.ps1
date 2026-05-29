$ErrorActionPreference = "Stop"
if (Test-Path .\.venv\Scripts\Activate.ps1) { . .\.venv\Scripts\Activate.ps1 }
$env:PYTHONPATH = "$PWD\src"
python -m winseclite.cli scan quick --report html
