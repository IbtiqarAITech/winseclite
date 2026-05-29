param([string]$Python = "py -3.12")
$ErrorActionPreference = "Stop"
Invoke-Expression "$Python -m venv .venv"
. .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:PYTHONPATH = "$PWD\src"
python -m winseclite.cli init-db
python -m winseclite.cli doctor
