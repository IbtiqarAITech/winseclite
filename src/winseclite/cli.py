from __future__ import annotations
from pathlib import Path
from typing import Annotated
import typer
from rich.console import Console
from rich.table import Table
from winseclite.config import load_config
from winseclite.core.orchestrator import ScanOrchestrator
from winseclite.logging_config import configure_logging
from winseclite.platform.defender import DefenderClient
from winseclite.quarantine.quarantine_manager import QuarantineManager
from winseclite.storage.database import Database
from winseclite.utils.platform import is_admin

app = typer.Typer(help="WinSecLite defensive Windows security scanner")
scan_app = typer.Typer(help="Run scans")
defender_app = typer.Typer(help="Microsoft Defender integration")
quarantine_app = typer.Typer(help="Quarantine operations")
app.add_typer(scan_app, name="scan")
app.add_typer(defender_app, name="defender")
app.add_typer(quarantine_app, name="quarantine")
console = Console()


def bootstrap():
    cfg = load_config()
    configure_logging(cfg.log_dir)
    db = Database(cfg.db_path)
    db.init()
    return cfg, db


@app.command("init-db")
def init_db() -> None:
    cfg, db = bootstrap()
    db.init()
    console.print(f"[green]Initialized database:[/green] {cfg.db_path}")


@app.command("doctor")
def doctor() -> None:
    cfg, _ = bootstrap()
    table = Table(title="WinSecLite Doctor")
    table.add_column("Check")
    table.add_column("Value")
    table.add_row("Home", str(cfg.base_dir))
    table.add_row("Database", str(cfg.db_path))
    table.add_row("Admin", "yes" if is_admin() else "no")
    table.add_row("YARA", "enabled" if cfg.enable_yara else "disabled")
    console.print(table)


@scan_app.command("quick")
def quick_scan(report: Annotated[str, typer.Option(help="json, html, both, or none")] = "json") -> None:
    cfg, db = bootstrap()
    session, detections, report_path = ScanOrchestrator(cfg, db).run_quick_scan(report_format=report)
    console.print(f"[green]Scan completed[/green] id={session.id}")
    console.print(f"Files scanned: {session.files_scanned}")
    console.print(f"Detections: {len(detections)}")
    if report_path:
        console.print(f"Report: {report_path}")


@scan_app.command("path")
def path_scan(path: Annotated[Path, typer.Argument(help="File or folder path to scan")], report: Annotated[str, typer.Option(help="json, html, both, or none")] = "json") -> None:
    cfg, db = bootstrap()
    if not path.exists():
        raise typer.BadParameter(f"Path does not exist: {path}")
    session, detections, report_path = ScanOrchestrator(cfg, db).run_custom_scan([path], report_format=report)
    console.print(f"[green]Scan completed[/green] id={session.id}")
    console.print(f"Files scanned: {session.files_scanned}")
    console.print(f"Detections: {len(detections)}")
    if report_path:
        console.print(f"Report: {report_path}")


@defender_app.command("status")
def defender_status() -> None:
    result = DefenderClient().status()
    console.print(result.stdout or result.stderr)


@defender_app.command("update")
def defender_update() -> None:
    result = DefenderClient().update_signatures()
    console.print(result.stdout or result.stderr)
    raise typer.Exit(result.returncode)


@defender_app.command("quick-scan")
def defender_quick_scan() -> None:
    result = DefenderClient().quick_scan()
    console.print(result.stdout or result.stderr)
    raise typer.Exit(result.returncode)


@quarantine_app.command("list")
def quarantine_list() -> None:
    cfg, _ = bootstrap()
    manager = QuarantineManager(cfg.quarantine_dir)
    table = Table(title="Quarantine")
    table.add_column("ID")
    table.add_column("Original Path")
    table.add_column("SHA256")
    for item in manager.list_items():
        table.add_row(item.get("id", ""), item.get("original_path", ""), item.get("sha256", ""))
    console.print(table)


if __name__ == "__main__":
    app()
