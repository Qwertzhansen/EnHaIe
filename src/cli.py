"""
NHI Discovery Tool - CLI Interface

Verwendung:
    python -m src.cli scan
    python -m src.cli report
    python -m src.cli history
    python -m src.cli export --format csv
"""

from __future__ import annotations

import csv
import json
import logging
import os
import sys
from datetime import datetime

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _risk_color(level: str) -> str:
    """Gibt die Rich-Farbe für ein Risk Level zurück."""
    return {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }.get(level, "white")


def _risk_emoji(level: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(level, "⚪")


def _format_days(days: int | None) -> str:
    if days is None:
        return "Nie"
    if days == 0:
        return "Heute"
    return f"{days}d"


def _get_mock_nhis() -> list[dict]:
    """Gibt Demo-Daten zurück wenn keine AWS-Credentials vorhanden sind."""
    return [
        {
            "type": "IAM_USER", "name": "svc-old-backup", "age_days": 400,
            "days_since_last_used": None, "last_used": "Never",
            "policies": ["AdministratorAccess"],
            "access_key_1_age_days": 210, "access_key_1_status": "Active",
        },
        {
            "type": "IAM_USER", "name": "svc-deployment", "age_days": 180,
            "days_since_last_used": 2, "last_used": "2026-02-27",
            "policies": ["AmazonS3FullAccess", "AmazonEC2FullAccess"],
            "access_key_1_age_days": 95, "access_key_1_status": "Active",
        },
        {
            "type": "IAM_USER", "name": "svc-external-api", "age_days": 45,
            "days_since_last_used": 1, "last_used": "2026-02-28",
            "policies": ["AmazonS3ReadOnlyAccess"],
            "access_key_1_age_days": 45, "access_key_1_status": "Active",
        },
        {
            "type": "IAM_ROLE", "name": "role-lambda-overprivileged", "age_days": 300,
            "days_since_last_used": 95, "last_used": "2025-11-26",
            "policies": ["AdministratorAccess"],
        },
        {
            "type": "IAM_ROLE", "name": "role-ec2-webserver", "age_days": 60,
            "days_since_last_used": 5, "last_used": "2026-02-24",
            "policies": ["AmazonS3ReadOnlyAccess", "CloudWatchLogsFullAccess"],
        },
    ]


# ---------------------------------------------------------------------------
# CLI-Gruppe
# ---------------------------------------------------------------------------

@click.group()
@click.version_option("2.0.0", prog_name="nhi-discovery")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Aktiviert Debug-Logging (alle Module)")
def cli(verbose: bool):
    """NHI Discovery Tool – findet und bewertet Non-Human Identities in AWS."""
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
    else:
        logging.basicConfig(level=logging.WARNING)


# ---------------------------------------------------------------------------
# Command: scan
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--mock", is_flag=True, default=False,
              help="Benutzt Demo-Daten statt echtem AWS-Scan (kein AWS-Zugriff nötig)")
@click.option("--deep", is_flag=True, default=False,
              help="Aktiviert CloudTrail-Analyse für genauere Exposure-Bewertung")
@click.option("--iac", "iac_path", default=None, metavar="PATH",
              help="Scannt Terraform-Verzeichnis auf IAM-Sicherheitsprobleme")
@click.option("--iac-format", "iac_fmt", type=click.Choice(["table", "sarif"]),
              default="table", show_default=True,
              help="Ausgabeformat für IaC-Scan-Ergebnisse")
@click.option("--account", default=None, help="AWS Account ID (optional)")
@click.option("--db", default=None, help="Pfad zur Datenbankdatei")
def scan(mock: bool, deep: bool, iac_path: str | None, iac_fmt: str, account: str | None, db: str | None):
    """Scannt AWS nach Non-Human Identities und speichert Ergebnisse.

    \b
    Beispiele:
      python -m src.cli scan --mock
      python -m src.cli scan --deep
      python -m src.cli scan --iac ./terraform
    """
    from src.risk_scoring import score_all, summarize
    from src.database import save_scan, _DEFAULT_DB_PATH

    db_path = db or _DEFAULT_DB_PATH

    console.print(Panel.fit(
        "[bold cyan]NHI Discovery Tool v2[/bold cyan]\n"
        "[dim]CVSS-inspiriertes Non-Human Identity Scanner[/dim]",
        border_style="cyan",
    ))

    if mock:
        console.print("[yellow]⚠  Mock-Modus aktiv – verwende Demo-Daten[/yellow]\n")
        raw_nhis = _get_mock_nhis()
    else:
        console.print("[cyan]Verbinde mit AWS...[/cyan]")
        try:
            from botocore.exceptions import ClientError, NoCredentialsError
            from src.discovery import discover_iam_users, discover_iam_roles
            with console.status("[cyan]Scanne IAM Users...[/cyan]"):
                users = discover_iam_users()
            with console.status("[cyan]Scanne IAM Roles...[/cyan]"):
                roles = discover_iam_roles()
            raw_nhis = users + roles
        except NoCredentialsError:
            console.print("[red]Keine AWS-Credentials gefunden.[/red]")
            console.print("[yellow]Tipp: Starte mit --mock für einen Demo-Scan ohne AWS.[/yellow]")
            sys.exit(1)
        except ClientError as exc:
            console.print(f"[red]AWS-Fehler: {exc}[/red]")
            console.print("[yellow]Tipp: Starte mit --mock für einen Demo-Scan ohne AWS.[/yellow]")
            sys.exit(1)

    # CloudTrail-Enrichment (--deep)
    if deep and not mock:
        try:
            import boto3
            from src.cloudtrail_analyzer import get_nhi_activity, enrich_nhis_with_cloudtrail
            with console.status("[cyan]Analysiere CloudTrail (90 Tage)...[/cyan]"):
                ct_client = boto3.client("cloudtrail")
                events = get_nhi_activity(ct_client, days=90)
                raw_nhis = enrich_nhis_with_cloudtrail(raw_nhis, events)
            console.print(f"[green]✓ CloudTrail: {len(events)} Events analysiert[/green]")
        except Exception as exc:
            console.print(f"[yellow]CloudTrail nicht verfügbar: {exc}[/yellow]")
    elif deep and mock:
        console.print("[dim]--deep im Mock-Modus ignoriert[/dim]")

    with console.status("[cyan]Berechne Risk Scores...[/cyan]"):
        results = score_all(raw_nhis)
        summary = summarize(results)

    scan_id = save_scan(results, aws_account=account, db_path=db_path)

    # Ergebnistabelle
    table = Table(
        title=f"Scan-Ergebnisse (ID: {scan_id})",
        box=box.ROUNDED,
        show_lines=False,
        header_style="bold cyan",
    )
    table.add_column("NHI", style="bold", min_width=25)
    table.add_column("Typ", width=10)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Level", width=10)
    table.add_column("Alter", justify="right", width=8)
    table.add_column("Inaktiv seit", justify="right", width=12)

    for r in results:
        level_color = _risk_color(r.risk_level)
        table.add_row(
            r.name,
            r.nhi_type.replace("IAM_", ""),
            f"[{level_color}]{r.risk_score}[/{level_color}]",
            f"[{level_color}]{_risk_emoji(r.risk_level)} {r.risk_level}[/{level_color}]",
            _format_days(r.age_days),
            _format_days(r.days_since_last_used),
        )

    console.print(table)

    # KPI-Zusammenfassung
    console.print()
    console.print(
        f"  Gesamt: [bold]{summary['total']}[/bold]  "
        f"[bold red]CRITICAL: {summary['critical_count']}[/bold red]  "
        f"[red]HIGH: {summary['high_count']}[/red]  "
        f"[yellow]MEDIUM: {summary['medium_count']}[/yellow]  "
        f"[green]LOW: {summary['low_count']}[/green]"
    )
    console.print(f"\n[dim]Gespeichert in: {db_path}[/dim]")

    # IaC-Scan (--iac)
    if iac_path:
        _run_iac_scan(iac_path, output_format=iac_fmt)


def _run_iac_scan(iac_path: str, output_format: str = "table") -> None:
    """Führt einen IaC-Scan durch und gibt Ergebnisse aus."""
    from src.iac_scanner import generate_report as iac_report, to_sarif

    if not os.path.exists(iac_path):
        console.print(f"[red]IaC-Pfad nicht gefunden: {iac_path}[/red]")
        return

    with console.status("[magenta]Analysiere Terraform-Dateien...[/magenta]"):
        result = iac_report(iac_path)

    if output_format == "sarif":
        sarif_data = to_sarif(result, base_path=iac_path)
        click.echo(json.dumps(sarif_data, indent=2, ensure_ascii=False))
        return

    console.print()
    console.print(Panel.fit(
        f"[bold]Terraform IaC-Scan:[/bold] {iac_path}",
        border_style="magenta",
    ))

    console.print(
        f"  Dateien: [bold]{result.files_scanned}[/bold]  "
        f"Ressourcen: [bold]{result.total_resources}[/bold]  "
        f"[bold red]CRITICAL: {result.critical_count}[/bold red]  "
        f"[red]HIGH: {result.high_count}[/red]  "
        f"[yellow]MEDIUM: {result.medium_count}[/yellow]"
    )

    if not result.findings:
        console.print("[green]✓ Keine Sicherheitsprobleme gefunden[/green]")
        return

    iac_table = Table(box=box.ROUNDED, header_style="bold magenta", show_lines=True)
    iac_table.add_column("Severity", width=10)
    iac_table.add_column("Ressource", min_width=20)
    iac_table.add_column("Problem", min_width=35)
    iac_table.add_column("Empfehlung", min_width=30)

    sev_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}

    for finding in result.findings:
        color = sev_colors.get(finding.severity, "white")
        line_info = f" (Zeile {finding.line})" if finding.line else ""
        file_name = os.path.basename(finding.file) + line_info
        iac_table.add_row(
            f"[{color}]{finding.severity}[/{color}]",
            f"{finding.resource}\n[dim]{file_name}[/dim]",
            finding.issue,
            finding.recommendation,
        )

    console.print(iac_table)


# ---------------------------------------------------------------------------
# Command: report
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--db", default=None, help="Pfad zur Datenbankdatei")
@click.option("--verbose", "-v", is_flag=True, help="Zeigt Findings und Empfehlungen")
def report(db: str | None, verbose: bool):
    """Zeigt den neuesten Scan als formatierte Tabelle."""
    from src.database import get_latest_scan, _DEFAULT_DB_PATH

    db_path = db or _DEFAULT_DB_PATH
    latest = get_latest_scan(db_path=db_path)

    if not latest:
        console.print("[yellow]Keine Scans gefunden. Führe zuerst 'scan' aus.[/yellow]")
        return

    scan = latest["scan"]
    nhis = latest["nhis"]
    ts = scan["timestamp"][:19].replace("T", " ")

    console.print(Panel.fit(
        f"[bold]Letzter Scan:[/bold] {ts}\n"
        f"[bold]Account:[/bold] {scan.get('aws_account') or 'unbekannt'}\n"
        f"[bold]NHIs gesamt:[/bold] {scan['total_nhis']}",
        title="[cyan]NHI Discovery Report[/cyan]",
        border_style="cyan",
    ))

    # Haupttabelle
    table = Table(box=box.ROUNDED, header_style="bold cyan", show_lines=verbose)
    table.add_column("NHI", style="bold", min_width=25)
    table.add_column("Typ", width=10)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Level", width=12)
    table.add_column("Alter", justify="right", width=8)
    table.add_column("Policies", min_width=20)

    if verbose:
        table.add_column("Findings", min_width=30)

    for nhi in nhis:
        level = nhi["risk_level"]
        color = _risk_color(level)
        policies = nhi.get("policies") or []
        policy_str = ", ".join(policies[:2]) + ("…" if len(policies) > 2 else "")

        row = [
            nhi["name"],
            nhi["type"].replace("IAM_", ""),
            f"[{color}]{nhi['risk_score']}[/{color}]",
            f"[{color}]{_risk_emoji(level)} {level}[/{color}]",
            _format_days(nhi.get("age_days")),
            policy_str or "[dim]–[/dim]",
        ]

        if verbose:
            findings = nhi.get("findings") or []
            row.append("\n".join(f"• {f}" for f in findings) or "[dim]–[/dim]")

        table.add_row(*row)

    console.print(table)

    # Zusammenfassung
    console.print(
        f"\n  [bold red]CRITICAL: {scan['critical_count']}[/bold red]  "
        f"[red]HIGH: {scan['high_count']}[/red]  "
        f"[yellow]MEDIUM: {scan['medium_count']}[/yellow]  "
        f"[green]LOW: {scan['low_count']}[/green]"
    )

    if verbose:
        # Empfehlungen für kritische NHIs
        critical = [n for n in nhis if n["risk_level"] == "CRITICAL"]
        if critical:
            console.print("\n[bold red]Top-Empfehlungen (CRITICAL):[/bold red]")
            for nhi in critical[:3]:
                console.print(f"\n  [bold]{nhi['name']}[/bold]")
                for rec in (nhi.get("recommendations") or []):
                    console.print(f"  → {rec}")


# ---------------------------------------------------------------------------
# Command: history
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--db", default=None, help="Pfad zur Datenbankdatei")
def history(db: str | None):
    """Zeigt alle bisherigen Scans mit ihren Kennzahlen."""
    from src.database import get_scan_history, _DEFAULT_DB_PATH

    db_path = db or _DEFAULT_DB_PATH
    scans = get_scan_history(db_path=db_path)

    if not scans:
        console.print("[yellow]Keine Scans gefunden. Führe zuerst 'scan' aus.[/yellow]")
        return

    table = Table(
        title=f"Scan-History ({len(scans)} Scans)",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("ID", justify="right", width=5)
    table.add_column("Zeitstempel", min_width=20)
    table.add_column("Account", min_width=14)
    table.add_column("Total", justify="right", width=7)
    table.add_column("CRITICAL", justify="right", width=9)
    table.add_column("HIGH", justify="right", width=7)
    table.add_column("MEDIUM", justify="right", width=8)
    table.add_column("LOW", justify="right", width=6)

    for s in scans:
        ts = s["timestamp"][:19].replace("T", " ")
        table.add_row(
            str(s["id"]),
            ts,
            s.get("aws_account") or "–",
            str(s["total_nhis"]),
            f"[bold red]{s['critical_count']}[/bold red]" if s["critical_count"] else "0",
            f"[red]{s['high_count']}[/red]" if s["high_count"] else "0",
            f"[yellow]{s['medium_count']}[/yellow]" if s["medium_count"] else "0",
            f"[green]{s['low_count']}[/green]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Command: export
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--format", "fmt", type=click.Choice(["csv", "json", "sarif"]),
              default="csv", show_default=True, help="Ausgabeformat")
@click.option("--iac", "iac_path", default=None, metavar="PATH",
              help="Terraform-Pfad für SARIF-Export (nur bei --format sarif)")
@click.option("--output", "-o", default=None,
              help="Ausgabedatei (Standard: data/export.<format>)")
@click.option("--db", default=None, help="Pfad zur Datenbankdatei")
def export(fmt: str, iac_path: str | None, output: str | None, db: str | None):
    """Exportiert den neuesten Scan nach CSV, JSON oder SARIF.

    \b
    Beispiele:
      nhi-discovery export --format sarif --iac ./terraform > results.sarif
      nhi-discovery export --format json -o scan.json
    """
    from src.database import get_latest_scan, _DEFAULT_DB_PATH

    db_path = db or _DEFAULT_DB_PATH

    # SARIF-Export: direkt aus IaC-Scan, kein DB-Zugriff nötig
    if fmt == "sarif":
        if not iac_path:
            console.print("[red]--iac PATH ist bei --format sarif erforderlich.[/red]")
            sys.exit(1)
        _run_iac_scan(iac_path, output_format="sarif")
        return

    # Standard-Ausgabepfad
    if output is None:
        data_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data",
        )
        os.makedirs(data_dir, exist_ok=True)
        output = os.path.join(data_dir, f"export.{fmt}")

    latest = get_latest_scan(db_path=db_path)
    if not latest:
        console.print("[yellow]Keine Scans gefunden. Führe zuerst 'scan' aus.[/yellow]")
        return

    nhis = latest["nhis"]

    if fmt == "csv":
        _export_csv(nhis, output)
    else:
        _export_json(nhis, latest["scan"], output)

    console.print(f"[green]✓ Exportiert nach:[/green] {output}")
    console.print(f"[dim]{len(nhis)} NHIs exportiert.[/dim]")


def _export_csv(nhis: list[dict], path: str) -> None:
    """Schreibt NHIs als CSV."""
    if not nhis:
        return

    fieldnames = [
        "name", "type", "risk_score", "risk_level",
        "age_days", "days_since_last_used", "access_key_age_days",
        "policies", "findings", "recommendations",
        "score_age", "score_unused", "score_permissions", "score_key_rotation",
    ]

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for nhi in nhis:
            row = dict(nhi)
            # Listen als Semikolon-getrennte Strings
            for field in ("policies", "findings", "recommendations"):
                val = row.get(field)
                if isinstance(val, list):
                    row[field] = "; ".join(val)
            writer.writerow(row)


def _export_json(nhis: list[dict], scan_meta: dict, path: str) -> None:
    """Schreibt NHIs als JSON."""
    data = {"scan": scan_meta, "nhis": nhis}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Command: explain
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("nhi_name")
@click.option("--db", default=None, help="Pfad zur Datenbankdatei")
def explain(nhi_name: str, db: str | None):
    """Erklärt den Risk Score eines NHI im Detail (LIKELIHOOD × IMPACT).

    \b
    Beispiel:
      python -m src.cli explain svc-old-backup
    """
    import math
    from rich.tree import Tree
    from src.database import get_latest_scan, _DEFAULT_DB_PATH

    db_path = db or _DEFAULT_DB_PATH
    latest = get_latest_scan(db_path=db_path)

    if not latest:
        console.print("[yellow]Keine Scans gefunden. Führe zuerst 'scan' aus.[/yellow]")
        return

    nhi_data = next(
        (n for n in latest["nhis"] if n["name"] == nhi_name),
        None,
    )

    if nhi_data is not None:
        # Aus DB gefundene Daten verwenden
        _print_explain(nhi_data)
    else:
        # Versuche in Mock-Daten zu finden
        mock = next((n for n in _get_mock_nhis() if n["name"] == nhi_name), None)
        if mock:
            from src.risk_scoring import calculate_risk_score
            result = calculate_risk_score(mock)
            _print_explain_from_result(result)
        else:
            console.print(
                f"[red]NHI '{nhi_name}' nicht gefunden.[/red]\n"
                "[dim]Verfügbare NHIs im letzten Scan:[/dim]"
            )
            for n in latest["nhis"]:
                console.print(f"  • {n['name']}")


def _print_explain(nhi: dict) -> None:
    """Gibt die CVSS-Breakdown-Ansicht für ein NHI aus der DB aus."""
    import math
    from rich.tree import Tree

    name = nhi["name"]
    nhi_type = nhi.get("type", "?")
    score = nhi["risk_score"]
    level = nhi["risk_level"]
    level_color = _risk_color(level)

    likelihood = nhi.get("likelihood") or 0.0
    impact = nhi.get("impact") or 0.0
    exposure = nhi.get("exposure") or 0.0
    vulnerability = nhi.get("vulnerability") or 0.0
    attack_vector = nhi.get("attack_vector") or 0.0
    privilege_level = nhi.get("privilege_level") or 0.0
    data_sensitivity = nhi.get("data_sensitivity") or 0.0
    blast_radius = nhi.get("blast_radius") or 0.0

    # Header
    console.print()
    console.print(Panel.fit(
        f"[bold]NHI:[/bold] {name}   [bold]Typ:[/bold] {nhi_type.replace('IAM_', '')}\n"
        f"[bold]Risk Score:[/bold] [{level_color}]{score}/100 ({level})[/{level_color}]",
        title="[cyan]NHI Explain[/cyan]",
        border_style="cyan",
    ))

    # Formel
    raw = math.sqrt(likelihood * impact) if likelihood * impact > 0 else 0
    console.print(
        f"\n  [dim]Formel: sqrt({likelihood:.2f} × {impact:.2f}) × 100 = "
        f"{raw:.3f} × 100 ≈ {score}[/dim]"
    )
    console.print()

    # LIKELIHOOD-Tree
    l_tree = Tree(f"[bold cyan]LIKELIHOOD: {likelihood:.2f}[/bold cyan]  [dim](max 0.9)[/dim]")

    exp_desc = _exposure_desc(exposure)
    vuln_desc = _vuln_desc(vulnerability, nhi)
    av_desc = _av_desc(attack_vector)

    l_tree.add(f"Exposure:       [{'yellow' if exposure > 0 else 'green'}]{exposure:.2f}[/{'yellow' if exposure > 0 else 'green'}]  [dim]{exp_desc}[/dim]")
    l_tree.add(f"Vulnerability:  [{'yellow' if vulnerability > 0 else 'green'}]{vulnerability:.2f}[/{'yellow' if vulnerability > 0 else 'green'}]  [dim]{vuln_desc}[/dim]")
    l_tree.add(f"Attack Vector:  [{'yellow' if attack_vector > 0 else 'green'}]{attack_vector:.2f}[/{'yellow' if attack_vector > 0 else 'green'}]  [dim]{av_desc}[/dim]")
    console.print(l_tree)
    console.print()

    # IMPACT-Tree
    i_tree = Tree(f"[bold magenta]IMPACT: {impact:.2f}[/bold magenta]  [dim](max 1.0)[/dim]")
    priv_desc = _priv_desc(privilege_level)
    i_tree.add(f"Privilege Level:  [{'red' if privilege_level >= 0.3 else 'yellow'}]{privilege_level:.2f}[/{'red' if privilege_level >= 0.3 else 'yellow'}]  [dim]{priv_desc}[/dim]")
    i_tree.add(f"Data Sensitivity: [{'yellow' if data_sensitivity > 0 else 'green'}]{data_sensitivity:.2f}[/{'yellow' if data_sensitivity > 0 else 'green'}]")
    i_tree.add(f"Blast Radius:     [{'yellow' if blast_radius > 0 else 'green'}]{blast_radius:.2f}[/{'yellow' if blast_radius > 0 else 'green'}]")
    console.print(i_tree)
    console.print()

    # Empfehlungen
    recs = nhi.get("recommendations") or []
    if recs:
        console.print("[bold]Empfehlungen:[/bold]")
        for rec in recs:
            # Severity-Tag aus Empfehlung extrahieren
            color = "white"
            if "[KRITISCH]" in rec:
                color = "bold red"
            elif "[HOCH]" in rec:
                color = "red"
            elif "[MITTEL]" in rec:
                color = "yellow"
            console.print(f"  [{color}]→ {rec}[/{color}]")

    # Findings
    findings = nhi.get("findings") or []
    if findings:
        console.print()
        console.print("[bold]Befunde:[/bold]")
        for f in findings:
            console.print(f"  [dim]• {f}[/dim]")


def _print_explain_from_result(result) -> None:
    """Wandelt NHIRiskResult in ein DB-ähnliches Dict um und zeigt es an."""
    nhi_dict = {
        "name": result.name, "type": result.nhi_type,
        "risk_score": result.risk_score, "risk_level": result.risk_level,
        "likelihood": result.likelihood, "impact": result.impact,
        "exposure": result.exposure, "vulnerability": result.vulnerability,
        "attack_vector": result.attack_vector,
        "privilege_level": result.privilege_level,
        "data_sensitivity": result.data_sensitivity,
        "blast_radius": result.blast_radius,
        "findings": result.findings, "recommendations": result.recommendations,
        "age_days": result.age_days,
    }
    _print_explain(nhi_dict)


def _exposure_desc(val: float) -> str:
    if val >= 0.4: return "Bekannte Exposition (suspicious activity)"
    if val >= 0.2: return "Potenziell exponiert (keine IP-Restrictions)"
    return "Gut abgesichert"

def _vuln_desc(val: float, nhi: dict) -> str:
    key_age = nhi.get("access_key_age_days")
    if val >= 0.3: return f"Key nie rotiert UND ≥365d alt{f' ({key_age}d)' if key_age else ''}"
    if val >= 0.2: return "Key nie rotiert ODER ≥365d alt"
    if val >= 0.1: return f"Key ≥90d alt{f' ({key_age}d)' if key_age else ''}"
    return "Key frisch / IAM Role"

def _av_desc(val: float) -> str:
    if val >= 0.2: return "Keine MFA + keine IP-Condition"
    if val >= 0.1: return "Teilweise abgesichert"
    return "MFA + IP-Condition vorhanden"

def _priv_desc(val: float) -> str:
    if val >= 0.5: return "AdministratorAccess (volle Kontrolle)"
    if val >= 0.45: return "IAMFullAccess (Privilege Escalation möglich)"
    if val >= 0.3: return "PowerUser / *FullAccess"
    if val >= 0.2: return "Schreibrechte"
    if val > 0:   return "Leserechte"
    return "Keine Policies"


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
