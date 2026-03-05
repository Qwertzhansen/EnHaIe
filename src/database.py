"""
NHI Discovery Tool - Datenbank-Schicht

Persistiert Scan-Ergebnisse in einer lokalen SQLite-Datenbank.
Kein externer Datenbankserver erforderlich.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

from src.risk_scoring import NHIRiskResult


# Standardpfad relativ zum Projekt-Root
_DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "nhi_discovery.db",
)


# ---------------------------------------------------------------------------
# Initialisierung
# ---------------------------------------------------------------------------

def init_db(db_path: str = _DEFAULT_DB_PATH) -> sqlite3.Connection:
    """
    Initialisiert die SQLite-Datenbank und erstellt Tabellen falls nötig.

    Args:
        db_path: Pfad zur SQLite-Datenbankdatei.

    Returns:
        Offene Datenbankverbindung.
    """
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Ergebnisse als Dict-ähnliche Objekte
    conn.execute("PRAGMA journal_mode=WAL")  # Bessere Concurrent-Reads

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            aws_account     TEXT,
            total_nhis      INTEGER NOT NULL DEFAULT 0,
            critical_count  INTEGER NOT NULL DEFAULT 0,
            high_count      INTEGER NOT NULL DEFAULT 0,
            medium_count    INTEGER NOT NULL DEFAULT 0,
            low_count       INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS nhis (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id         INTEGER NOT NULL REFERENCES scans(id),
            type            TEXT    NOT NULL,
            name            TEXT    NOT NULL,
            aws_account     TEXT,
            created_at      TEXT,
            last_used       TEXT,
            policies        TEXT,   -- JSON-Array als String
            risk_score      INTEGER NOT NULL,
            risk_level      TEXT    NOT NULL,
            age_days        INTEGER,
            days_since_last_used INTEGER,
            access_key_age_days  INTEGER,
            findings        TEXT,   -- JSON-Array als String
            recommendations TEXT,  -- JSON-Array als String
            score_age       INTEGER,
            score_unused    INTEGER,
            score_permissions INTEGER,
            score_key_rotation INTEGER,
            scan_timestamp  TEXT    NOT NULL,
            -- CVSS-inspiriertes Modell (v2)
            likelihood      REAL,
            impact          REAL,
            exposure        REAL,
            vulnerability   REAL,
            attack_vector   REAL,
            privilege_level REAL,
            data_sensitivity REAL,
            blast_radius    REAL
        );

        CREATE INDEX IF NOT EXISTS idx_nhis_scan_id    ON nhis(scan_id);
        CREATE INDEX IF NOT EXISTS idx_nhis_risk_level ON nhis(risk_level);
        CREATE INDEX IF NOT EXISTS idx_nhis_name       ON nhis(name);
        CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
    """)

    # Migration: neue CVSS-Spalten zu bestehenden Tabellen hinzufügen
    _migrate_add_columns(conn, "nhis", [
        ("likelihood",       "REAL"),
        ("impact",           "REAL"),
        ("exposure",         "REAL"),
        ("vulnerability",    "REAL"),
        ("attack_vector",    "REAL"),
        ("privilege_level",  "REAL"),
        ("data_sensitivity", "REAL"),
        ("blast_radius",     "REAL"),
    ])
    conn.commit()
    return conn


def _migrate_add_columns(
    conn: sqlite3.Connection,
    table: str,
    columns: list[tuple[str, str]],
) -> None:
    """Fügt neue Spalten zu einer bestehenden Tabelle hinzu (idempotent)."""
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    for col_name, col_type in columns:
        if col_name not in existing:
            logger.warning("Migration: Füge Spalte '%s %s' zu Tabelle '%s' hinzu", col_name, col_type, table)
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")


# ---------------------------------------------------------------------------
# Schreiben
# ---------------------------------------------------------------------------

def save_scan(
    results: list[NHIRiskResult],
    aws_account: Optional[str] = None,
    db_path: str = _DEFAULT_DB_PATH,
) -> int:
    """
    Speichert einen vollständigen Scan in der Datenbank.

    Args:
        results:     Liste von NHIRiskResult aus score_all().
        aws_account: AWS-Account-ID (optional).
        db_path:     Pfad zur Datenbankdatei.

    Returns:
        Die ID des neu erstellten Scan-Eintrags.
    """
    from src.risk_scoring import summarize

    conn = init_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    summary = summarize(results)

    try:
        cursor = conn.execute(
            """
            INSERT INTO scans (timestamp, aws_account, total_nhis,
                               critical_count, high_count, medium_count, low_count)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                aws_account,
                summary["total"],
                summary["critical_count"],
                summary["high_count"],
                summary["medium_count"],
                summary["low_count"],
            ),
        )
        scan_id = cursor.lastrowid

        for r in results:
            conn.execute(
                """
                INSERT INTO nhis (
                    scan_id, type, name, aws_account, policies,
                    risk_score, risk_level, age_days, days_since_last_used,
                    access_key_age_days, findings, recommendations,
                    score_age, score_unused, score_permissions, score_key_rotation,
                    scan_timestamp,
                    likelihood, impact, exposure, vulnerability, attack_vector,
                    privilege_level, data_sensitivity, blast_radius
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    r.nhi_type,
                    r.name,
                    aws_account,
                    json.dumps(r.policies),
                    r.risk_score,
                    r.risk_level,
                    r.age_days,
                    r.days_since_last_used,
                    r.access_key_age_days,
                    json.dumps(r.findings),
                    json.dumps(r.recommendations),
                    r.score_age,
                    r.score_unused,
                    r.score_permissions,
                    r.score_key_rotation,
                    now,
                    r.likelihood,
                    r.impact,
                    r.exposure,
                    r.vulnerability,
                    r.attack_vector,
                    r.privilege_level,
                    r.data_sensitivity,
                    r.blast_radius,
                ),
            )

        conn.commit()
        return scan_id

    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Lesen
# ---------------------------------------------------------------------------

def _row_to_dict(row: sqlite3.Row) -> dict:
    """Konvertiert eine SQLite-Row in ein Dict, parst JSON-Felder."""
    d = dict(row)
    for field in ("policies", "findings", "recommendations"):
        if d.get(field):
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, TypeError) as exc:
                logger.warning("JSON-Parse-Fehler für Feld '%s' (row id=%s): %s", field, d.get("id"), exc)
                d[field] = []
    return d


def get_latest_scan(db_path: str = _DEFAULT_DB_PATH) -> Optional[dict]:
    """
    Gibt den neuesten Scan mit allen NHIs zurück.

    Returns:
        Dict mit 'scan' (Metadaten) und 'nhis' (Liste), oder None wenn keine Scans.
    """
    if not os.path.exists(db_path):
        return None

    conn = init_db(db_path)
    try:
        scan_row = conn.execute(
            "SELECT * FROM scans ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()

        if not scan_row:
            return None

        scan = dict(scan_row)
        nhi_rows = conn.execute(
            "SELECT * FROM nhis WHERE scan_id = ? ORDER BY risk_score DESC",
            (scan["id"],),
        ).fetchall()

        return {
            "scan": scan,
            "nhis": [_row_to_dict(r) for r in nhi_rows],
        }
    finally:
        conn.close()


def get_scan_history(db_path: str = _DEFAULT_DB_PATH) -> list[dict]:
    """
    Gibt alle Scans als Liste zurück, neueste zuerst.

    Returns:
        Liste von Scan-Dicts mit Metadaten (ohne NHI-Details).
    """
    if not os.path.exists(db_path):
        return []

    conn = init_db(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY timestamp DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_nhi_trend(nhi_name: str, db_path: str = _DEFAULT_DB_PATH) -> list[dict]:
    """
    Gibt die Risk-Score-Entwicklung eines NHI über alle Scans zurück.

    Args:
        nhi_name: Name des NHI.
        db_path:  Pfad zur Datenbankdatei.

    Returns:
        Liste von Dicts mit 'scan_timestamp' und 'risk_score', älteste zuerst.
    """
    if not os.path.exists(db_path):
        return []

    conn = init_db(db_path)
    try:
        rows = conn.execute(
            """
            SELECT n.scan_timestamp, n.risk_score, n.risk_level
            FROM nhis n
            WHERE n.name = ?
            ORDER BY n.scan_timestamp ASC
            """,
            (nhi_name,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_all_nhis_latest(db_path: str = _DEFAULT_DB_PATH) -> list[dict]:
    """
    Gibt alle NHIs des neuesten Scans zurück (Kurzform, ohne scan-Metadaten).

    Returns:
        Liste von NHI-Dicts, nach risk_score absteigend sortiert.
    """
    latest = get_latest_scan(db_path)
    if not latest:
        return []
    return latest["nhis"]
