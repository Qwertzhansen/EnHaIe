"""
NHI Discovery Tool – CloudTrail-Analyzer

Analysiert AWS CloudTrail-Logs um:
1. NHI-Aktivität zu tracken (last_used, usage_pattern)
2. Ungenutzte NHIs zu identifizieren
3. Verdächtige Aktivitäten zu erkennen (Anomalie-Erkennung)
4. NHI-Daten für das Risk-Scoring anzureichern

Design: Boto3-Client wird injiziert (dependency injection) → einfaches Mocking in Tests.

Wichtig: CloudTrail `LookupEvents` gibt max. 90 Tage zurück.
Für längere Zeiträume wird CloudTrail Lake oder S3-Export benötigt.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Protocol

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Typdefinitionen
# ---------------------------------------------------------------------------

class CloudTrailClient(Protocol):
    """Boto3-CloudTrail-Client-Interface (für Type-Checking und Mocking)."""
    def lookup_events(self, **kwargs: Any) -> dict: ...


# Sensitive IAM-APIs die auf Privilege Escalation hindeuten
_SENSITIVE_APIS = frozenset({
    "CreateUser",
    "CreateRole",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreatePolicy",
    "CreatePolicyVersion",
    "AddUserToGroup",
    "CreateAccessKey",
    "UpdateAssumeRolePolicy",
    "SetDefaultPolicyVersion",
})

# Normale Betriebszeiten (UTC): 06:00 – 22:00
_BUSINESS_HOURS_START = 6
_BUSINESS_HOURS_END = 22

# Bekannte AWS-interne IP-Ranges (vereinfacht – in Produktion: aws.amazon.com/ip-ranges.json)
_AWS_IP_PREFIX = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.0\.0\.1)"
)


# ---------------------------------------------------------------------------
# Haupt-Funktionen
# ---------------------------------------------------------------------------

def get_nhi_activity(
    ct_client: CloudTrailClient,
    days: int = 90,
) -> list[dict]:
    """
    Holt alle IAM-bezogenen CloudTrail-Events der letzten `days` Tage.

    Nutzt `lookup_events` mit EventSource-Filter auf iam.amazonaws.com.
    Paginiert automatisch über NextToken.

    Args:
        ct_client: Boto3-CloudTrail-Client (oder Mock).
        days:      Zeitraum in Tagen (max. 90 für LookupEvents).

    Returns:
        Liste von Event-Dictionaries mit:
          - EventId, EventName, EventTime (datetime)
          - Username (wer hat den API-Call gemacht)
          - SourceIPAddress
          - Resources (betroffene IAM-Ressourcen)
    """
    if days < 1:
        raise ValueError(f"days muss mindestens 1 sein, erhalten: {days}")
    if days > 90:
        logger.warning(
            "CloudTrail LookupEvents unterstützt max. 90 Tage. "
            "Anfrage für %d Tage wird auf 90 Tage begrenzt.", days
        )

    start_time = datetime.now(timezone.utc) - timedelta(days=min(days, 90))
    logger.info("Rufe CloudTrail-Events ab: Zeitraum %d Tage", min(days, 90))
    events: list[dict] = []
    next_token: Optional[str] = None

    while True:
        kwargs: dict = {
            "LookupAttributes": [
                {"AttributeKey": "EventSource", "AttributeValue": "iam.amazonaws.com"}
            ],
            "StartTime": start_time,
            "MaxResults": 50,
        }
        if next_token:
            kwargs["NextToken"] = next_token

        response = ct_client.lookup_events(**kwargs)
        events.extend(response.get("Events", []))

        next_token = response.get("NextToken")
        if not next_token:
            break

    return events


def find_unused_nhis(
    nhi_names: list[str],
    events: list[dict],
) -> list[str]:
    """
    Identifiziert NHIs ohne CloudTrail-Aktivität im betrachteten Zeitraum.

    Args:
        nhi_names: Liste der NHI-Namen (aus IAM Discovery).
        events:    CloudTrail-Events (Ausgabe von get_nhi_activity).

    Returns:
        Liste der NHI-Namen ohne CloudTrail-Aktivität.
    """
    active_users: set[str] = set()

    for event in events:
        username = event.get("Username", "")
        if username:
            active_users.add(username)

        # Auch aus Resources extrahieren
        for resource in event.get("Resources", []):
            if resource.get("ResourceType") in ("AWS::IAM::User", "AWS::IAM::Role"):
                name = resource.get("ResourceName", "")
                if name:
                    active_users.add(name)

    return [name for name in nhi_names if name not in active_users]


def find_suspicious_activity(events: list[dict]) -> list[dict]:
    """
    Erkennt anomale Aktivitäten in CloudTrail-Events.

    Erkennungsregeln:
      1. API-Calls außerhalb Betriebszeiten (06:00–22:00 UTC)
      2. Sensitive IAM-APIs (Privilege Escalation Indicators)
      3. Calls von nicht-privaten IP-Adressen (externe IPs)

    Args:
        events: CloudTrail-Events (Ausgabe von get_nhi_activity).

    Returns:
        Liste verdächtiger Events mit zusätzlichem `suspicion_reason`-Feld.
    """
    suspicious: list[dict] = []

    for event in events:
        reasons: list[str] = []
        event_name = event.get("EventName", "")
        event_time = event.get("EventTime")
        source_ip = event.get("SourceIPAddress", "")
        username = event.get("Username", "")

        # Regel 1: Außerhalb Betriebszeiten
        if isinstance(event_time, datetime):
            hour = event_time.astimezone(timezone.utc).hour
            if not (_BUSINESS_HOURS_START <= hour < _BUSINESS_HOURS_END):
                reasons.append(
                    f"API-Call außerhalb Betriebszeiten ({hour:02d}:xx UTC)"
                )

        # Regel 2: Sensitive API
        if event_name in _SENSITIVE_APIS:
            reasons.append(f"Sensitive API: {event_name} (Privilege Escalation Indicator)")

        # Regel 3: Externe IP (nicht intern / kein AWS-Service)
        if (
            source_ip
            and not _AWS_IP_PREFIX.match(source_ip)
            and not source_ip.endswith(".amazonaws.com")
            and source_ip not in ("AWS Internal", "")
        ):
            reasons.append(f"Zugriff von externer IP: {source_ip}")

        if reasons:
            suspicious_event = dict(event)
            suspicious_event["suspicion_reasons"] = reasons
            suspicious_event["username"] = username
            suspicious.append(suspicious_event)

    return suspicious


def get_nhi_usage_pattern(
    events: list[dict],
    nhi_name: str,
) -> dict:
    """
    Analysiert das Nutzungsmuster eines NHI.

    Args:
        events:   CloudTrail-Events (Ausgabe von get_nhi_activity).
        nhi_name: Name des NHI.

    Returns:
        Dict mit:
          - total_calls:      Gesamtanzahl API-Calls
          - last_seen:        Letzter bekannter Zeitstempel (datetime | None)
          - days_since_last_used: Tage seit letzter Nutzung (int | None)
          - peak_hours:       Top-3 Stunden mit den meisten Calls
          - calls_per_day:    Durchschnittliche Calls pro Tag
          - api_calls:        Dict {EventName: Anzahl}
          - suspicious_count: Anzahl verdächtiger Events für dieses NHI
    """
    nhi_events = [
        e for e in events
        if e.get("Username") == nhi_name
        or any(
            r.get("ResourceName") == nhi_name
            for r in e.get("Resources", [])
        )
    ]

    if not nhi_events:
        return {
            "total_calls": 0,
            "last_seen": None,
            "days_since_last_used": None,
            "peak_hours": [],
            "calls_per_day": 0.0,
            "api_calls": {},
            "suspicious_count": 0,
        }

    # Zeitstempel filtern
    timestamps = [
        e["EventTime"] for e in nhi_events
        if isinstance(e.get("EventTime"), datetime)
    ]

    last_seen = max(timestamps) if timestamps else None
    days_since = None
    if last_seen:
        delta = datetime.now(timezone.utc) - last_seen.astimezone(timezone.utc)
        days_since = max(0, delta.days)

    # Stunden-Verteilung
    hour_counts: dict[int, int] = defaultdict(int)
    api_counts: dict[str, int] = defaultdict(int)
    for e in nhi_events:
        t = e.get("EventTime")
        if isinstance(t, datetime):
            hour_counts[t.astimezone(timezone.utc).hour] += 1
        name = e.get("EventName", "Unknown")
        api_counts[name] += 1

    peak_hours = sorted(hour_counts.keys(), key=lambda h: hour_counts[h], reverse=True)[:3]

    # Calls pro Tag (über Zeitraum der Events)
    if timestamps and len(timestamps) > 1:
        span_days = max(1, (max(timestamps) - min(timestamps)).days + 1)
    else:
        span_days = 1
    calls_per_day = round(len(nhi_events) / span_days, 2)

    # Verdächtige Events für dieses NHI
    suspicious_events = find_suspicious_activity(nhi_events)

    return {
        "total_calls": len(nhi_events),
        "last_seen": last_seen,
        "days_since_last_used": days_since,
        "peak_hours": peak_hours,
        "calls_per_day": calls_per_day,
        "api_calls": dict(api_counts),
        "suspicious_count": len(suspicious_events),
    }


def enrich_nhis_with_cloudtrail(
    nhis: list[dict],
    events: list[dict],
) -> list[dict]:
    """
    Reichert NHI-Daten mit CloudTrail-Informationen an.

    Fügt für jedes NHI hinzu:
      - days_since_last_used (überschreibt IAM-Wert falls CloudTrail aktueller)
      - suspicious_activity_flag (bool)
      - cloudtrail_calls      (Gesamtanzahl API-Calls)

    Args:
        nhis:   Liste von NHI-Dicts (Ausgabe von discovery.py).
        events: CloudTrail-Events (Ausgabe von get_nhi_activity).

    Returns:
        Angereicherte NHI-Liste (Kopie, Original unverändert).
    """
    # Suspicious Events pro User vorberechnen
    suspicious_by_user: dict[str, list[dict]] = defaultdict(list)
    for event in find_suspicious_activity(events):
        user = event.get("username") or event.get("Username", "")
        if user:
            suspicious_by_user[user].append(event)

    enriched: list[dict] = []
    for nhi in nhis:
        nhi_copy = dict(nhi)
        name = nhi.get("name", "")

        pattern = get_nhi_usage_pattern(events, name)

        # days_since_last_used: CloudTrail-Wert ist genauer
        if pattern["days_since_last_used"] is not None:
            nhi_copy["days_since_last_used"] = pattern["days_since_last_used"]

        nhi_copy["suspicious_activity_flag"] = len(suspicious_by_user.get(name, [])) > 0
        nhi_copy["cloudtrail_calls"] = pattern["total_calls"]
        nhi_copy["cloudtrail_suspicious_events"] = suspicious_by_user.get(name, [])

        enriched.append(nhi_copy)

    return enriched
