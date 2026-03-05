"""
Test-Fixtures für das NHI Discovery Tool.

Alle Tests laufen ohne echte AWS-Credentials.
Die Fixtures liefern realistische Mock-Daten für das neue CVSS-Modell.
"""

import json
import os
from datetime import datetime, timezone, timedelta
from typing import Any

import pytest


_FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


# ---------------------------------------------------------------------------
# Standard-Konfiguration
# ---------------------------------------------------------------------------

@pytest.fixture
def config():
    """Standard-Testkonfiguration (entspricht config.yaml)."""
    return {
        "scoring": {
            "model": "cvss_inspired",
            "thresholds": {
                "key_rotation_warning_days": 90,
                "key_rotation_critical_days": 365,
            },
        },
        "risk_levels": {
            "critical": 80,
            "high": 60,
            "medium": 40,
        },
    }


# ---------------------------------------------------------------------------
# NHI-Fixtures (CVSS-Modell)
# ---------------------------------------------------------------------------

@pytest.fixture
def nhi_critical():
    """
    CRITICAL-NHI: Verdächtige Aktivität + Admin + Cross-Account + Secrets.
    Erwartet: Score ≥ 60 (HIGH), wahrscheinlich CRITICAL.
    L = 0.9 (suspicious=0.4, vuln=0.3, av=0.2), I = 1.0 (admin=0.5, secrets=0.3, blast=0.2)
    sqrt(0.9 × 1.0) × 100 ≈ 95
    """
    return {
        "type": "IAM_USER",
        "name": "svc-compromised",
        "age_days": 500,
        "days_since_last_used": 1,
        "last_used": "2026-02-28",
        "policies": ["AdministratorAccess", "SecretsManagerReadWrite"],
        "access_key_1_age_days": 500,
        "access_key_1_status": "Active",
        "has_ip_condition": False,
        "has_mfa_condition": False,
        "suspicious_activity_flag": True,
        "assume_role_policy": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "sts:AssumeRole",
                }
            ]
        },
    }


@pytest.fixture
def nhi_high():
    """
    HIGH-NHI: Keine IP-Restrictions, Vulnerability, FullAccess-Policies.
    L ≈ 0.5-0.7, I ≈ 0.5-0.7
    """
    return {
        "type": "IAM_USER",
        "name": "svc-deployment",
        "age_days": 180,
        "days_since_last_used": 2,
        "policies": ["AmazonS3FullAccess", "AmazonEC2FullAccess"],
        "access_key_1_age_days": 95,
        "access_key_1_status": "Active",
        "has_ip_condition": False,
        "has_mfa_condition": False,
    }


@pytest.fixture
def nhi_medium():
    """
    MEDIUM-NHI: S3-Zugriff, kein MFA, moderate Key-Alter.
    """
    return {
        "type": "IAM_ROLE",
        "name": "role-lambda-overprivileged",
        "age_days": 300,
        "days_since_last_used": 95,
        "policies": ["AdministratorAccess"],
        "has_ip_condition": False,
        "assume_role_policy": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ]
        },
    }


@pytest.fixture
def nhi_low():
    """
    LOW-NHI: Vollständig abgesichert, ReadOnly-Policies.
    L = 0.0 (alle Conditions vorhanden), I = 0.05 (ReadOnly)
    Score = 0
    """
    return {
        "type": "IAM_ROLE",
        "name": "role-lambda-secure",
        "age_days": 10,
        "days_since_last_used": 1,
        "policies": ["AmazonS3ReadOnlyAccess"],
        "has_ip_condition": True,
        "has_mfa_condition": True,
        "assume_role_policy": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
                }
            ]
        },
    }


@pytest.fixture
def nhi_no_policies():
    """NHI ohne Policies – Privilege Level = 0."""
    return {
        "type": "IAM_ROLE",
        "name": "role-empty",
        "age_days": 30,
        "days_since_last_used": 5,
        "policies": [],
        "has_ip_condition": False,
    }


@pytest.fixture
def nhi_inactive_key():
    """User mit inaktivem Key – Vulnerability soll 0 sein."""
    return {
        "type": "IAM_USER",
        "name": "svc-rotated",
        "age_days": 200,
        "days_since_last_used": 2,
        "policies": ["AmazonS3ReadOnlyAccess"],
        "access_key_1_age_days": 200,
        "access_key_1_status": "Inactive",  # Inaktiv!
    }


@pytest.fixture
def nhi_cross_account():
    """IAM Role mit Cross-Account-Zugriff → Blast Radius +0.1."""
    return {
        "type": "IAM_ROLE",
        "name": "role-cross-account",
        "age_days": 100,
        "days_since_last_used": 10,
        "policies": ["AmazonS3ReadOnlyAccess"],
        "has_ip_condition": False,
        "assume_role_policy": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::987654321098:root"},
                    "Action": "sts:AssumeRole",
                }
            ]
        },
    }


@pytest.fixture
def sample_nhi_list(nhi_critical, nhi_high, nhi_medium, nhi_low):
    """Liste mit mehreren NHIs für Integrationstests."""
    return [nhi_critical, nhi_high, nhi_medium, nhi_low]


# ---------------------------------------------------------------------------
# CloudTrail-Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_cloudtrail_events():
    """Lädt Mock-CloudTrail-Events aus der JSON-Fixture."""
    path = os.path.join(_FIXTURES_DIR, "mock_cloudtrail_events.json")
    with open(path) as fh:
        raw = json.load(fh)

    # EventTime als datetime-Objekte parsen
    events = []
    for event in raw:
        e = dict(event)
        if "EventTime" in e:
            try:
                e["EventTime"] = datetime.fromisoformat(e["EventTime"])
            except (ValueError, TypeError):
                pass
        events.append(e)

    return events


@pytest.fixture
def mock_iam_data():
    """Lädt Mock-IAM-Daten aus der JSON-Fixture."""
    path = os.path.join(_FIXTURES_DIR, "mock_iam_data.json")
    with open(path) as fh:
        return json.load(fh)
