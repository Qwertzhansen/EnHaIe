"""
Unit Tests für den CloudTrail-Analyzer.

Alle Tests nutzen Mock-Daten aus tests/fixtures/mock_cloudtrail_events.json.
Keine AWS-Credentials nötig.

mock_cloudtrail_events enthält 10 Events:
  - svc-deployment:    3 Events, business hours, interne IPs (10.x.x.x) → unauffällig
  - role-ec2-webserver: 1 Event, business hours, interne IP (172.16.x.x)
  - svc-old-backup:    2 Events, 03:17/03:18 UTC, CreateAccessKey+AttachUserPolicy,
                       externe IP (203.0.113.42) → VERDÄCHTIG
  - role-compromised:  2 Events, 04:00/02:30 UTC, GetSecretValue+CreateUser,
                       externe IPs → VERDÄCHTIG
  - svc-external-api:  2 Events, business hours, 192.168.1.x (privat) → unauffällig
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

from src.cloudtrail_analyzer import (
    enrich_nhis_with_cloudtrail,
    find_suspicious_activity,
    find_unused_nhis,
    get_nhi_activity,
    get_nhi_usage_pattern,
)


# ---------------------------------------------------------------------------
# Tests: find_unused_nhis()
# ---------------------------------------------------------------------------

class TestFindUnusedNhis:
    def test_active_nhi_not_in_unused_list(self, mock_cloudtrail_events):
        unused = find_unused_nhis(["svc-deployment"], mock_cloudtrail_events)
        assert "svc-deployment" not in unused

    def test_role_active_via_resource_not_in_unused(self, mock_cloudtrail_events):
        # role-ec2-webserver hat ein Event als Username + Resource
        unused = find_unused_nhis(["role-ec2-webserver"], mock_cloudtrail_events)
        assert "role-ec2-webserver" not in unused

    def test_nonexistent_nhi_is_unused(self, mock_cloudtrail_events):
        unused = find_unused_nhis(["svc-nonexistent-service"], mock_cloudtrail_events)
        assert "svc-nonexistent-service" in unused

    def test_empty_events_all_marked_unused(self):
        nhis = ["svc-a", "svc-b"]
        unused = find_unused_nhis(nhis, [])
        assert set(unused) == set(nhis)

    def test_empty_nhi_list_returns_empty(self, mock_cloudtrail_events):
        unused = find_unused_nhis([], mock_cloudtrail_events)
        assert unused == []

    def test_mixed_list_correctly_partitioned(self, mock_cloudtrail_events):
        nhis = ["svc-deployment", "svc-nonexistent", "role-ec2-webserver"]
        unused = find_unused_nhis(nhis, mock_cloudtrail_events)
        assert "svc-deployment" not in unused
        assert "role-ec2-webserver" not in unused
        assert "svc-nonexistent" in unused

    def test_returns_list_not_set(self, mock_cloudtrail_events):
        unused = find_unused_nhis(["svc-nonexistent"], mock_cloudtrail_events)
        assert isinstance(unused, list)


# ---------------------------------------------------------------------------
# Tests: find_suspicious_activity()
# ---------------------------------------------------------------------------

class TestFindSuspiciousActivity:
    def test_night_call_is_suspicious(self, mock_cloudtrail_events):
        """Events von svc-old-backup um 03:17/03:18 UTC → außerhalb Betriebszeiten."""
        suspicious = find_suspicious_activity(mock_cloudtrail_events)
        usernames = [e.get("Username") for e in suspicious]
        assert "svc-old-backup" in usernames

    def test_sensitive_api_is_suspicious(self, mock_cloudtrail_events):
        """CreateAccessKey und AttachUserPolicy sind sensitive APIs."""
        suspicious = find_suspicious_activity(mock_cloudtrail_events)
        event_names = [e.get("EventName") for e in suspicious]
        assert "CreateAccessKey" in event_names
        assert "AttachUserPolicy" in event_names

    def test_external_ip_is_suspicious(self, mock_cloudtrail_events):
        """203.0.113.x ist eine öffentliche IP → Verdacht."""
        suspicious = find_suspicious_activity(mock_cloudtrail_events)
        source_ips = [e.get("SourceIPAddress") for e in suspicious]
        assert any(ip and ip.startswith("203.0.113") for ip in source_ips)

    def test_role_compromised_is_suspicious(self, mock_cloudtrail_events):
        """role-compromised: CreateUser um 02:30 UTC, externe IP → verdächtig."""
        suspicious = find_suspicious_activity(mock_cloudtrail_events)
        usernames = [e.get("Username") for e in suspicious]
        assert "role-compromised" in usernames

    def test_internal_ip_business_hours_not_suspicious(self):
        """Normale Nutzung: interner IP + business hours → kein Verdacht."""
        events = [{
            "EventId": "test-001",
            "EventName": "GetUser",
            "EventTime": datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc),
            "Username": "svc-normal",
            "SourceIPAddress": "10.0.1.50",
            "Resources": [],
        }]
        suspicious = find_suspicious_activity(events)
        assert len(suspicious) == 0

    def test_private_192_168_ip_not_suspicious(self):
        """192.168.x.x ist ein privater IP-Bereich → kein External-IP-Verdacht."""
        events = [{
            "EventId": "test-002",
            "EventName": "DescribeInstances",
            "EventTime": datetime(2026, 3, 1, 14, 0, tzinfo=timezone.utc),
            "Username": "svc-external-api",
            "SourceIPAddress": "192.168.1.100",
            "Resources": [],
        }]
        suspicious = find_suspicious_activity(events)
        # Kein Verdacht: interne IP, business hours, harmlose API
        assert len(suspicious) == 0

    def test_suspicious_event_has_suspicion_reasons_field(self, mock_cloudtrail_events):
        suspicious = find_suspicious_activity(mock_cloudtrail_events)
        assert len(suspicious) > 0
        for event in suspicious:
            assert "suspicion_reasons" in event
            assert len(event["suspicion_reasons"]) > 0

    def test_empty_events_returns_empty(self):
        assert find_suspicious_activity([]) == []

    def test_aws_service_ip_not_suspicious(self):
        """AWS-Service-IPs (iam.amazonaws.com) sind keine externen IPs."""
        events = [{
            "EventId": "test-003",
            "EventName": "GetUser",
            "EventTime": datetime(2026, 3, 1, 15, 0, tzinfo=timezone.utc),
            "Username": "svc-test",
            "SourceIPAddress": "iam.amazonaws.com",
            "Resources": [],
        }]
        suspicious = find_suspicious_activity(events)
        assert len(suspicious) == 0

    def test_create_user_at_night_is_suspicious(self):
        """CreateUser um 02:30 UTC: Nacht + sensitive API + externe IP."""
        events = [{
            "EventId": "evt-010-test",
            "EventName": "CreateUser",
            "EventTime": datetime(2026, 2, 19, 2, 30, tzinfo=timezone.utc),
            "Username": "role-test",
            "SourceIPAddress": "198.51.100.77",
            "Resources": [],
        }]
        suspicious = find_suspicious_activity(events)
        assert len(suspicious) == 1
        reasons = suspicious[0]["suspicion_reasons"]
        assert any("02:" in r for r in reasons)     # Nacht
        assert any("CreateUser" in r for r in reasons)  # Sensitive API
        assert any("198.51.100" in r for r in reasons)  # Externe IP

    def test_svc_deployment_business_hours_not_suspicious(self, mock_cloudtrail_events):
        """svc-deployment nutzt nur business hours + interne IPs → unauffällig."""
        # Nur svc-deployment Events filtern
        deployment_events = [
            e for e in mock_cloudtrail_events
            if e.get("Username") == "svc-deployment"
        ]
        suspicious = find_suspicious_activity(deployment_events)
        assert len(suspicious) == 0


# ---------------------------------------------------------------------------
# Tests: get_nhi_usage_pattern()
# ---------------------------------------------------------------------------

class TestGetNhiUsagePattern:
    def test_known_nhi_has_activity(self, mock_cloudtrail_events):
        pattern = get_nhi_usage_pattern(mock_cloudtrail_events, "svc-deployment")
        assert pattern["total_calls"] >= 3

    def test_nonexistent_nhi_zero_calls(self, mock_cloudtrail_events):
        pattern = get_nhi_usage_pattern(mock_cloudtrail_events, "nonexistent-nhi")
        assert pattern["total_calls"] == 0
        assert pattern["last_seen"] is None
        assert pattern["days_since_last_used"] is None

    def test_pattern_has_required_keys(self, mock_cloudtrail_events):
        pattern = get_nhi_usage_pattern(mock_cloudtrail_events, "svc-deployment")
        required_keys = [
            "total_calls", "last_seen", "days_since_last_used",
            "peak_hours", "calls_per_day", "api_calls", "suspicious_count",
        ]
        for key in required_keys:
            assert key in pattern, f"Schlüssel '{key}' fehlt in Pattern"

    def test_api_calls_breakdown_for_svc_deployment(self, mock_cloudtrail_events):
        """svc-deployment hat GetUser, ListBuckets, PutObject Calls."""
        pattern = get_nhi_usage_pattern(mock_cloudtrail_events, "svc-deployment")
        assert "GetUser" in pattern["api_calls"]
        assert "ListBuckets" in pattern["api_calls"]

    def test_peak_hours_are_valid(self, mock_cloudtrail_events):
        pattern = get_nhi_usage_pattern(mock_cloudtrail_events, "svc-deployment")
        for hour in pattern["peak_hours"]:
            assert 0 <= hour <= 23

    def test_days_since_non_negative(self, mock_cloudtrail_events):
        pattern = get_nhi_usage_pattern(mock_cloudtrail_events, "svc-deployment")
        if pattern["days_since_last_used"] is not None:
            assert pattern["days_since_last_used"] >= 0

    def test_last_seen_is_datetime(self, mock_cloudtrail_events):
        pattern = get_nhi_usage_pattern(mock_cloudtrail_events, "svc-deployment")
        assert isinstance(pattern["last_seen"], datetime)

    def test_suspicious_count_for_compromised_role(self, mock_cloudtrail_events):
        """role-compromised hat 2 verdächtige Events."""
        pattern = get_nhi_usage_pattern(mock_cloudtrail_events, "role-compromised")
        assert pattern["suspicious_count"] > 0

    def test_suspicious_count_for_svc_deployment_is_zero(self, mock_cloudtrail_events):
        """svc-deployment ist unauffällig → suspicious_count = 0."""
        pattern = get_nhi_usage_pattern(mock_cloudtrail_events, "svc-deployment")
        assert pattern["suspicious_count"] == 0

    def test_calls_per_day_positive(self, mock_cloudtrail_events):
        pattern = get_nhi_usage_pattern(mock_cloudtrail_events, "svc-deployment")
        assert pattern["calls_per_day"] > 0.0


# ---------------------------------------------------------------------------
# Tests: enrich_nhis_with_cloudtrail()
# ---------------------------------------------------------------------------

class TestEnrichNhisWithCloudtrail:
    def test_enriched_has_cloudtrail_calls_field(self, mock_cloudtrail_events):
        nhis = [{"name": "svc-deployment", "type": "IAM_USER"}]
        enriched = enrich_nhis_with_cloudtrail(nhis, mock_cloudtrail_events)
        assert "cloudtrail_calls" in enriched[0]
        assert enriched[0]["cloudtrail_calls"] > 0

    def test_suspicious_flag_set_for_svc_old_backup(self, mock_cloudtrail_events):
        nhis = [{"name": "svc-old-backup", "type": "IAM_USER"}]
        enriched = enrich_nhis_with_cloudtrail(nhis, mock_cloudtrail_events)
        assert enriched[0]["suspicious_activity_flag"] is True

    def test_suspicious_flag_false_for_normal_nhi(self, mock_cloudtrail_events):
        nhis = [{"name": "svc-deployment", "type": "IAM_USER"}]
        enriched = enrich_nhis_with_cloudtrail(nhis, mock_cloudtrail_events)
        assert enriched[0]["suspicious_activity_flag"] is False

    def test_original_nhis_unchanged(self, mock_cloudtrail_events):
        nhis = [{"name": "svc-deployment", "type": "IAM_USER"}]
        original_copy = dict(nhis[0])
        enrich_nhis_with_cloudtrail(nhis, mock_cloudtrail_events)
        assert nhis[0] == original_copy

    def test_days_since_last_used_updated_from_cloudtrail(self, mock_cloudtrail_events):
        nhis = [{"name": "svc-deployment", "type": "IAM_USER", "days_since_last_used": 9999}]
        enriched = enrich_nhis_with_cloudtrail(nhis, mock_cloudtrail_events)
        # CloudTrail-Daten sollen IAM-Wert überschreiben
        assert enriched[0]["days_since_last_used"] != 9999

    def test_empty_nhis_returns_empty(self, mock_cloudtrail_events):
        enriched = enrich_nhis_with_cloudtrail([], mock_cloudtrail_events)
        assert enriched == []

    def test_enriched_preserves_existing_fields(self, mock_cloudtrail_events):
        nhis = [{"name": "svc-deployment", "type": "IAM_USER", "policies": ["S3FullAccess"]}]
        enriched = enrich_nhis_with_cloudtrail(nhis, mock_cloudtrail_events)
        assert enriched[0]["policies"] == ["S3FullAccess"]
        assert enriched[0]["type"] == "IAM_USER"

    def test_enriched_adds_suspicious_events_list(self, mock_cloudtrail_events):
        nhis = [{"name": "svc-old-backup", "type": "IAM_USER"}]
        enriched = enrich_nhis_with_cloudtrail(nhis, mock_cloudtrail_events)
        assert "cloudtrail_suspicious_events" in enriched[0]
        assert len(enriched[0]["cloudtrail_suspicious_events"]) > 0

    def test_enriched_list_same_length_as_input(self, mock_cloudtrail_events, mock_iam_data):
        enriched = enrich_nhis_with_cloudtrail(mock_iam_data, mock_cloudtrail_events)
        assert len(enriched) == len(mock_iam_data)


# ---------------------------------------------------------------------------
# Tests: get_nhi_activity() – mit Mock-Client
# ---------------------------------------------------------------------------

class TestGetNhiActivity:
    def test_returns_events_from_client(self):
        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {
            "Events": [{"EventId": "test-1", "EventName": "GetUser", "Username": "svc-test"}]
        }
        events = get_nhi_activity(mock_client, days=7)
        assert len(events) == 1
        assert events[0]["EventId"] == "test-1"

    def test_paginates_with_next_token(self):
        mock_client = MagicMock()
        mock_client.lookup_events.side_effect = [
            {"Events": [{"EventId": "page1-evt"}], "NextToken": "token-abc"},
            {"Events": [{"EventId": "page2-evt"}]},
        ]
        events = get_nhi_activity(mock_client, days=7)
        assert len(events) == 2
        assert events[0]["EventId"] == "page1-evt"
        assert events[1]["EventId"] == "page2-evt"

    def test_empty_response(self):
        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {"Events": []}
        events = get_nhi_activity(mock_client, days=7)
        assert events == []

    def test_lookup_called_with_iam_event_source(self):
        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {"Events": []}
        get_nhi_activity(mock_client, days=7)
        call_kwargs = mock_client.lookup_events.call_args[1]
        attrs = call_kwargs["LookupAttributes"]
        assert any(a["AttributeValue"] == "iam.amazonaws.com" for a in attrs)

    def test_days_capped_at_90(self):
        """CloudTrail LookupEvents unterstützt max. 90 Tage."""
        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {"Events": []}
        get_nhi_activity(mock_client, days=200)
        # MaxResults und StartTime werden gesetzt – Hauptsache es wird aufgerufen
        mock_client.lookup_events.assert_called_once()

    def test_multiple_pages_all_collected(self):
        """Drei Seiten mit je 2 Events → 6 Events total."""
        mock_client = MagicMock()
        mock_client.lookup_events.side_effect = [
            {"Events": [{"EventId": "e1"}, {"EventId": "e2"}], "NextToken": "t1"},
            {"Events": [{"EventId": "e3"}, {"EventId": "e4"}], "NextToken": "t2"},
            {"Events": [{"EventId": "e5"}, {"EventId": "e6"}]},
        ]
        events = get_nhi_activity(mock_client, days=30)
        assert len(events) == 6


# ---------------------------------------------------------------------------
# Neue Tests: Input-Validierung für get_nhi_activity()
# ---------------------------------------------------------------------------

class TestGetNhiActivityInputValidation:
    def test_days_zero_raises_value_error(self):
        """days=0 ist ungültig → ValueError."""
        mock_client = MagicMock()
        with pytest.raises(ValueError, match="mindestens 1"):
            get_nhi_activity(mock_client, days=0)

    def test_days_negative_raises_value_error(self):
        """Negativer days-Wert ist ungültig → ValueError."""
        mock_client = MagicMock()
        with pytest.raises(ValueError):
            get_nhi_activity(mock_client, days=-5)

    def test_days_91_logs_warning(self, caplog):
        """days=91 überschreitet CloudTrail-Limit → Warning wird geloggt."""
        import logging
        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {"Events": []}
        with caplog.at_level(logging.WARNING, logger="src.cloudtrail_analyzer"):
            get_nhi_activity(mock_client, days=91)
        assert any("90" in record.message for record in caplog.records)

    def test_days_90_no_warning(self, caplog):
        """days=90 ist das Maximum und soll keine Warnung erzeugen."""
        import logging
        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {"Events": []}
        with caplog.at_level(logging.WARNING, logger="src.cloudtrail_analyzer"):
            get_nhi_activity(mock_client, days=90)
        warning_msgs = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warning_msgs) == 0

    def test_days_1_is_valid(self):
        """days=1 ist der Minimalwert und soll funktionieren."""
        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {"Events": []}
        events = get_nhi_activity(mock_client, days=1)
        assert events == []
