"""
Unit- und Integrationstests für den IaC-Scanner (Terraform).

Alle Tests laufen lokal gegen tests/fixtures/sample.tf – keine AWS-Credentials nötig.
"""

import json
import os
import pytest

from src.iac_scanner import (
    IaCFinding,
    IaCScanResult,
    _extract_jsonencode,
    analyze_policy,
    find_hardcoded_secrets,
    generate_report,
    scan_directory,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
SAMPLE_TF = os.path.join(FIXTURES_DIR, "sample.tf")


# ---------------------------------------------------------------------------
# Tests: _extract_jsonencode()
# ---------------------------------------------------------------------------

class TestExtractJsonencode:
    def test_valid_json_inside_jsonencode(self):
        s = '${jsonencode({"Statement": [{"Effect": "Allow"}]})}'
        result = _extract_jsonencode(s)
        assert result is not None
        assert "Statement" in result
        assert result["Statement"][0]["Effect"] == "Allow"

    def test_non_jsonencode_string_returns_none(self):
        assert _extract_jsonencode("just a regular string") is None

    def test_non_string_returns_none(self):
        assert _extract_jsonencode({"key": "value"}) is None

    def test_none_returns_none(self):
        assert _extract_jsonencode(None) is None

    def test_complex_policy_extracted(self):
        policy_dict = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }
        s = f'${{jsonencode({json.dumps(policy_dict)})}}'
        result = _extract_jsonencode(s)
        assert result is not None
        assert result["Statement"][0]["Action"] == "*"


# ---------------------------------------------------------------------------
# Tests: analyze_policy() – direkte Unit-Tests
# ---------------------------------------------------------------------------

class TestAnalyzePolicy:
    def test_wildcard_action_is_critical(self):
        policy = {
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        }
        findings = analyze_policy(policy, "test_resource", "test.tf")
        assert any(f.severity == "CRITICAL" for f in findings)
        assert any("*" in f.issue for f in findings)

    def test_iam_star_action_is_critical(self):
        policy = {
            "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]
        }
        findings = analyze_policy(policy, "test_resource", "test.tf")
        assert any(f.severity == "CRITICAL" for f in findings)

    def test_sts_star_action_is_critical(self):
        policy = {
            "Statement": [{"Effect": "Allow", "Action": "sts:*", "Resource": "*"}]
        }
        findings = analyze_policy(policy, "test_resource", "test.tf")
        assert any(f.severity == "CRITICAL" for f in findings)

    def test_resource_wildcard_with_write_is_high(self):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:DeleteObject"],
                "Resource": "*",
            }]
        }
        findings = analyze_policy(policy, "test_resource", "test.tf")
        assert any(f.severity == "HIGH" for f in findings)

    def test_resource_wildcard_readonly_no_high(self):
        """Wildcard Read-Actions (Get*, List*) mit Resource: * → kein HIGH,
        weil der Scanner nur Wildcard-Patterns (e.g. s3:Get*) ausschließt."""
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:Get*", "s3:List*"],
                "Resource": "*",
            }]
        }
        findings = analyze_policy(policy, "test_resource", "test.tf")
        assert not any(f.severity == "HIGH" for f in findings)

    def test_sensitive_action_no_condition_is_medium(self):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:CreateUser", "iam:AttachUserPolicy"],
                "Resource": "arn:aws:iam::123456789012:user/*",
            }]
        }
        findings = analyze_policy(policy, "test_resource", "test.tf")
        assert any(f.severity == "MEDIUM" for f in findings)

    def test_sensitive_action_with_condition_no_medium(self):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:CreateUser"],
                "Resource": "arn:aws:iam::123456789012:user/*",
                "Condition": {"StringEquals": {"aws:SourceIp": "10.0.0.0/8"}},
            }]
        }
        findings = analyze_policy(policy, "test_resource", "test.tf")
        assert not any(f.severity == "MEDIUM" for f in findings)

    def test_deny_statements_are_ignored(self):
        policy = {
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
        }
        findings = analyze_policy(policy, "test_resource", "test.tf")
        assert len(findings) == 0

    def test_empty_statement_no_findings(self):
        policy = {"Statement": []}
        findings = analyze_policy(policy, "test_resource", "test.tf")
        assert len(findings) == 0

    def test_json_string_input_parsed(self):
        policy_str = json.dumps({
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        })
        findings = analyze_policy(policy_str, "test_resource", "test.tf")
        assert any(f.severity == "CRITICAL" for f in findings)

    def test_list_input_processed(self):
        policy_list = [
            {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        ]
        findings = analyze_policy(policy_list, "test_resource", "test.tf")
        assert any(f.severity == "CRITICAL" for f in findings)

    def test_finding_fields_are_populated(self):
        policy = {
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        }
        findings = analyze_policy(policy, "my_resource", "my.tf")
        for f in findings:
            assert f.recommendation != ""
            assert f.file == "my.tf"
            assert f.resource == "my_resource"
            assert f.issue != ""

    def test_secretsmanager_action_no_condition_is_medium(self):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": ["secretsmanager:GetSecretValue"],
                "Resource": "arn:aws:secretsmanager:*:*:secret:*",
            }]
        }
        findings = analyze_policy(policy, "test_resource", "test.tf")
        assert any(f.severity == "MEDIUM" for f in findings)


# ---------------------------------------------------------------------------
# Tests: find_hardcoded_secrets()
# ---------------------------------------------------------------------------

class TestFindHardcodedSecrets:
    def test_detect_aws_access_key(self):
        content = 'legacy_access_key = "AKIAIOSFODNN7EXAMPLE"'
        findings = find_hardcoded_secrets(content, "test.tf")
        assert any(f.severity == "CRITICAL" for f in findings)
        # Die ersten 8 Zeichen von AKIAIOSFODNN7EXAMPLE = AKIAIOFS
        assert any("AKIA" in f.issue for f in findings)

    def test_detect_password_literal(self):
        content = 'password = "my-super-secret-password123"'
        findings = find_hardcoded_secrets(content, "test.tf")
        assert any(f.severity == "HIGH" for f in findings)

    def test_detect_secret_literal(self):
        content = 'secret = "SuperSecretValue!"'
        findings = find_hardcoded_secrets(content, "test.tf")
        assert any(f.severity == "HIGH" for f in findings)

    def test_detect_api_key_literal(self):
        content = 'api_key = "abcdef1234567890xyz"'
        findings = find_hardcoded_secrets(content, "test.tf")
        assert any(f.severity == "HIGH" for f in findings)

    def test_var_reference_not_flagged(self):
        content = 'password = "${var.db_password}"'
        findings = find_hardcoded_secrets(content, "test.tf")
        assert len(findings) == 0

    def test_placeholder_not_flagged(self):
        content = 'password = "CHANGE_ME"'
        findings = find_hardcoded_secrets(content, "test.tf")
        assert len(findings) == 0

    def test_todo_placeholder_not_flagged(self):
        content = 'password = "TODO"'
        findings = find_hardcoded_secrets(content, "test.tf")
        assert len(findings) == 0

    def test_clean_content_no_findings(self):
        content = 'name = "my-role"\ndescription = "An IAM role"'
        findings = find_hardcoded_secrets(content, "test.tf")
        assert len(findings) == 0

    def test_finding_has_line_number(self):
        content = 'first_line = "nothing"\nsecond_line = "AKIAIOSFODNN7EXAMPLE"'
        findings = find_hardcoded_secrets(content, "test.tf")
        critical = [f for f in findings if f.severity == "CRITICAL"]
        assert len(critical) > 0
        assert critical[0].line == 2

    def test_multiple_secrets_detected(self):
        content = (
            'key1 = "AKIAIOSFODNN7EXAMPLE"\n'
            'password = "literalpassword"\n'
        )
        findings = find_hardcoded_secrets(content, "test.tf")
        assert len(findings) >= 2

    def test_file_path_in_findings(self):
        content = 'legacy_access_key = "AKIAIOSFODNN7EXAMPLE"'
        findings = find_hardcoded_secrets(content, "/path/to/main.tf")
        assert all(f.file == "/path/to/main.tf" for f in findings)


# ---------------------------------------------------------------------------
# Tests: scan_directory() – Integration mit sample.tf
# ---------------------------------------------------------------------------

class TestScanDirectory:
    def test_scan_correct_file_count(self):
        result = scan_directory(SAMPLE_TF)
        assert result.files_scanned == 1

    def test_scan_finds_iam_resources(self):
        result = scan_directory(SAMPLE_TF)
        # sample.tf hat mehrere IAM-Ressourcen (aws_iam_policy, aws_iam_role, aws_iam_user, aws_iam_access_key)
        assert result.total_resources >= 3

    def test_scan_finds_hardcoded_access_key(self):
        result = scan_directory(SAMPLE_TF)
        critical = [f for f in result.findings if f.severity == "CRITICAL"]
        assert any("AKIA" in f.issue for f in critical), (
            f"Kein CRITICAL-Fund mit AKIA. Gefundene CRITICAL-Findings: {[f.issue for f in critical]}"
        )

    def test_scan_finds_hardcoded_password(self):
        result = scan_directory(SAMPLE_TF)
        high = [f for f in result.findings if f.severity == "HIGH"]
        assert any("password" in f.issue.lower() for f in high), (
            f"Kein HIGH-Fund für Passwort. HIGH-Findings: {[f.issue for f in high]}"
        )

    def test_scan_flags_aws_iam_access_key_resource(self):
        result = scan_directory(SAMPLE_TF)
        high = [f for f in result.findings if f.severity == "HIGH"]
        assert any("aws_iam_access_key" in f.issue for f in high), (
            f"aws_iam_access_key Ressource nicht als HIGH erkannt. HIGH-Findings: {[f.issue for f in high]}"
        )

    def test_scan_nonexistent_path_returns_empty(self):
        result = scan_directory("/nonexistent/path/to/terraform")
        assert result.files_scanned == 0
        assert len(result.findings) == 0

    def test_scan_counts_match_findings(self):
        result = scan_directory(SAMPLE_TF)
        assert result.critical_count == sum(1 for f in result.findings if f.severity == "CRITICAL")
        assert result.high_count == sum(1 for f in result.findings if f.severity == "HIGH")
        assert result.medium_count == sum(1 for f in result.findings if f.severity == "MEDIUM")

    def test_scan_returns_iac_scan_result(self):
        result = scan_directory(SAMPLE_TF)
        assert isinstance(result, IaCScanResult)


class TestGenerateReport:
    def test_report_sorted_by_severity(self):
        """Findings müssen nach Severity sortiert sein: CRITICAL vor HIGH vor MEDIUM."""
        result = generate_report(SAMPLE_TF)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
        severities = [
            severity_order[f.severity]
            for f in result.findings
            if f.severity in severity_order
        ]
        assert severities == sorted(severities), (
            f"Findings nicht nach Severity sortiert: {[f.severity for f in result.findings]}"
        )

    def test_report_same_findings_as_scan(self):
        """generate_report und scan_directory finden dieselben Findings."""
        scan_result = scan_directory(SAMPLE_TF)
        report_result = generate_report(SAMPLE_TF)
        assert len(scan_result.findings) == len(report_result.findings)


# ---------------------------------------------------------------------------
# Tests: Datenstrukturen
# ---------------------------------------------------------------------------

class TestIaCFinding:
    def test_finding_optional_line_default_none(self):
        f = IaCFinding(
            severity="CRITICAL",
            resource="aws_iam_policy.test",
            issue="Wildcard action",
            recommendation="Restrict actions",
            file="test.tf",
        )
        assert f.line is None

    def test_finding_with_line_number(self):
        f = IaCFinding(
            severity="HIGH",
            resource="aws_iam_policy.test",
            issue="Password found",
            recommendation="Use secrets manager",
            file="test.tf",
            line=42,
        )
        assert f.line == 42

    def test_finding_all_severity_levels(self):
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
            f = IaCFinding(severity=severity, resource="r", issue="i", recommendation="r", file="f")
            assert f.severity == severity


class TestIaCScanResult:
    def test_result_counts_auto_calculated(self):
        findings = [
            IaCFinding("CRITICAL", "r1", "i1", "rec", "f.tf"),
            IaCFinding("CRITICAL", "r2", "i2", "rec", "f.tf"),
            IaCFinding("HIGH", "r3", "i3", "rec", "f.tf"),
            IaCFinding("MEDIUM", "r4", "i4", "rec", "f.tf"),
        ]
        result = IaCScanResult(findings=findings, total_resources=5, files_scanned=1)
        assert result.critical_count == 2
        assert result.high_count == 1
        assert result.medium_count == 1

    def test_empty_result(self):
        result = IaCScanResult()
        assert result.total_resources == 0
        assert result.files_scanned == 0
        assert result.critical_count == 0
        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Neue Tests: SARIF-Export
# ---------------------------------------------------------------------------

from src.iac_scanner import to_sarif


class TestToSarifStructure:
    def _make_result(self, findings: list) -> IaCScanResult:
        r = IaCScanResult(findings=findings, files_scanned=1, total_resources=2)
        r._update_counts()
        return r

    def test_to_sarif_produces_valid_top_level_keys(self):
        """SARIF-Ausgabe muss $schema, version und runs enthalten."""
        result = self._make_result([
            IaCFinding("HIGH", "aws_iam_role.test", "Wildcard Resource", "Restrict it", "main.tf"),
        ])
        sarif = to_sarif(result)
        assert "$schema" in sarif
        assert "version" in sarif
        assert "runs" in sarif

    def test_to_sarif_version_is_210(self):
        result = self._make_result([
            IaCFinding("MEDIUM", "aws_iam_policy.p", "No condition", "Add condition", "main.tf"),
        ])
        sarif = to_sarif(result)
        assert sarif["version"] == "2.1.0"

    def test_to_sarif_schema_url_present(self):
        result = self._make_result([
            IaCFinding("HIGH", "r", "issue", "rec", "f.tf"),
        ])
        sarif = to_sarif(result)
        assert "sarif" in sarif["$schema"].lower() or "schemastore" in sarif["$schema"]

    def test_to_sarif_runs_has_one_entry(self):
        result = self._make_result([
            IaCFinding("HIGH", "r", "issue", "rec", "f.tf"),
        ])
        sarif = to_sarif(result)
        assert len(sarif["runs"]) == 1

    def test_to_sarif_tool_driver_present(self):
        result = self._make_result([
            IaCFinding("HIGH", "r", "issue", "rec", "f.tf"),
        ])
        sarif = to_sarif(result)
        driver = sarif["runs"][0]["tool"]["driver"]
        assert "name" in driver
        assert driver["name"] == "nhi-discovery"

    def test_to_sarif_results_count_matches_findings(self):
        findings = [
            IaCFinding("CRITICAL", "r1", "issue1", "rec1", "a.tf"),
            IaCFinding("HIGH", "r2", "issue2", "rec2", "b.tf"),
            IaCFinding("MEDIUM", "r3", "issue3", "rec3", "c.tf"),
        ]
        result = self._make_result(findings)
        sarif = to_sarif(result)
        assert len(sarif["runs"][0]["results"]) == 3

    def test_to_sarif_empty_findings_produces_empty_results(self):
        result = self._make_result([])
        sarif = to_sarif(result)
        assert sarif["runs"][0]["results"] == []

    def test_to_sarif_result_has_location(self):
        result = self._make_result([
            IaCFinding("HIGH", "aws_iam_role.x", "issue", "rec", "/path/to/main.tf", line=10),
        ])
        sarif = to_sarif(result)
        sarif_result = sarif["runs"][0]["results"][0]
        assert "locations" in sarif_result
        assert len(sarif_result["locations"]) > 0

    def test_to_sarif_is_json_serializable(self):
        """SARIF-Output muss vollständig JSON-serialisierbar sein."""
        result = self._make_result([
            IaCFinding("CRITICAL", "r", "issue", "rec", "f.tf", line=5),
        ])
        sarif = to_sarif(result)
        serialized = json.dumps(sarif)
        parsed = json.loads(serialized)
        assert parsed["version"] == "2.1.0"


class TestToSarifSeverityMapping:
    def _make_result_with_severity(self, severity: str) -> IaCScanResult:
        r = IaCScanResult(
            findings=[IaCFinding(severity, "res", "issue", "rec", "f.tf")],
            files_scanned=1,
        )
        r._update_counts()
        return r

    def test_critical_maps_to_error(self):
        sarif = to_sarif(self._make_result_with_severity("CRITICAL"))
        level = sarif["runs"][0]["results"][0]["level"]
        assert level == "error"

    def test_high_maps_to_error(self):
        sarif = to_sarif(self._make_result_with_severity("HIGH"))
        level = sarif["runs"][0]["results"][0]["level"]
        assert level == "error"

    def test_medium_maps_to_warning(self):
        sarif = to_sarif(self._make_result_with_severity("MEDIUM"))
        level = sarif["runs"][0]["results"][0]["level"]
        assert level == "warning"

    def test_info_maps_to_note(self):
        sarif = to_sarif(self._make_result_with_severity("INFO"))
        level = sarif["runs"][0]["results"][0]["level"]
        assert level == "note"

    def test_rule_level_matches_result_level(self):
        """Der Level in der Rule muss mit dem Level im Result übereinstimmen."""
        sarif = to_sarif(self._make_result_with_severity("MEDIUM"))
        result_level = sarif["runs"][0]["results"][0]["level"]
        rule_id = sarif["runs"][0]["results"][0]["ruleId"]
        rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        rule_level = rules[rule_id]["defaultConfiguration"]["level"]
        assert result_level == rule_level
