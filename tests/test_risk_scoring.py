"""
Unit Tests für die Risk Scoring Engine (CVSS-inspiriertes Modell).

Formel: RISK_SCORE = round(sqrt(LIKELIHOOD × IMPACT) × 100)

Alle Tests laufen ohne AWS-Credentials.
"""

import math
import pytest
from src.risk_scoring import (
    NHIRiskResult,
    _calc_attack_vector,
    _calc_blast_radius,
    _calc_data_sensitivity,
    _calc_exposure,
    _calc_privilege_level,
    _calc_vulnerability,
    _has_condition,
    _has_cross_account_access,
    _risk_level,
    calculate_risk_score,
    score_all,
    summarize,
)


# ---------------------------------------------------------------------------
# Tests: _risk_level()
# ---------------------------------------------------------------------------

class TestRiskLevel:
    def test_critical_boundary(self):
        assert _risk_level(80) == "CRITICAL"
        assert _risk_level(100) == "CRITICAL"
        assert _risk_level(99) == "CRITICAL"

    def test_high_boundary(self):
        assert _risk_level(60) == "HIGH"
        assert _risk_level(79) == "HIGH"

    def test_medium_boundary(self):
        assert _risk_level(40) == "MEDIUM"
        assert _risk_level(59) == "MEDIUM"

    def test_low_boundary(self):
        assert _risk_level(0) == "LOW"
        assert _risk_level(39) == "LOW"

    def test_exact_thresholds(self):
        assert _risk_level(79) == "HIGH"
        assert _risk_level(80) == "CRITICAL"
        assert _risk_level(59) == "MEDIUM"
        assert _risk_level(60) == "HIGH"


# ---------------------------------------------------------------------------
# Tests: _has_condition() und _has_cross_account_access()
# ---------------------------------------------------------------------------

class TestHasCondition:
    def test_policy_with_condition_returns_true(self):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceIp": "10.0.0.0/8"}},
            }]
        }
        assert _has_condition(policy) is True

    def test_policy_without_condition_returns_false(self):
        policy = {
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole"}]
        }
        assert _has_condition(policy) is False

    def test_empty_policy_returns_false(self):
        assert _has_condition({}) is False

    def test_string_input_returns_false(self):
        assert _has_condition("not a dict") is False

    def test_json_string_with_condition(self):
        import json
        policy = json.dumps({
            "Statement": [{
                "Effect": "Allow",
                "Condition": {"StringEquals": {"aws:RequestedRegion": "eu-central-1"}},
            }]
        })
        assert _has_condition(policy) is True


class TestHasCrossAccountAccess:
    def test_external_aws_arn_returns_true(self):
        policy = {
            "Statement": [{"Principal": {"AWS": "arn:aws:iam::999999999999:root"}}]
        }
        assert _has_cross_account_access(policy) is True

    def test_service_principal_returns_false(self):
        policy = {
            "Statement": [{"Principal": {"Service": "lambda.amazonaws.com"}}]
        }
        assert _has_cross_account_access(policy) is False

    def test_wildcard_principal_returns_true(self):
        policy = {
            "Statement": [{"Principal": "*"}]
        }
        assert _has_cross_account_access(policy) is True

    def test_empty_policy_returns_false(self):
        assert _has_cross_account_access({}) is False

    def test_list_of_aws_arns(self):
        policy = {
            "Statement": [{"Principal": {"AWS": ["arn:aws:iam::123:root", "arn:aws:iam::456:root"]}}]
        }
        assert _has_cross_account_access(policy) is True


# ---------------------------------------------------------------------------
# Tests: _calc_exposure()
# ---------------------------------------------------------------------------

class TestCalcExposure:
    def test_suspicious_flag_returns_max(self):
        nhi = {"suspicious_activity_flag": True}
        val, findings, recs = _calc_exposure(nhi)
        assert val == 0.4
        assert len(findings) > 0
        assert len(recs) > 0

    def test_no_ip_condition_returns_medium(self):
        nhi = {"has_ip_condition": False}
        val, findings, recs = _calc_exposure(nhi)
        assert val == 0.2
        assert len(findings) > 0

    def test_ip_condition_returns_zero(self):
        nhi = {"has_ip_condition": True}
        val, _, _ = _calc_exposure(nhi)
        assert val == 0.0

    def test_trust_policy_condition_reduces_exposure(self):
        nhi = {
            "has_ip_condition": False,
            "assume_role_policy": {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
                }]
            },
        }
        val, _, _ = _calc_exposure(nhi)
        assert val == 0.0

    def test_suspicious_flag_overrides_ip_condition(self):
        # Suspicious flag takes priority even if IP condition is present
        nhi = {"suspicious_activity_flag": True, "has_ip_condition": True}
        val, _, _ = _calc_exposure(nhi)
        assert val == 0.4


# ---------------------------------------------------------------------------
# Tests: _calc_vulnerability()
# ---------------------------------------------------------------------------

class TestCalcVulnerability:
    def setup_method(self):
        self.thresholds = {
            "key_rotation_warning_days": 90,
            "key_rotation_critical_days": 365,
        }

    def test_role_returns_zero(self):
        nhi = {"type": "IAM_ROLE"}
        val, findings, _ = _calc_vulnerability(nhi, self.thresholds)
        assert val == 0.0
        assert findings == []

    def test_inactive_key_returns_zero(self):
        nhi = {
            "type": "IAM_USER",
            "age_days": 200,
            "access_key_1_age_days": 200,
            "access_key_1_status": "Inactive",
        }
        val, _, _ = _calc_vulnerability(nhi, self.thresholds)
        assert val == 0.0

    def test_no_key_returns_zero(self):
        nhi = {"type": "IAM_USER", "age_days": 100}
        val, _, _ = _calc_vulnerability(nhi, self.thresholds)
        assert val == 0.0

    def test_fresh_rotated_key_returns_zero(self):
        """User existiert 200 Tage, Key wurde vor 30 Tagen rotiert → 0.0."""
        nhi = {
            "type": "IAM_USER",
            "age_days": 200,
            "access_key_1_age_days": 30,   # 30 < 90 warning UND 30 < 200*0.9=180 → rotiert
            "access_key_1_status": "Active",
        }
        val, _, _ = _calc_vulnerability(nhi, self.thresholds)
        assert val == 0.0

    def test_old_key_warning_returns_01(self):
        nhi = {
            "type": "IAM_USER",
            "age_days": 180,
            "access_key_1_age_days": 95,  # >= 90 warning days
            "access_key_1_status": "Active",
        }
        val, findings, recs = _calc_vulnerability(nhi, self.thresholds)
        assert val == 0.1
        assert len(findings) > 0

    def test_old_key_critical_never_rotated_returns_03(self):
        nhi = {
            "type": "IAM_USER",
            "age_days": 500,
            "access_key_1_age_days": 500,  # >= 365 AND never rotated (500 >= 500*0.9)
            "access_key_1_status": "Active",
        }
        val, findings, recs = _calc_vulnerability(nhi, self.thresholds)
        assert val == 0.3
        assert any("rotiert" in f.lower() for f in findings)

    def test_old_key_critical_but_rotated_returns_02(self):
        nhi = {
            "type": "IAM_USER",
            "age_days": 500,
            "access_key_1_age_days": 370,  # >= 365 but rotated (370 < 500*0.9=450)
            "access_key_1_status": "Active",
        }
        val, _, _ = _calc_vulnerability(nhi, self.thresholds)
        assert val == 0.2


# ---------------------------------------------------------------------------
# Tests: _calc_attack_vector()
# ---------------------------------------------------------------------------

class TestCalcAttackVector:
    def test_no_conditions_returns_max(self):
        nhi = {"has_ip_condition": False, "has_mfa_condition": False}
        val, findings, recs = _calc_attack_vector(nhi)
        assert val == 0.2
        assert len(findings) > 0

    def test_both_conditions_returns_zero(self):
        nhi = {"has_ip_condition": True, "has_mfa_condition": True}
        val, _, _ = _calc_attack_vector(nhi)
        assert val == 0.0

    def test_only_mfa_returns_partial(self):
        nhi = {"has_ip_condition": False, "has_mfa_condition": True}
        val, findings, _ = _calc_attack_vector(nhi)
        assert val == 0.1
        assert len(findings) > 0

    def test_only_ip_returns_partial(self):
        nhi = {"has_ip_condition": True, "has_mfa_condition": False}
        val, _, _ = _calc_attack_vector(nhi)
        assert val == 0.1

    def test_trust_policy_condition_counts_as_protection(self):
        nhi = {
            "has_ip_condition": False,
            "has_mfa_condition": False,
            "assume_role_policy": {
                "Statement": [{
                    "Effect": "Allow",
                    "Condition": {"StringEquals": {"aws:SourceAccount": "123"}},
                }]
            },
        }
        val, _, _ = _calc_attack_vector(nhi)
        # Trust policy condition counts as has_ip → conditions_count = 1
        assert val == 0.1


# ---------------------------------------------------------------------------
# Tests: _calc_privilege_level()
# ---------------------------------------------------------------------------

class TestCalcPrivilegeLevel:
    def test_admin_access_returns_max(self):
        val, findings, recs = _calc_privilege_level(["AdministratorAccess"])
        assert val == 0.5
        assert any("AdministratorAccess" in f for f in findings)
        assert len(recs) > 0

    def test_iam_full_access_returns_045(self):
        val, _, _ = _calc_privilege_level(["IAMFullAccess"])
        assert val == 0.45

    def test_full_access_policy_returns_03(self):
        val, _, _ = _calc_privilege_level(["AmazonS3FullAccess"])
        assert val == 0.3

    def test_ec2_full_access_returns_03(self):
        val, _, _ = _calc_privilege_level(["AmazonEC2FullAccess"])
        assert val == 0.3

    def test_read_only_returns_low(self):
        val, _, _ = _calc_privilege_level(["AmazonS3ReadOnlyAccess"])
        assert val == 0.05

    def test_no_policies_returns_zero(self):
        val, findings, _ = _calc_privilege_level([])
        assert val == 0.0
        assert len(findings) > 0

    def test_admin_overrides_readonly(self):
        val, _, _ = _calc_privilege_level(["AmazonS3ReadOnlyAccess", "AdministratorAccess"])
        assert val == 0.5

    def test_finding_has_recommendation(self):
        _, _, recs = _calc_privilege_level(["AdministratorAccess"])
        assert len(recs) > 0
        assert any("Least Privilege" in r for r in recs)


# ---------------------------------------------------------------------------
# Tests: _calc_data_sensitivity()
# ---------------------------------------------------------------------------

class TestCalcDataSensitivity:
    def test_secrets_manager_returns_max(self):
        val, findings, _ = _calc_data_sensitivity(["SecretsManagerReadWrite"])
        assert val == 0.3
        assert len(findings) > 0

    def test_s3_returns_medium(self):
        val, _, _ = _calc_data_sensitivity(["AmazonS3FullAccess"])
        assert val == 0.2

    def test_cloudwatch_returns_low(self):
        val, _, _ = _calc_data_sensitivity(["CloudWatchLogsFullAccess"])
        assert val == 0.1

    def test_unrelated_policy_returns_zero(self):
        val, _, _ = _calc_data_sensitivity(["AmazonEC2ReadOnlyAccess"])
        assert val == 0.0

    def test_no_policies_returns_zero(self):
        val, _, _ = _calc_data_sensitivity([])
        assert val == 0.0

    def test_kms_returns_max(self):
        val, _, _ = _calc_data_sensitivity(["AWSKeyManagementServicePowerUser"])
        assert val == 0.3


# ---------------------------------------------------------------------------
# Tests: _calc_blast_radius()
# ---------------------------------------------------------------------------

class TestCalcBlastRadius:
    def test_cross_account_adds_01(self):
        nhi = {
            "assume_role_policy": {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "sts:AssumeRole",
                }]
            }
        }
        val, findings, _ = _calc_blast_radius(nhi, [])
        assert val >= 0.1
        assert any("Cross-Account" in f for f in findings)

    def test_iam_admin_adds_escalation(self):
        nhi = {}
        val, findings, recs = _calc_blast_radius(nhi, ["AdministratorAccess"])
        assert val >= 0.1
        assert any("Escalation" in f for f in findings)
        assert len(recs) > 0

    def test_cross_account_plus_iam_returns_02(self, nhi_cross_account):
        # AdministratorAccess gives IAM escalation AND cross-account
        nhi = {
            "assume_role_policy": nhi_cross_account["assume_role_policy"]
        }
        val, _, _ = _calc_blast_radius(nhi, ["AdministratorAccess"])
        assert val == 0.2

    def test_no_risk_returns_zero(self):
        nhi = {}
        val, _, _ = _calc_blast_radius(nhi, ["AmazonS3ReadOnlyAccess"])
        assert val == 0.0

    def test_service_principal_not_cross_account(self):
        nhi = {
            "assume_role_policy": {
                "Statement": [{
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }]
            }
        }
        val, findings, _ = _calc_blast_radius(nhi, [])
        cross_account_findings = [f for f in findings if "Cross-Account" in f]
        assert len(cross_account_findings) == 0

    def test_cross_account_fixture(self, nhi_cross_account, config):
        """Cross-Account-NHI: blast_radius sollte >= 0.1 sein."""
        result = calculate_risk_score(nhi_cross_account, config)
        assert result.blast_radius >= 0.1


# ---------------------------------------------------------------------------
# Tests: calculate_risk_score()
# ---------------------------------------------------------------------------

class TestCalculateRiskScore:
    def test_returns_nhi_risk_result(self, nhi_low, config):
        result = calculate_risk_score(nhi_low, config)
        assert isinstance(result, NHIRiskResult)

    def test_name_and_type_preserved(self, nhi_critical, config):
        result = calculate_risk_score(nhi_critical, config)
        assert result.name == nhi_critical["name"]
        assert result.nhi_type == nhi_critical["type"]

    def test_score_is_0_to_100(self, nhi_critical, nhi_low, config):
        for nhi in [nhi_critical, nhi_low]:
            result = calculate_risk_score(nhi, config)
            assert 0 <= result.risk_score <= 100

    def test_critical_nhi_is_critical(self, nhi_critical, config):
        result = calculate_risk_score(nhi_critical, config)
        assert result.risk_score >= 80
        assert result.risk_level == "CRITICAL"

    def test_low_nhi_is_low(self, nhi_low, config):
        result = calculate_risk_score(nhi_low, config)
        assert result.risk_score == 0
        assert result.risk_level == "LOW"

    def test_formula_is_geometric_mean(self, nhi_critical, config):
        """Verifiziert: score = round(sqrt(L × I) × 100)."""
        result = calculate_risk_score(nhi_critical, config)
        expected = round(math.sqrt(result.likelihood * result.impact) * 100)
        assert result.risk_score == expected

    def test_formula_geometric_mean_nhi_high(self, nhi_high, config):
        result = calculate_risk_score(nhi_high, config)
        expected = round(math.sqrt(result.likelihood * result.impact) * 100)
        assert result.risk_score == expected

    def test_likelihood_bounded_by_one(self, nhi_critical, config):
        result = calculate_risk_score(nhi_critical, config)
        assert 0.0 <= result.likelihood <= 1.0

    def test_impact_bounded_by_one(self, nhi_critical, config):
        result = calculate_risk_score(nhi_critical, config)
        assert 0.0 <= result.impact <= 1.0

    def test_likelihood_components_sum(self, nhi_critical, config):
        """Likelihood = clamp(exposure + vulnerability + attack_vector, 0, 1)."""
        result = calculate_risk_score(nhi_critical, config)
        component_sum = result.exposure + result.vulnerability + result.attack_vector
        assert result.likelihood == round(min(1.0, component_sum), 4)

    def test_impact_components_sum(self, nhi_critical, config):
        """Impact = clamp(privilege_level + data_sensitivity + blast_radius, 0, 1)."""
        result = calculate_risk_score(nhi_critical, config)
        component_sum = result.privilege_level + result.data_sensitivity + result.blast_radius
        assert result.impact == round(min(1.0, component_sum), 4)

    def test_zero_likelihood_yields_zero_score(self, nhi_low, config):
        """Wenn Likelihood = 0, muss Score = 0 sein (unabhängig von Impact)."""
        result = calculate_risk_score(nhi_low, config)
        assert result.likelihood == 0.0
        assert result.risk_score == 0

    def test_zero_impact_yields_zero_score(self, nhi_no_policies, config):
        """Wenn Impact = 0, muss Score = 0 sein."""
        result = calculate_risk_score(nhi_no_policies, config)
        assert result.impact == 0.0
        assert result.risk_score == 0

    def test_critical_higher_than_low(self, nhi_critical, nhi_low, config):
        r_crit = calculate_risk_score(nhi_critical, config)
        r_low = calculate_risk_score(nhi_low, config)
        assert r_crit.risk_score > r_low.risk_score

    def test_findings_present_for_critical(self, nhi_critical, config):
        result = calculate_risk_score(nhi_critical, config)
        assert len(result.findings) > 0

    def test_recommendations_present_for_critical(self, nhi_critical, config):
        result = calculate_risk_score(nhi_critical, config)
        assert len(result.recommendations) > 0

    def test_roles_have_zero_vulnerability(self, nhi_medium, config):
        """IAM Roles haben keine Access Keys → vulnerability = 0."""
        result = calculate_risk_score(nhi_medium, config)
        assert result.vulnerability == 0.0

    def test_inactive_key_yields_zero_vulnerability(self, nhi_inactive_key, config):
        """Inaktiver Access Key → vulnerability = 0."""
        result = calculate_risk_score(nhi_inactive_key, config)
        assert result.vulnerability == 0.0

    def test_no_policies_zero_privilege_level(self, nhi_no_policies, config):
        result = calculate_risk_score(nhi_no_policies, config)
        assert result.privilege_level == 0.0

    def test_cross_account_blast_radius(self, nhi_cross_account, config):
        result = calculate_risk_score(nhi_cross_account, config)
        assert result.blast_radius >= 0.1

    def test_exposure_critical_nhi(self, nhi_critical, config):
        """Suspicious-Flag → exposure = 0.4 (Maximum)."""
        result = calculate_risk_score(nhi_critical, config)
        assert result.exposure == 0.4

    def test_exposure_low_nhi(self, nhi_low, config):
        """IP + Condition → exposure = 0.0."""
        result = calculate_risk_score(nhi_low, config)
        assert result.exposure == 0.0

    def test_config_none_uses_defaults(self, nhi_critical):
        """Kein Config-Argument → Default-Config wird geladen."""
        result = calculate_risk_score(nhi_critical)
        assert isinstance(result, NHIRiskResult)
        assert result.risk_score > 0


# ---------------------------------------------------------------------------
# Tests: score_all() und summarize()
# ---------------------------------------------------------------------------

class TestScoreAll:
    def test_returns_sorted_descending(self, sample_nhi_list, config):
        results = score_all(sample_nhi_list, config)
        scores = [r.risk_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_correct_count(self, sample_nhi_list, config):
        results = score_all(sample_nhi_list, config)
        assert len(results) == len(sample_nhi_list)

    def test_empty_list(self, config):
        results = score_all([], config)
        assert results == []

    def test_all_results_are_nhi_risk_result(self, sample_nhi_list, config):
        results = score_all(sample_nhi_list, config)
        for r in results:
            assert isinstance(r, NHIRiskResult)

    def test_all_scores_valid_range(self, sample_nhi_list, config):
        results = score_all(sample_nhi_list, config)
        for r in results:
            assert 0 <= r.risk_score <= 100


class TestSummarize:
    def test_total_count(self, sample_nhi_list, config):
        results = score_all(sample_nhi_list, config)
        summary = summarize(results)
        assert summary["total"] == len(sample_nhi_list)

    def test_counts_sum_to_total(self, sample_nhi_list, config):
        results = score_all(sample_nhi_list, config)
        summary = summarize(results)
        assert (
            summary["critical_count"]
            + summary["high_count"]
            + summary["medium_count"]
            + summary["low_count"]
        ) == summary["total"]

    def test_empty_summary(self, config):
        summary = summarize([])
        assert summary["total"] == 0
        assert summary["critical_count"] == 0

    def test_summary_keys_present(self, sample_nhi_list, config):
        results = score_all(sample_nhi_list, config)
        summary = summarize(results)
        assert all(
            k in summary
            for k in ["total", "critical_count", "high_count", "medium_count", "low_count"]
        )

    def test_critical_nhi_counted(self, nhi_critical, config):
        result = calculate_risk_score(nhi_critical, config)
        summary = summarize([result])
        if result.risk_level == "CRITICAL":
            assert summary["critical_count"] == 1


# ---------------------------------------------------------------------------
# Neue Tests: Edge Cases
# ---------------------------------------------------------------------------

class TestAssumeRolePolicyEdgeCases:
    def test_assume_role_policy_empty_string_no_crash(self):
        """Leerer String als assume_role_policy darf keinen Absturz verursachen."""
        nhi = {
            "type": "IAM_ROLE",
            "name": "test-role",
            "assume_role_policy": "",
        }
        result = calculate_risk_score(nhi)
        assert isinstance(result, NHIRiskResult)

    def test_assume_role_policy_none_no_crash(self):
        """None als assume_role_policy darf keinen Absturz verursachen."""
        nhi = {
            "type": "IAM_ROLE",
            "name": "test-role",
            "assume_role_policy": None,
        }
        result = calculate_risk_score(nhi)
        assert isinstance(result, NHIRiskResult)


class TestPoliciesNoneEdgeCase:
    def test_policies_none_treated_as_empty_privilege(self):
        """policies=None führt zu privilege_level=0.0, kein Absturz."""
        nhi = {
            "type": "IAM_ROLE",
            "name": "test-role",
            "policies": None,
        }
        result = calculate_risk_score(nhi)
        assert result.privilege_level == 0.0

    def test_policies_none_zero_impact(self):
        """policies=None und keine weiteren Faktoren → impact sollte 0.0 sein."""
        nhi = {
            "type": "IAM_ROLE",
            "name": "test-role",
            "policies": None,
            "assume_role_policy": {"Statement": [{"Principal": {"Service": "lambda.amazonaws.com"}}]},
        }
        result = calculate_risk_score(nhi)
        assert result.impact == 0.0


class TestIAMFullAccessVsAdminAccessScoring:
    def test_iam_full_access_lower_than_admin_access(self):
        """IAMFullAccess (0.45) muss kleiner sein als AdministratorAccess (0.50).

        Wissenschaftlich begründet: IAMFullAccess ermöglicht Privilege Escalation
        (Scope:Changed), aber gewährt keine direkte Vollkontrolle. AdministratorAccess
        kompromittiert alle CIA-Säulen unmittelbar. (CVSS 3.1, FIRST 2019)
        """
        admin_val, _, _ = _calc_privilege_level(["AdministratorAccess"])
        iam_val, _, _ = _calc_privilege_level(["IAMFullAccess"])
        assert iam_val < admin_val

    def test_admin_access_is_exactly_050(self):
        val, _, _ = _calc_privilege_level(["AdministratorAccess"])
        assert val == 0.5

    def test_iam_full_access_is_exactly_045(self):
        val, _, _ = _calc_privilege_level(["IAMFullAccess"])
        assert val == 0.45

    def test_iam_full_access_finding_mentions_escalation(self):
        """Finding muss auf Privilege-Escalation-Risiko hinweisen."""
        _, findings, _ = _calc_privilege_level(["IAMFullAccess"])
        assert any("Eskalation" in f or "Escalation" in f or "escalation" in f.lower()
                   or "IAM" in f for f in findings)

    def test_admin_beats_iam_full_access_in_combination(self):
        """Wenn beide Policies vorhanden: AdministratorAccess gewinnt (0.50)."""
        val, _, _ = _calc_privilege_level(["IAMFullAccess", "AdministratorAccess"])
        assert val == 0.5
