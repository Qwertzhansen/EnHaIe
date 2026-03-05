"""
NHI Risk Scoring Engine – CVSS-inspiriertes Modell

Formel:  RISK_SCORE = round(sqrt(LIKELIHOOD × IMPACT) × 100)

LIKELIHOOD (0.0 – 1.0):  Wie wahrscheinlich ist eine erfolgreiche Kompromittierung?
  ├── Exposure     (0.0–0.4)  Ist das NHI extern erreichbar oder exponiert?
  ├── Vulnerability (0.0–0.3) Wie anfällig ist das Credential (Alter/Rotation)?
  └── Attack Vector (0.0–0.2) Welche Schutzmechanismen fehlen (MFA, Conditions)?

IMPACT (0.0 – 1.0):  Welcher Schaden entsteht bei erfolgreicher Kompromittierung?
  ├── Privilege Level  (0.0–0.5) Wie weitreichend sind die Berechtigungen?
  ├── Data Sensitivity (0.0–0.3) Auf welche sensiblen Daten hat das NHI Zugriff?
  └── Blast Radius     (0.0–0.2) Kann Schaden lateral ausgeweitet werden?

Risk Levels:
  CRITICAL  ≥ 80   sqrt(L×I) ≥ 0.80  →  L×I ≥ 0.64
  HIGH      ≥ 60   sqrt(L×I) ≥ 0.60  →  L×I ≥ 0.36
  MEDIUM    ≥ 40   sqrt(L×I) ≥ 0.40  →  L×I ≥ 0.16
  LOW        < 40

Wissenschaftliche Basis: Anlehnung an CVSS 3.1 (FIRST, 2019).
Begründung der Formel: Das geometrische Mittel (sqrt(L×I)) stellt sicher,
dass beide Dimensionen gleichzeitig erhöht sein müssen für einen hohen Score –
konsistent mit dem CVSS-Prinzip, dass Exploitability UND Impact relevant sind.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
from dataclasses import dataclass, field
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Policy-Klassifizierung
# ---------------------------------------------------------------------------

# Policies mit vollständiger administrativer Kontrolle (alle AWS-Aktionen)
FULL_ADMIN_POLICIES = frozenset({
    "AdministratorAccess",
})

# Policies die Privilege-Escalation ermöglichen (IAM-Vollzugriff ohne direkte Admin-Rechte)
IAM_FULL_ACCESS_POLICIES = frozenset({
    "IAMFullAccess",
})

# Vereinigung beider Sets für Backward-Kompatibilität (z.B. Blast-Radius-Prüfung)
ADMIN_POLICIES = FULL_ADMIN_POLICIES | IAM_FULL_ACCESS_POLICIES

# Policies mit weitreichenden Rechten (Power-User-Niveau)
POWER_POLICIES = frozenset({
    "PowerUserAccess",
    "AWSOrganizationsFullAccess",
})

# Policies mit vollständigem Zugriff auf einen Service (*FullAccess)
FULL_ACCESS_PATTERN = re.compile(r".*FullAccess$", re.IGNORECASE)

# Policies mit Zugriff auf besonders sensible Dienste
SECRETS_POLICIES = frozenset({
    "SecretsManagerReadWrite",
    "AmazonRDSFullAccess",
    "AmazonRDSReadOnlyAccess",
    "AWSKeyManagementServicePowerUser",
})

SECRETS_POLICY_PATTERN = re.compile(
    r"(SecretsManager|KMSFull|KeyManagement|RDS|DatabaseAdministrator)",
    re.IGNORECASE,
)

S3_POLICY_PATTERN = re.compile(r"S3", re.IGNORECASE)

LOG_POLICY_PATTERN = re.compile(
    r"(CloudWatch|CloudTrail|Logging|Logs)",
    re.IGNORECASE,
)

# APIs die auf IAM-Eskalation hindeuten
IAM_ESCALATION_APIS = frozenset({
    "iam:CreateUser",
    "iam:CreateRole",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "iam:AddUserToGroup",
    "iam:CreateAccessKey",
})


# ---------------------------------------------------------------------------
# Standard-Konfiguration
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG: dict = {
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


def _load_config(config_path: Optional[str] = None) -> dict:
    """Lädt Konfiguration aus config.yaml, fällt auf Defaults zurück."""
    if config_path is None:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base, "config.yaml")

    if os.path.exists(config_path):
        with open(config_path, "r") as fh:
            loaded = yaml.safe_load(fh) or {}
        return _deep_merge(_DEFAULT_CONFIG, loaded)

    return _DEFAULT_CONFIG


def _deep_merge(base: dict, override: dict) -> dict:
    """Führt zwei Dictionaries rekursiv zusammen."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# ---------------------------------------------------------------------------
# Ergebnisdatenstruktur
# ---------------------------------------------------------------------------

@dataclass
class NHIRiskResult:
    """
    Vollständiges Risikobewertungsergebnis für ein NHI.

    Der Score ergibt sich aus: round(sqrt(likelihood × impact) × 100)

    Attribute:
        name:              Bezeichner des NHI (IAM-Name)
        nhi_type:          IAM_USER oder IAM_ROLE
        risk_score:        Gesamtscore 0–100
        risk_level:        LOW / MEDIUM / HIGH / CRITICAL
        likelihood:        Wahrscheinlichkeits-Dimension (0.0–1.0)
        exposure:          Exponiertheitsgrad (0.0–0.4)
        vulnerability:     Credential-Verwundbarkeit (0.0–0.3)
        attack_vector:     Fehlende Schutzmechanismen (0.0–0.2)
        impact:            Auswirkungs-Dimension (0.0–1.0)
        privilege_level:   Berechtigungsumfang (0.0–0.5)
        data_sensitivity:  Datensensitivität (0.0–0.3)
        blast_radius:      Lateraler Schadensradius (0.0–0.2)
        findings:          Menschenlesbare Befunde
        recommendations:   Priorisierte Handlungsempfehlungen
        age_days:          Alter des NHI in Tagen
        days_since_last_used: Inaktivitätsdauer (None = nie benutzt)
        policies:          Zugewiesene IAM-Policies
        access_key_age_days: Alter des ältesten aktiven Access Keys
    """

    name: str
    nhi_type: str
    risk_score: int
    risk_level: str

    # LIKELIHOOD-Komponenten
    likelihood: float = 0.0
    exposure: float = 0.0
    vulnerability: float = 0.0
    attack_vector: float = 0.0

    # IMPACT-Komponenten
    impact: float = 0.0
    privilege_level: float = 0.0
    data_sensitivity: float = 0.0
    blast_radius: float = 0.0

    # Befunde und Empfehlungen
    findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    # Rohdaten (für Drilldown und Export)
    age_days: Optional[int] = None
    days_since_last_used: Optional[int] = None
    policies: list[str] = field(default_factory=list)
    access_key_age_days: Optional[int] = None

    # Backward-Kompatibilität mit altem Modell (Datenbank, Dashboard)
    score_age: int = 0
    score_unused: int = 0
    score_permissions: int = 0
    score_key_rotation: int = 0


# ---------------------------------------------------------------------------
# LIKELIHOOD: Exposure
# ---------------------------------------------------------------------------

def _calc_exposure(nhi: dict) -> tuple[float, list[str], list[str]]:
    """
    Berechnet den Exposure-Wert (0.0–0.4).

    Exposure beschreibt, wie stark ein NHI für Angreifer erreichbar ist.
    Methodisch angelehnt an den CVSS-Parameter 'Attack Complexity':
    Je weniger Einschränkungen, desto höher die Exposition.

    Stufen:
      +0.4  Bekannt exponiert: CloudTrail zeigt Zugriff von verdächtiger IP
      +0.2  Potenziell exponiert: Keine IP-Restriction-Conditions
      +0.0  Gut abgesichert: IP-Restrictions vorhanden
    """
    findings: list[str] = []
    recs: list[str] = []

    # CloudTrail: bekannte Exposition (gesetzt von cloudtrail_analyzer.py)
    if nhi.get("suspicious_activity_flag"):
        findings.append("Bekannte Exposition: Verdächtige CloudTrail-Aktivität erkannt")
        recs.append("[KRITISCH] Credentials sofort sperren und rotieren")
        return 0.4, findings, recs

    # Prüfe ob IP-Conditions in der Policy vorhanden sind
    has_ip_condition = nhi.get("has_ip_condition", False)
    assume_role_doc = nhi.get("assume_role_policy", {})

    if not has_ip_condition and not _has_condition(assume_role_doc):
        findings.append("Potenziell exponiert: Keine IP-Restrictions konfiguriert")
        recs.append("[MITTEL] aws:SourceIp-Condition in Policies hinzufügen")
        return 0.2, findings, recs

    return 0.0, findings, recs


def _has_condition(policy_doc: dict | str) -> bool:
    """Prüft ob ein Policy-Dokument Conditions enthält."""
    if isinstance(policy_doc, str):
        try:
            policy_doc = json.loads(policy_doc)
        except (json.JSONDecodeError, TypeError):
            return False

    if not isinstance(policy_doc, dict):
        return False

    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    return any(
        bool(stmt.get("Condition"))
        for stmt in statements
        if isinstance(stmt, dict)
    )


# ---------------------------------------------------------------------------
# LIKELIHOOD: Vulnerability
# ---------------------------------------------------------------------------

def _calc_vulnerability(nhi: dict, thresholds: dict) -> tuple[float, list[str], list[str]]:
    """
    Berechnet den Vulnerability-Wert (0.0–0.3).

    Vulnerability misst die Anfälligkeit des Credentials selbst.
    Angelehnt an CVSS 'Scope' und 'User Interaction': Ein nie rotiertes,
    altes Credential ist dauerhaft exponiert ohne Angreifer-Interaktion.

    Stufen:
      +0.3  Key nie rotiert UND älter als key_rotation_critical_days
      +0.2  Key nie rotiert ODER älter als key_rotation_critical_days
      +0.1  Key älter als key_rotation_warning_days
      +0.0  Key frisch oder Rolle ohne Credentials
    """
    findings: list[str] = []
    recs: list[str] = []

    if nhi.get("type") != "IAM_USER":
        # IAM Roles haben keine Access Keys → Vulnerability = 0
        return 0.0, findings, recs

    warn_days = thresholds.get("key_rotation_warning_days", 90)
    crit_days = thresholds.get("key_rotation_critical_days", 365)

    # Ältesten aktiven Key bestimmen
    key_age: Optional[int] = None
    for i in range(1, 5):
        age = nhi.get(f"access_key_{i}_age_days")
        status = nhi.get(f"access_key_{i}_status", "Inactive")
        if age is not None and status == "Active":
            if key_age is None or age > key_age:
                key_age = age

    if key_age is None:
        return 0.0, findings, recs  # Kein aktiver Key

    # Wurde der Key jemals rotiert? Proxy: Key-Alter ≈ User-Alter
    user_age = nhi.get("age_days") or 0
    never_rotated = key_age >= (user_age * 0.9)  # Toleranzbereich 10%

    if key_age >= crit_days and never_rotated:
        findings.append(
            f"Credential nie rotiert und {key_age} Tage alt "
            f"(kritisch ab {crit_days} Tage)"
        )
        recs.append("[KRITISCH] Access Key sofort rotieren")
        return 0.3, findings, recs

    if key_age >= crit_days or never_rotated:
        findings.append(
            f"Credential-Hygiene mangelhaft: Key {key_age} Tage alt "
            f"{'(nie rotiert)' if never_rotated else ''}"
        )
        recs.append("[HOCH] Access Key Rotation einplanen")
        return 0.2, findings, recs

    if key_age >= warn_days:
        findings.append(f"Access Key ist {key_age} Tage alt (Warnung ab {warn_days})")
        recs.append("[MITTEL] Key-Rotation prüfen")
        return 0.1, findings, recs

    return 0.0, findings, recs


# ---------------------------------------------------------------------------
# LIKELIHOOD: Attack Vector
# ---------------------------------------------------------------------------

def _calc_attack_vector(nhi: dict) -> tuple[float, list[str], list[str]]:
    """
    Berechnet den Attack-Vector-Wert (0.0–0.2).

    Attack Vector beschreibt, welche technischen Schutzmechanismen fehlen.
    Entspricht dem CVSS-Parameter 'Privileges Required': Je weniger
    Voraussetzungen ein Angreifer erfüllen muss, desto höher der Wert.

    Stufen:
      +0.2  Keine Nutzungsbedingungen: Weder MFA noch IP-Conditions
      +0.1  Teilweise eingeschränkt: Nur eine der Bedingungen
      +0.0  Gut abgesichert: MFA UND IP-Restrictions vorhanden
    """
    findings: list[str] = []
    recs: list[str] = []

    has_ip = nhi.get("has_ip_condition", False)
    has_mfa = nhi.get("has_mfa_condition", False)

    # Auch Trust-Policy für Roles prüfen
    assume_doc = nhi.get("assume_role_policy", {})
    if _has_condition(assume_doc):
        has_ip = True  # Vereinfachung: jede Condition in Trust Policy ist ein Schutz

    conditions_count = int(has_ip) + int(has_mfa)

    if conditions_count == 0:
        findings.append("Keine Authentifizierungsbedingungen: Weder MFA noch IP-Restriction")
        recs.append("[MITTEL] MFA-Requirement und/oder IP-Restriction in Policies ergänzen")
        return 0.2, findings, recs

    if conditions_count == 1:
        missing = "MFA" if not has_mfa else "IP-Restriction"
        findings.append(f"Nur teilweise abgesichert: {missing} fehlt")
        recs.append(f"[NIEDRIG] {missing} als zusätzliche Condition hinzufügen")
        return 0.1, findings, recs

    return 0.0, findings, recs


# ---------------------------------------------------------------------------
# IMPACT: Privilege Level
# ---------------------------------------------------------------------------

def _calc_privilege_level(policies: list[str]) -> tuple[float, list[str], list[str]]:
    """
    Berechnet das Privilege-Level (0.0–0.5).

    Privilege Level misst den maximalen Schaden durch direkte Aktionen
    des kompromittierten NHI. Angelehnt an CVSS 'Confidentiality',
    'Integrity' und 'Availability Impact': AdministratorAccess erlaubt
    vollständige Kompromittierung aller drei CIA-Säulen.

    Stufen:
      +0.50 AdministratorAccess (vollständige AWS-Kontrolle – CIA-Triade komplett)
      +0.45 IAMFullAccess (Privilege Escalation möglich, keine direkte Admin-Kontrolle)
      +0.30 PowerUserAccess oder *FullAccess (hohe Service-Kontrolle)
      +0.20 Schreibrechte ohne Full Access
      +0.05 Nur Leserechte
      +0.00 Keine Policies

    Wissenschaftliche Begründung: AdministratorAccess erlaubt direkte Vollkontrolle
    über alle CIA-Säulen. IAMFullAccess ermöglicht Privilege Escalation (Anlegen neuer
    Admins), aber keine unmittelbare vollständige Kontrolle → minimal geringerer Score.
    Angelehnt an CVSS 3.1 Scope:Changed-Konzept (FIRST, 2019).
    """
    findings: list[str] = []
    recs: list[str] = []

    if not policies:
        return 0.0, ["Keine direkt zugewiesenen Policies"], []

    # Höchste Kategorie gewinnt (kein Addieren)
    full_admin = [p for p in policies if p in FULL_ADMIN_POLICIES]
    if full_admin:
        findings.append(
            f"Volle administrative Kontrolle: {', '.join(full_admin)}"
        )
        recs.append(
            f"[KRITISCH] {', '.join(full_admin)} entfernen – "
            "Principle of Least Privilege anwenden"
        )
        logger.debug("Privilege FULL_ADMIN (0.50) für Policies: %s", full_admin)
        return 0.5, findings, recs

    iam_full = [p for p in policies if p in IAM_FULL_ACCESS_POLICIES]
    if iam_full:
        findings.append(
            f"IAM-Vollzugriff: {', '.join(iam_full)} – Privilege Escalation möglich"
        )
        recs.append(
            f"[KRITISCH] {', '.join(iam_full)} entfernen – "
            "IAM-Vollzugriff ermöglicht Eskalation zu AdministratorAccess"
        )
        logger.debug("Privilege IAM_FULL_ACCESS (0.45) für Policies: %s", iam_full)
        return 0.45, findings, recs

    power = [p for p in policies if p in POWER_POLICIES]
    full_access = [p for p in policies if FULL_ACCESS_PATTERN.match(p)]
    if power or full_access:
        relevant = power + full_access
        findings.append(f"Weitreichende Vollzugriff-Policies: {', '.join(relevant[:3])}")
        recs.append("[HOCH] Policies auf tatsächlich benötigte Aktionen einschränken")
        return 0.3, findings, recs

    # Schreibrechte erkennen: Policies mit "Write", "ReadWrite", "Power"
    write_pattern = re.compile(r"(Write|ReadWrite|Power|Manage|Describe.*Create)", re.IGNORECASE)
    write_policies = [p for p in policies if write_pattern.search(p)]
    if write_policies:
        findings.append(f"Schreibrechte: {', '.join(write_policies[:3])}")
        recs.append("[MITTEL] Schreibrechte auf Minimum reduzieren")
        return 0.2, findings, recs

    # Leserechte
    findings.append(f"Leserechte: {', '.join(policies[:3])}")
    return 0.05, findings, recs


# ---------------------------------------------------------------------------
# IMPACT: Data Sensitivity
# ---------------------------------------------------------------------------

def _calc_data_sensitivity(policies: list[str]) -> tuple[float, list[str], list[str]]:
    """
    Berechnet die Datensensitivität (0.0–0.3).

    Data Sensitivity bewertet, auf welche Datenkategorien ein kompromittiertes
    NHI Zugriff hat. Basiert auf dem Datenschutzniveau verschiedener AWS-Services:
    Secrets Manager/KMS enthält Schlüsselmaterial (höchste Sensitivität),
    S3 kann regulierte Daten enthalten, CloudWatch enthält Betriebslogs.

    Stufen:
      +0.3  Secrets Manager, KMS oder RDS (Schlüssel/Passwörter/Kundendaten)
      +0.2  S3-Zugriff (potenziell PII/regulierte Daten)
      +0.1  CloudWatch/CloudTrail (Logs mit sensitiven Infos)
      +0.0  Keine bekannten sensitiven Dienste
    """
    findings: list[str] = []
    recs: list[str] = []

    if not policies:
        return 0.0, findings, recs

    secrets = [p for p in policies if SECRETS_POLICY_PATTERN.search(p)]
    if secrets:
        findings.append(f"Zugriff auf Schlüssel/Credentials: {', '.join(secrets[:2])}")
        recs.append("[HOCH] Secrets-Zugriff auf Minimum einschränken")
        return 0.3, findings, recs

    s3 = [p for p in policies if S3_POLICY_PATTERN.search(p)]
    if s3:
        findings.append(f"S3-Zugriff (möglicherweise PII): {', '.join(s3[:2])}")
        recs.append("[MITTEL] S3-Bucket-Policy und Datenkategorien prüfen")
        return 0.2, findings, recs

    logs = [p for p in policies if LOG_POLICY_PATTERN.search(p)]
    if logs:
        findings.append(f"Zugriff auf Logs/Monitoring: {', '.join(logs[:2])}")
        return 0.1, findings, recs

    return 0.0, findings, recs


# ---------------------------------------------------------------------------
# IMPACT: Blast Radius
# ---------------------------------------------------------------------------

def _calc_blast_radius(nhi: dict, policies: list[str]) -> tuple[float, list[str], list[str]]:
    """
    Berechnet den Blast Radius (0.0–0.2).

    Blast Radius misst die laterale Ausbreitungsmöglichkeit nach einer
    Kompromittierung. Angelehnt an CVSS 'Scope': Eine Identität mit
    Scope:Changed kann den Angriff über ihre eigene Sicherheitsdomäne
    hinaus ausweiten.

    Stufen (kumulativ):
      +0.1  Cross-Account-Zugriff möglich (Trust Policy erlaubt externe Accounts)
      +0.1  IAM-Eskalation möglich (Kann neue Identitäten/Policies erstellen)
    """
    findings: list[str] = []
    recs: list[str] = []
    score = 0.0

    # Cross-Account: Prüfe Trust Policy auf externe Principals
    assume_doc = nhi.get("assume_role_policy", {})
    if _has_cross_account_access(assume_doc):
        score += 0.1
        findings.append("Cross-Account-Zugriff möglich (externes Principal in Trust Policy)")
        recs.append("[HOCH] Trust Policy auf notwendige Accounts/Services einschränken")

    # IAM-Eskalation: Prüfe auf IAM-Management-Policies
    iam_write = [p for p in policies if p in ADMIN_POLICIES or "IAM" in p]
    if iam_write:
        score += 0.1
        findings.append(
            f"Privilege Escalation möglich: {', '.join(iam_write[:2])} erlaubt IAM-Änderungen"
        )
        recs.append("[KRITISCH] IAM-Schreibrechte entfernen um Escalation zu verhindern")

    return min(0.2, score), findings, recs


def _has_cross_account_access(policy_doc: dict | str) -> bool:
    """
    Prüft ob eine Trust Policy externen (Cross-Account) Zugriff erlaubt.
    Gibt False zurück wenn Dokument fehlt oder nur AWS-Services als Principal.
    """
    if isinstance(policy_doc, str):
        try:
            policy_doc = json.loads(policy_doc)
        except (json.JSONDecodeError, TypeError):
            return False

    if not isinstance(policy_doc, dict):
        return False

    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        principal = stmt.get("Principal", {})
        # AWS-Service-Principals (lambda.amazonaws.com etc.) = kein Cross-Account
        if isinstance(principal, str) and principal == "*":
            return True
        if isinstance(principal, dict):
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for p in aws_principals:
                # Echter Account-ARN oder Wildcard = Cross-Account
                if isinstance(p, str) and ("arn:aws:iam::" in p or p == "*"):
                    return True
    return False


# ---------------------------------------------------------------------------
# Haupt-API
# ---------------------------------------------------------------------------

def _risk_level(score: int) -> str:
    """Wandelt numerischen Score in Risk Level um."""
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def calculate_risk_score(
    nhi: dict,
    config: Optional[dict] = None,
) -> NHIRiskResult:
    """
    Berechnet den Risk Score für ein einzelnes NHI.

    Formel: RISK_SCORE = round(sqrt(LIKELIHOOD × IMPACT) × 100)

    Das geometrische Mittel stellt sicher, dass ein hoher Score sowohl
    hohe Likelihood als auch hohen Impact erfordert – konsistent mit dem
    CVSS-Grundprinzip (FIRST, 2019: CVSS v3.1 Specification).

    Args:
        nhi:    NHI-Dictionary (Ausgabe von discovery.py oder Mock-Daten).
                Pflichtfelder: type, name
                Optionale Felder: age_days, policies, access_key_*_age_days,
                                  access_key_*_status, assume_role_policy,
                                  has_ip_condition, has_mfa_condition,
                                  suspicious_activity_flag, days_since_last_used
        config: Optionales Config-Dict. Wenn None, wird config.yaml geladen.

    Returns:
        NHIRiskResult mit vollständiger Begründung.
    """
    if config is None:
        config = _load_config()

    thresholds = config.get("scoring", {}).get("thresholds", {})

    nhi_type = nhi.get("type", "UNKNOWN")
    name = nhi.get("name", "unknown")
    policies = nhi.get("policies") or []

    # Access Key Alter (ältester aktiver Key) für Kompatibilität
    key_age_days: Optional[int] = None
    for i in range(1, 5):
        age = nhi.get(f"access_key_{i}_age_days")
        status = nhi.get(f"access_key_{i}_status", "Inactive")
        if age is not None and status == "Active":
            if key_age_days is None or age > key_age_days:
                key_age_days = age

    # --- LIKELIHOOD ---
    exp_val, exp_find, exp_rec = _calc_exposure(nhi)
    vuln_val, vuln_find, vuln_rec = _calc_vulnerability(nhi, thresholds)
    av_val, av_find, av_rec = _calc_attack_vector(nhi)

    likelihood = round(min(1.0, exp_val + vuln_val + av_val), 4)

    # --- IMPACT ---
    priv_val, priv_find, priv_rec = _calc_privilege_level(policies)
    sens_val, sens_find, sens_rec = _calc_data_sensitivity(policies)
    blast_val, blast_find, blast_rec = _calc_blast_radius(nhi, policies)

    impact = round(min(1.0, priv_val + sens_val + blast_val), 4)

    # --- SCORE (Geometrisches Mittel) ---
    raw_score = math.sqrt(likelihood * impact) if (likelihood > 0 and impact > 0) else 0.0
    risk_score = round(raw_score * 100)
    risk_score = max(0, min(100, risk_score))
    logger.debug(
        "Score für %s: L=%.3f I=%.3f → %d (%s)",
        name, likelihood, impact, risk_score, _risk_level(risk_score),
    )

    # Alle Findings und Empfehlungen zusammenführen
    all_findings = exp_find + vuln_find + av_find + priv_find + sens_find + blast_find
    all_recs = exp_rec + vuln_rec + av_rec + priv_rec + sens_rec + blast_rec

    # Inaktivität als separates Finding (kein eigener Score-Faktor, aber dokumentiert)
    days_since_used = nhi.get("days_since_last_used")
    if days_since_used is None and nhi.get("last_used") in (None, "Never"):
        all_findings.append("NHI wurde noch nie genutzt")
        all_recs.append("[MITTEL] Unbenutzte Identität prüfen und ggf. deaktivieren")
    elif isinstance(days_since_used, int) and days_since_used > 90:
        all_findings.append(f"Lange inaktiv: {days_since_used} Tage seit letzter Nutzung")
        all_recs.append("[MITTEL] Aktiv prüfen ob NHI noch benötigt wird")

    return NHIRiskResult(
        name=name,
        nhi_type=nhi_type,
        risk_score=risk_score,
        risk_level=_risk_level(risk_score),
        likelihood=likelihood,
        exposure=exp_val,
        vulnerability=vuln_val,
        attack_vector=av_val,
        impact=impact,
        privilege_level=priv_val,
        data_sensitivity=sens_val,
        blast_radius=blast_val,
        findings=all_findings,
        recommendations=all_recs,
        age_days=nhi.get("age_days"),
        days_since_last_used=days_since_used,
        policies=policies,
        access_key_age_days=key_age_days,
        # Legacy-Felder für Backward-Kompatibilität
        score_age=0,
        score_unused=0,
        score_permissions=0,
        score_key_rotation=0,
    )


def score_all(nhis: list[dict], config: Optional[dict] = None) -> list[NHIRiskResult]:
    """
    Berechnet Risk Scores für eine Liste von NHIs.

    Returns:
        Liste von NHIRiskResult, absteigend nach Score sortiert.
    """
    if config is None:
        config = _load_config()

    results = [calculate_risk_score(nhi, config) for nhi in nhis]
    results.sort(key=lambda r: r.risk_score, reverse=True)
    return results


def summarize(results: list[NHIRiskResult]) -> dict:
    """
    Erstellt eine statistische Zusammenfassung der Scan-Ergebnisse.

    Returns:
        Dict mit total, critical_count, high_count, medium_count, low_count.
    """
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        counts[r.risk_level] = counts.get(r.risk_level, 0) + 1

    return {
        "total": len(results),
        "critical_count": counts["CRITICAL"],
        "high_count": counts["HIGH"],
        "medium_count": counts["MEDIUM"],
        "low_count": counts["LOW"],
    }
