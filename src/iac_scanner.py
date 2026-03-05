"""
NHI Discovery Tool – Terraform/IaC-Scanner

Analysiert Terraform (.tf) Dateien auf IAM-Sicherheitsprobleme:
  - Überprivilegierte IAM-Policies (Action: *, Resource: *)
  - Fehlende Conditions in Trust Policies
  - Hardcodierte Credentials (AWS Access Keys, Passwörter)
  - Direkte aws_iam_access_key Ressourcen

Nutzt python-hcl2 zum Parsen von Terraform HCL2-Syntax.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import hcl2
    _HCL2_AVAILABLE = True
except ImportError:
    _HCL2_AVAILABLE = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Datenstrukturen
# ---------------------------------------------------------------------------

@dataclass
class IaCFinding:
    """Ein einzelner Sicherheitsbefund in einer Terraform-Datei."""

    severity: str        # CRITICAL | HIGH | MEDIUM | INFO
    resource: str        # Terraform-Ressourcen-ID (z.B. aws_iam_role.lambda_exec)
    issue: str           # Beschreibung des Problems
    recommendation: str  # Konkrete Handlungsempfehlung
    file: str            # Relativer Dateipfad
    line: Optional[int] = None  # Zeilennummer (falls verfügbar)


@dataclass
class IaCResource:
    """Eine IAM-Ressource aus einer Terraform-Datei."""

    resource_type: str   # aws_iam_user | aws_iam_role | aws_iam_policy | ...
    resource_name: str   # Terraform-Ressourcenname
    file: str
    attributes: dict = field(default_factory=dict)


@dataclass
class IaCScanResult:
    """Zusammenfassung eines IaC-Scans."""

    findings: list[IaCFinding] = field(default_factory=list)
    resources: list[IaCResource] = field(default_factory=list)
    total_resources: int = 0
    files_scanned: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0

    def __post_init__(self) -> None:
        self._update_counts()

    def _update_counts(self) -> None:
        self.critical_count = sum(1 for f in self.findings if f.severity == "CRITICAL")
        self.high_count = sum(1 for f in self.findings if f.severity == "HIGH")
        self.medium_count = sum(1 for f in self.findings if f.severity == "MEDIUM")


# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

# IAM-Ressourcentypen die für den Scanner relevant sind
_IAM_RESOURCE_TYPES: frozenset[str] = frozenset({
    "aws_iam_user",
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_access_key",
    "aws_iam_role_policy_attachment",
    "aws_iam_user_policy_attachment",
    "aws_iam_role_policy",
})

# Action-Suffixe die reine Leseoperationen kennzeichnen
_READ_ONLY_SUFFIXES: frozenset[str] = frozenset({
    ":Get",
    ":List",
    ":Describe",
})


# ---------------------------------------------------------------------------
# Reguläre Ausdrücke für Secret-Erkennung
# ---------------------------------------------------------------------------

# AWS Access Key ID Pattern: AKIA + 16 Großbuchstaben/Zahlen
_AWS_KEY_PATTERN = re.compile(
    r'(?<![A-Z0-9])(A(?:KIA|GPA|IPA|NPA|NVA|SIA)[A-Z0-9]{16})(?![A-Z0-9])'
)

# Potenzielle Passwörter/Secrets in Terraform-Variablen
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r'(?i)(password|passwd|secret|api_key|access_key|token|credential)\s*=\s*"([^"]{6,})"'
)

# Terraform-Variable-Referenzen (diese sind OK, keine Hardcoding)
_VAR_REFERENCE_PATTERN = re.compile(r'^\$\{var\.|^var\.')


# ---------------------------------------------------------------------------
# Terraform-Parsing
# ---------------------------------------------------------------------------

def _parse_tf_file(file_path: str) -> Optional[dict]:
    """
    Parst eine Terraform-Datei mit python-hcl2.

    Returns:
        Geparster Inhalt als Dict, oder None bei Fehler.
    """
    if not _HCL2_AVAILABLE:
        raise ImportError(
            "python-hcl2 ist nicht installiert. "
            "Installieren mit: pip install python-hcl2"
        )

    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            return hcl2.load(fh)
    except OSError as exc:
        logger.warning("Datei konnte nicht gelesen werden (%s): %s", file_path, exc)
        return None
    except Exception as exc:  # hcl2/lark parse errors haben keinen stabilen Typ
        logger.warning("HCL2-Parse-Fehler in %s: %s", file_path, exc)
        return None


def extract_iam_resources(parsed_hcl: dict, file_path: str) -> list[IaCResource]:
    """
    Extrahiert IAM-Ressourcen aus einem geparsten Terraform-Dict.

    Unterstützte Ressourcentypen:
      - aws_iam_user
      - aws_iam_role
      - aws_iam_policy
      - aws_iam_access_key
      - aws_iam_role_policy_attachment
      - aws_iam_user_policy_attachment
      - aws_iam_role_policy (inline)

    Args:
        parsed_hcl: Ausgabe von hcl2.load()
        file_path:  Quelldatei für Fehlerberichte

    Returns:
        Liste von IaCResource-Objekten
    """
    resources: list[IaCResource] = []
    resource_blocks = parsed_hcl.get("resource", [])

    # hcl2 gibt resource als Liste von Dicts zurück
    if isinstance(resource_blocks, dict):
        resource_blocks = [resource_blocks]

    for block in resource_blocks:
        for res_type, res_instances in block.items():
            if res_type not in _IAM_RESOURCE_TYPES:
                continue
            if isinstance(res_instances, dict):
                for res_name, attributes in res_instances.items():
                    resources.append(IaCResource(
                        resource_type=res_type,
                        resource_name=res_name,
                        file=file_path,
                        attributes=attributes if isinstance(attributes, dict) else {},
                    ))

    return resources


def _extract_jsonencode(value: str) -> Optional[dict]:
    """
    Extrahiert und parst den Inhalt einer `${jsonencode({...})}` Terraform-Funktion.

    hcl2 gibt jsonencode()-Aufrufe als String zurück: '${jsonencode({...})}'.
    Diese Funktion extrahiert das innere JSON-Objekt.
    """
    if not isinstance(value, str):
        return None

    # Muster: ${jsonencode({...})}  oder  jsonencode({...})
    match = re.search(r'jsonencode\s*\((.+)\)\s*\}?\s*$', value, re.DOTALL)
    if not match:
        return None

    inner = match.group(1).strip()
    # Letztes ')' entfernen falls vorhanden
    if inner.endswith(")"):
        inner = inner[:-1].strip()

    try:
        return json.loads(inner)
    except (json.JSONDecodeError, TypeError):
        # Terraform HCL kann `=` statt `:` verwenden – nicht weiter parsen
        return None


def analyze_policy(
    policy_doc: dict | str | list,
    resource_id: str,
    file_path: str,
) -> list[IaCFinding]:
    """
    Analysiert ein IAM-Policy-Dokument auf Sicherheitsprobleme.

    Prüfungen:
      1. Action: "*" (zu permissiv → CRITICAL)
      2. Resource: "*" kombiniert mit breitem Action-Scope (→ HIGH)
      3. Fehlende Conditions bei sensitiven Actions (→ MEDIUM)

    Args:
        policy_doc:  Policy-Dokument als Dict, JSON-String oder Liste
        resource_id: Terraform-Ressourcen-ID für den Befund
        file_path:   Quelldatei

    Returns:
        Liste von IaCFinding-Objekten
    """
    findings: list[IaCFinding] = []

    # Normalisierung
    if isinstance(policy_doc, str):
        # Versuche jsonencode()-String zu extrahieren
        jsonencode_result = _extract_jsonencode(policy_doc)
        if jsonencode_result:
            policy_doc = jsonencode_result
        else:
            try:
                policy_doc = json.loads(policy_doc)
            except (json.JSONDecodeError, TypeError):
                return []

    if isinstance(policy_doc, list):
        for item in policy_doc:
            findings.extend(analyze_policy(item, resource_id, file_path))
        return findings

    if not isinstance(policy_doc, dict):
        return []

    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue

        effect = stmt.get("Effect", "Allow")
        if effect != "Allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        conditions = stmt.get("Condition", {})

        # Prüfung 1: Wildcard-Action
        wildcard_actions = [a for a in actions if a in ("*", "iam:*", "sts:*")]
        if wildcard_actions:
            findings.append(IaCFinding(
                severity="CRITICAL",
                resource=resource_id,
                issue=f"Wildcard-Action '{', '.join(wildcard_actions)}' erlaubt alle AWS-Operationen",
                recommendation=(
                    "Action auf tatsächlich benötigte Operationen einschränken "
                    "(Principle of Least Privilege)"
                ),
                file=file_path,
            ))

        # Prüfung 2: Resource Wildcard kombiniert mit breiten Actions
        if "*" in resources and actions and not wildcard_actions:
            # HIGH wenn Schreibrechte mit Resource-Wildcard
            write_actions = [
                a for a in actions
                if not any(a.endswith(suffix + "*") for suffix in _READ_ONLY_SUFFIXES)
            ]
            if write_actions:
                findings.append(IaCFinding(
                    severity="HIGH",
                    resource=resource_id,
                    issue=(
                        f"Resource: '*' kombiniert mit Schreib-Actions "
                        f"({', '.join(write_actions[:3])}{'...' if len(write_actions) > 3 else ''})"
                    ),
                    recommendation=(
                        "Resource auf spezifische ARNs einschränken "
                        "(z.B. arn:aws:s3:::my-bucket/*)"
                    ),
                    file=file_path,
                ))

        # Prüfung 3: Sensitive Actions ohne Conditions
        sensitive = [a for a in actions if any(
            a.startswith(p) for p in (
                "iam:", "sts:AssumeRole", "kms:", "secretsmanager:", "s3:DeleteBucket"
            )
        )]
        if sensitive and not conditions:
            findings.append(IaCFinding(
                severity="MEDIUM",
                resource=resource_id,
                issue=(
                    f"Sensitive Actions ohne Condition: "
                    f"{', '.join(sensitive[:3])}"
                ),
                recommendation=(
                    "Condition-Block mit aws:SourceIp oder aws:MultiFactorAuthPresent "
                    "für sensitive Operationen hinzufügen"
                ),
                file=file_path,
            ))

    return findings


def find_hardcoded_secrets(
    file_content: str,
    file_path: str,
) -> list[IaCFinding]:
    """
    Sucht nach hardcodierten Credentials in Terraform-Code.

    Erkennt:
      - AWS Access Key IDs (AKIA...)
      - Passwort/Secret-Zuweisungen mit Literalwerten

    Args:
        file_content: Rohinhalt der .tf-Datei
        file_path:    Quelldatei für Befunde

    Returns:
        Liste von IaCFinding-Objekten
    """
    findings: list[IaCFinding] = []

    # AWS Access Key IDs
    for match in _AWS_KEY_PATTERN.finditer(file_content):
        line_num = file_content[:match.start()].count("\n") + 1
        findings.append(IaCFinding(
            severity="CRITICAL",
            resource="hardcoded_secret",
            issue=f"Hardcodierter AWS Access Key gefunden: {match.group(1)[:8]}...",
            recommendation=(
                "Credentials niemals in Terraform-Code speichern. "
                "Nutze AWS Secrets Manager, Vault oder Umgebungsvariablen."
            ),
            file=file_path,
            line=line_num,
        ))

    # Passwort/Secret-Zuweisungen
    for match in _SECRET_ASSIGNMENT_PATTERN.finditer(file_content):
        var_name = match.group(1)
        value = match.group(2)

        # Terraform-Variablenreferenzen und Platzhalter überspringen
        if (
            _VAR_REFERENCE_PATTERN.match(value)
            or value.startswith("${")
            or value in ("<placeholder>", "CHANGE_ME", "TODO")
        ):
            continue

        line_num = file_content[:match.start()].count("\n") + 1
        findings.append(IaCFinding(
            severity="HIGH",
            resource="hardcoded_secret",
            issue=f"Mögliches hardcodiertes Secret: {var_name} = \"{'*' * min(len(value), 8)}...\"",
            recommendation=(
                f"Variable '{var_name}' nicht als Literal speichern. "
                "Nutze var.<name> oder data.aws_secretsmanager_secret."
            ),
            file=file_path,
            line=line_num,
        ))

    return findings


def _analyze_trust_policy(resource: IaCResource, file_path: str) -> list[IaCFinding]:
    """Analysiert Trust Policies von IAM Roles auf problematische Principals."""
    findings: list[IaCFinding] = []

    assume_doc = resource.attributes.get("assume_role_policy", "")
    if not assume_doc:
        return findings

    if isinstance(assume_doc, str):
        jsonencode_result = _extract_jsonencode(assume_doc)
        if jsonencode_result:
            assume_doc = jsonencode_result
        else:
            try:
                assume_doc = json.loads(assume_doc)
            except (json.JSONDecodeError, TypeError):
                return findings

    stmts = assume_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    for stmt in stmts:
        if not isinstance(stmt, dict):
            continue
        principal = stmt.get("Principal", {})
        if principal == "*":
            findings.append(IaCFinding(
                severity="CRITICAL",
                resource=f"aws_iam_role.{resource.resource_name}",
                issue="Trust Policy erlaubt Principal: '*' (alle AWS-Identitäten)",
                recommendation="Principal auf spezifische Services oder Account-ARNs einschränken",
                file=file_path,
            ))
        elif isinstance(principal, dict):
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            if "*" in aws_principals:
                findings.append(IaCFinding(
                    severity="CRITICAL",
                    resource=f"aws_iam_role.{resource.resource_name}",
                    issue="Trust Policy erlaubt AWS: '*' (alle AWS-Accounts)",
                    recommendation="Principal auf spezifische Account-ARNs einschränken",
                    file=file_path,
                ))

    return findings


# ---------------------------------------------------------------------------
# Haupt-API
# ---------------------------------------------------------------------------

def scan_directory(path: str) -> IaCScanResult:
    """
    Scannt ein Verzeichnis rekursiv nach Terraform-Dateien und analysiert
    alle IAM-Ressourcen auf Sicherheitsprobleme.

    Args:
        path: Pfad zum Verzeichnis (oder einzelner .tf-Datei)

    Returns:
        IaCScanResult mit allen Findings und Ressourcen.
    """
    tf_files: list[Path] = []
    scan_path = Path(path)

    if scan_path.is_file() and scan_path.suffix == ".tf":
        tf_files = [scan_path]
    elif scan_path.is_dir():
        tf_files = list(scan_path.rglob("*.tf"))
    else:
        return IaCScanResult()

    logger.info("Starte IaC-Scan: %d Terraform-Dateien in %s", len(tf_files), path)
    all_findings: list[IaCFinding] = []
    all_resources: list[IaCResource] = []

    for tf_file in tf_files:
        file_str = str(tf_file)
        file_content = tf_file.read_text(encoding="utf-8", errors="ignore")

        # 1. Hardcodierte Secrets (regex-basiert, kein HCL2 nötig)
        all_findings.extend(find_hardcoded_secrets(file_content, file_str))

        # 2. HCL2-Parsing
        parsed = _parse_tf_file(file_str)
        if parsed is None:
            continue

        resources = extract_iam_resources(parsed, file_str)
        all_resources.extend(resources)

        # 3. Ressourcen analysieren
        for resource in resources:
            resource_id = f"{resource.resource_type}.{resource.resource_name}"

            # Trust Policy für Roles
            if resource.resource_type == "aws_iam_role":
                all_findings.extend(_analyze_trust_policy(resource, file_str))

            # IAM Policy-Dokument analysieren
            policy_doc = resource.attributes.get("policy", "")
            if policy_doc:
                all_findings.extend(analyze_policy(policy_doc, resource_id, file_str))

            # aws_iam_access_key direkt in TF = Warnung
            if resource.resource_type == "aws_iam_access_key":
                all_findings.append(IaCFinding(
                    severity="HIGH",
                    resource=resource_id,
                    issue=(
                        "aws_iam_access_key Ressource in Terraform: "
                        "Credentials werden im State-File gespeichert"
                    ),
                    recommendation=(
                        "IAM User-Credentials nicht über Terraform verwalten. "
                        "Nutze IAM Roles und Instance Profiles statt Access Keys."
                    ),
                    file=file_str,
                ))

    result = IaCScanResult(
        findings=all_findings,
        resources=all_resources,
        total_resources=len(all_resources),
        files_scanned=len(tf_files),
    )
    result._update_counts()
    return result


def to_sarif(result: IaCScanResult, base_path: str = "") -> dict:
    """
    Konvertiert ein IaCScanResult in das SARIF 2.1.0-Format.

    SARIF (Static Analysis Results Interchange Format) ist der OASIS-Standard
    für statische Analyse-Ergebnisse und wird von GitHub Code Scanning nativ
    unterstützt (github.com/microsoft/sarif-tutorials).

    Severity-Mapping:
      CRITICAL → error
      HIGH     → error
      MEDIUM   → warning
      INFO     → note

    Args:
        result:    Ergebnis eines IaC-Scans.
        base_path: Basispfad zum Relativieren der Dateinamen (optional).

    Returns:
        SARIF 2.1.0-konformes Dict (json-serialisierbar).
    """
    _SEVERITY_MAP = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "INFO": "note",
    }

    # Regeln aus allen einzigartigen (severity, issue)-Kombinationen ableiten
    rules: dict[str, dict] = {}
    sarif_results: list[dict] = []

    for finding in result.findings:
        # Regelbezeichner: severity + ressource-type (stabil, eindeutig genug)
        rule_id = f"NHI-IAC-{finding.severity}-{finding.resource.replace('.', '-').upper()}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f"IaC{finding.severity.capitalize()}Finding",
                "shortDescription": {"text": finding.issue},
                "fullDescription": {"text": finding.recommendation},
                "defaultConfiguration": {
                    "level": _SEVERITY_MAP.get(finding.severity, "warning")
                },
                "helpUri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
                "properties": {"tags": ["security", "iam", "terraform"]},
            }

        # Relativer Dateipfad
        file_path = finding.file
        if base_path and file_path.startswith(base_path):
            file_path = os.path.relpath(file_path, base_path)

        sarif_result: dict = {
            "ruleId": rule_id,
            "level": _SEVERITY_MAP.get(finding.severity, "warning"),
            "message": {
                "text": f"{finding.issue}\n\nEmpfehlung: {finding.recommendation}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path.replace(os.sep, "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line or 1,
                        },
                    },
                    "logicalLocations": [
                        {
                            "name": finding.resource,
                            "kind": "resource",
                        }
                    ],
                }
            ],
            "properties": {"severity": finding.severity},
        }
        sarif_results.append(sarif_result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "nhi-discovery",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/example/nhi-discovery",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
                "properties": {
                    "filesScanned": result.files_scanned,
                    "totalResources": result.total_resources,
                },
            }
        ],
    }


def generate_report(path: str) -> IaCScanResult:
    """
    Führt einen vollständigen IaC-Scan durch und gibt das Ergebnis zurück.

    Alias für scan_directory() mit zusätzlicher Sortierung der Findings
    nach Severity (CRITICAL zuerst).

    Args:
        path: Verzeichnis- oder Dateipfad.

    Returns:
        IaCScanResult mit nach Severity sortierten Findings.
    """
    result = scan_directory(path)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    result.findings.sort(key=lambda f: severity_order.get(f.severity, 99))
    return result
