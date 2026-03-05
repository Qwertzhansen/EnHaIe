# NHI Discovery Tool

Automatische Erkennung und Risikobewertung von **Non-Human Identities (NHIs)** in AWS.
Entwickelt im Rahmen einer Masterarbeit über Cloud-Sicherheit und IAM-Governance.

---

## Was sind Non-Human Identities?

Non-Human Identities (NHIs) sind alle digitalen Identitäten, die nicht direkt von einem Menschen verwendet werden: Service Accounts, API Keys, IAM Roles für Lambda-Funktionen, EC2 Instance Profiles, CI/CD-Credentials etc.

Sie sind häufig eine unterschätzte Angriffsfläche, weil sie:

- selten rotiert werden und über Jahre aktiv bleiben
- überprivilegiert sind (Principle of Least Privilege wird verletzt)
- kein MFA haben und von überall aus verwendbar sind
- lang ungenutzt bleiben, ohne bemerkt zu werden

---

## Features

| Feature | Beschreibung |
|---------|-------------|
| **IAM Discovery** | Scannt alle IAM Users und Roles inkl. Policies, Key-Alter, letzte Nutzung |
| **CVSS-Scoring** | Risikobewertung 0–100 nach `RISK_SCORE = sqrt(LIKELIHOOD × IMPACT) × 100` |
| **CloudTrail-Analyse** | Erkennt verdächtige Aktivitäten: Nacht-Calls, sensitive APIs, externe IPs |
| **IaC-Scanner** | Analysiert Terraform-Code auf IAM-Fehlkonfigurationen und hardcodierte Secrets |
| **Score-Erklärung** | `explain`-Command zeigt Likelihood × Impact Breakdown pro NHI |
| **Trend-Tracking** | SQLite-Datenbank speichert jeden Scan für historische Auswertung |
| **Dashboard** | Streamlit-Web-UI mit interaktiven Charts und Drill-Down |
| **Mock-Modus** | Vollständig ohne AWS-Credentials nutzbar (Demo/Tests) |
| **172 Tests** | Alle Tests laufen ohne AWS-Zugriff |

---

## Installation

```bash
# Repository klonen
git clone <repo-url>
cd nhi-discovery

# Virtuelle Umgebung anlegen
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Dependencies installieren
pip install -r requirements.txt
```

**Voraussetzungen:** Python 3.10+

---

## Quick Start

```bash
# 1. Demo-Scan (kein AWS nötig)
python -m src.cli scan --mock

# 2. Score-Breakdown für ein NHI anzeigen
python -m src.cli explain svc-old-backup

# 3. Terraform-Verzeichnis auf Sicherheitsprobleme prüfen
python -m src.cli scan --mock --iac ./terraform/

# 4. Dashboard starten
streamlit run src/dashboard.py
```

---

## AWS-Konfiguration

Für echte Scans werden AWS-Credentials mit Leserechten benötigt:

```bash
# Option 1: AWS CLI
aws configure

# Option 2: Umgebungsvariablen
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=eu-central-1

# Option 3: IAM Role (empfohlen in AWS-Umgebungen – kein Key nötig)
```

**Minimale IAM-Policy** (ReadOnly, kein Write-Zugriff):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers", "iam:ListRoles",
        "iam:GetUser", "iam:GetRole",
        "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed",
        "iam:ListAttachedUserPolicies", "iam:ListAttachedRolePolicies"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["cloudtrail:LookupEvents"],
      "Resource": "*"
    }
  ]
}
```

---

## CLI-Referenz

### `scan` – NHI-Scan durchführen

```bash
# Demo-Modus (keine AWS-Credentials)
python -m src.cli scan --mock

# Echter Scan
python -m src.cli scan --account 123456789012

# + CloudTrail-Analyse (90 Tage, erkennt Anomalien)
python -m src.cli scan --deep

# + Terraform-Verzeichnis analysieren
python -m src.cli scan --iac ./terraform/

# Alles kombiniert
python -m src.cli scan --deep --iac ./terraform/ --account 123456789012
```

**Ausgabe:**
```
╭──────────────────────────────────────────────╮
│ NHI Discovery Tool v2                        │
│ CVSS-inspiriertes Non-Human Identity Scanner │
╰──────────────────────────────────────────────╯

  NHI                        │ Score │ Level      │ Alter │ Inaktiv seit
  ─────────────────────────────────────────────────────────────────────────
  svc-old-backup             │   55  │ 🟡 MEDIUM  │ 400d  │ Nie
  svc-deployment             │   50  │ 🟡 MEDIUM  │ 180d  │ 2d
  role-lambda-overprivileged │   49  │ 🟡 MEDIUM  │ 300d  │ 95d
  svc-external-api           │   39  │ 🟢 LOW     │  45d  │ 1d

  Gesamt: 5  CRITICAL: 0  HIGH: 0  MEDIUM: 4  LOW: 1
```

---

### `explain` – Score-Breakdown anzeigen

```bash
python -m src.cli explain svc-old-backup
```

**Ausgabe:**
```
NHI: svc-old-backup   Typ: USER
Risk Score: 55/100 (MEDIUM)
Formel: sqrt(0.50 × 0.60) × 100 ≈ 55

LIKELIHOOD: 0.50
  ├── Exposure:       0.20  (keine IP-Restrictions)
  ├── Vulnerability:  0.10  (Key 95 Tage alt)
  └── Attack Vector:  0.20  (keine MFA + keine IP-Condition)

IMPACT: 0.60
  ├── Privilege Level:  0.50  (AdministratorAccess)
  ├── Data Sensitivity: 0.00
  └── Blast Radius:     0.10  (IAM-Eskalation möglich)

Empfehlungen:
  → [KRITISCH] AdministratorAccess entfernen
  → [MITTEL]   Access Key rotieren
  → [MITTEL]   IP-Condition hinzufügen
```

---

### `report` – Letzten Scan anzeigen

```bash
# Kompakte Tabelle
python -m src.cli report

# Mit Findings und Empfehlungen
python -m src.cli report --verbose
```

---

### `history` – Scan-Verlauf

```bash
python -m src.cli history
```

```
  ID │ Zeitstempel          │ Total │ CRITICAL │ HIGH │ MEDIUM │ LOW
  ───┼──────────────────────┼───────┼──────────┼──────┼────────┼─────
   1 │ 2026-02-28 09:00:00  │     5 │        1 │    2 │      1 │   1
   2 │ 2026-03-01 08:00:00  │     5 │        0 │    1 │      3 │   1
```

---

### `export` – Daten exportieren

```bash
# CSV (Standard)
python -m src.cli export --format csv

# JSON
python -m src.cli export --format json

# Benutzerdefinierter Ausgabepfad
python -m src.cli export --format csv --output /tmp/nhi-report.csv
```

---

## Risk Scoring

Jedes NHI erhält einen Score von **0 (kein Risiko)** bis **100 (kritisch)**.

### Formel

```
RISK_SCORE = round( sqrt(LIKELIHOOD × IMPACT) × 100 )
```

Das geometrische Mittel stellt sicher, dass ein hoher Score **sowohl hohe Likelihood als auch hohen Impact** erfordert – konsistent mit dem CVSS 3.1-Grundprinzip.

### Dimensionen

| Dimension | Komponente | Bereich | Beschreibung |
|-----------|-----------|---------|-------------|
| **LIKELIHOOD** | Exposure | 0.0–0.4 | Exposition (IP-Restrictions, CloudTrail-Anomalien) |
| | Vulnerability | 0.0–0.3 | Credential-Alter und Rotation |
| | Attack Vector | 0.0–0.2 | Fehlende Schutzmechanismen (MFA, Conditions) |
| **IMPACT** | Privilege Level | 0.0–0.5 | Umfang der IAM-Berechtigungen |
| | Data Sensitivity | 0.0–0.3 | Zugriff auf sensible Services (Secrets, S3, KMS) |
| | Blast Radius | 0.0–0.2 | Cross-Account-Zugriff, IAM-Eskalation |

### Risk Levels

| Level | Score | Bedeutung |
|-------|-------|-----------|
| 🔴 CRITICAL | 80–100 | Sofortiger Handlungsbedarf |
| 🟠 HIGH | 60–79 | Hohe Priorität, zeitnah beheben |
| 🟡 MEDIUM | 40–59 | Mittelfristig adressieren |
| 🟢 LOW | 0–39 | Überwachen, kein Sofortbedarf |

Vollständige Modell-Dokumentation: [`docs/risk_model.md`](docs/risk_model.md)

---

## IaC-Scanner

Analysiert Terraform-Dateien auf IAM-Sicherheitsprobleme:

| Befund | Severity | Beispiel |
|--------|----------|---------|
| `Action: "*"` | 🔴 CRITICAL | Vollzugriff auf alle AWS-Services |
| Trust Policy `Principal: "*"` | 🔴 CRITICAL | Jeder kann die Rolle annehmen |
| Hardcodierter AWS Key (`AKIA...`) | 🔴 CRITICAL | Credentials im Quellcode |
| `Resource: "*"` + Schreibrechte | 🟠 HIGH | Unrestricted Write |
| `aws_iam_access_key` in TF | 🟠 HIGH | Key im State-File gespeichert |
| Sensitive Actions ohne Condition | 🟡 MEDIUM | IAM-Änderungen ohne Einschränkung |

```bash
# Standalone IaC-Scan
python -m src.cli scan --mock --iac ./terraform/

# Ausgabe:
# Dateien: 3  Ressourcen: 12  CRITICAL: 2  HIGH: 3  MEDIUM: 1
```

---

## Dashboard

```bash
# Erst einen Scan ausführen
python -m src.cli scan --mock

# Dashboard starten
streamlit run src/dashboard.py
# → Öffnet sich automatisch unter http://localhost:8501
```

---

## Tests

```bash
# Alle Tests (kein AWS nötig)
python -m pytest tests/ -v

# Nur Scoring-Tests
python -m pytest tests/test_risk_scoring.py -v

# Mit Coverage
python -m pytest tests/ --cov=src --cov-report=term-missing
```

**Testabdeckung:** 172 Tests in 3 Test-Dateien.

---

## Architektur-Übersicht

```
AWS IAM API ──► discovery.py ──────────────────────────────►┐
                                                            │
AWS CloudTrail ──► cloudtrail_analyzer.py ──► Enrichment ──►│
                                                            │
Terraform/.tf ──► iac_scanner.py ──► Findings ──────────────┤
                                                            ▼
                                              risk_scoring.py
                                         sqrt(L × I) × 100
                                                            │
                                                            ▼
                                              database.py (SQLite)
                                                            │
                                              ┌─────────────┴──────────┐
                                              │                        │
                                           cli.py                dashboard.py
                                       (Terminal)               (Streamlit)
```

Detaillierte Architektur-Dokumentation: [`docs/architecture.md`](docs/architecture.md)

---

## Konfiguration

```yaml
# config.yaml
scoring:
  model: cvss_inspired
  thresholds:
    key_rotation_warning_days: 90   # Vulnerability +0.1 ab hier
    key_rotation_critical_days: 365 # Vulnerability +0.3 wenn nie rotiert

risk_levels:
  critical: 80
  high: 60
  medium: 40

aws:
  region: eu-central-1

ignore:
  users: []   # NHI-Namen die vom Scan ausgeschlossen werden
  roles: []
```

---

## Technologie-Stack

| Komponente | Technologie |
|------------|-------------|
| AWS-Anbindung | boto3 |
| IaC-Parsing | python-hcl2 |
| CLI | Click + Rich |
| Dashboard | Streamlit + Plotly |
| Datenbank | SQLite (stdlib) |
| Konfiguration | PyYAML |
| Tests | pytest |
| Datenverarbeitung | pandas |

---

## Lizenz

Entwickelt im Rahmen einer Masterarbeit. Alle Rechte vorbehalten.
