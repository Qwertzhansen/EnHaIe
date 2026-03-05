# NHI Discovery Tool – Systemarchitektur

## 1. Systemübersicht

Das NHI Discovery Tool ist eine modulare Python-Anwendung zur automatisierten Erkennung und Risikobewertung von Non-Human Identities (NHIs) in AWS. Es besteht aus sechs unabhängigen Kernmodulen, die über eine gemeinsame CLI-Schicht orchestriert werden.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         NHI Discovery Tool v2                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Eingabe / Datenquellen                                                    │
│   ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────────┐   │
│   │   AWS IAM API    │  │ AWS CloudTrail   │  │  Terraform (.tf Files) │   │
│   │  (boto3/IAM)     │  │  (boto3/CT)      │  │    (python-hcl2)       │   │
│   └────────┬─────────┘  └────────┬─────────┘  └───────────┬────────────┘  │
│            │                     │                         │               │
│            ▼                     ▼                         ▼               │
│   ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────────┐   │
│   │  discovery.py    │  │cloudtrail_       │  │   iac_scanner.py       │   │
│   │  IAM Discovery   │  │analyzer.py       │  │   Terraform Scanner    │   │
│   │  - Users         │  │  - Aktivität     │  │   - Policy-Analyse     │   │
│   │  - Roles         │  │  - Anomalien     │  │   - Hardcoded Secrets  │   │
│   │  - Policies      │  │  - Enrichment    │  │   - Trust-Policies     │   │
│   └────────┬─────────┘  └────────┬─────────┘  └───────────┬────────────┘  │
│            │                     │                         │               │
│            └──────────┬──────────┘                         │               │
│                       │                                     │               │
│                       ▼                                     │               │
│   ┌──────────────────────────────────────┐                  │               │
│   │          risk_scoring.py             │                  │               │
│   │     CVSS-inspiriertes Scoring        │                  │               │
│   │  RISK_SCORE = sqrt(L × I) × 100      │                  │               │
│   │  - Likelihood: Exposure+Vuln+AV      │                  │               │
│   │  - Impact: Privilege+Sens+Blast      │                  │               │
│   └────────────────────┬─────────────────┘                  │               │
│                        │                                     │               │
│                        ▼                                     ▼               │
│   ┌──────────────────────────────────────────────────────────────────────┐   │
│   │                          cli.py  (Click)                             │   │
│   │  scan | scan --deep | scan --iac PATH | report | history | explain   │   │
│   └─────────────┬──────────────────────────────────────┬─────────────────┘  │
│                 │                                       │               │    │
│                 ▼                                       ▼               │    │
│   ┌─────────────────────────┐            ┌─────────────────────────┐   │    │
│   │      database.py        │            │      dashboard.py        │   │    │
│   │   SQLite Persistenz     │            │   Streamlit Web-UI       │   │    │
│   │   - Tabelle: scans      │            │   - Risk-Übersicht       │   │    │
│   │   - Tabelle: nhis       │◄──────────►│   - Trend-Charts         │   │    │
│   │   - Trend-Analyse       │            │   - Drill-Down           │   │    │
│   └─────────────────────────┘            └─────────────────────────┘   │    │
│                                                                         │    │
└─────────────────────────────────────────────────────────────────────────┘    │
```

---

## 2. Komponentenbeschreibung

### 2.1 `src/discovery.py` – IAM Discovery

Verantwortlich für die Abfrage aller NHIs aus dem AWS IAM-Service.

**Kernfunktionen:**
- `discover_iam_users()` – Listet alle IAM-User mit Metadaten (Alter, letzte Nutzung, Access Keys, Policies)
- `discover_iam_roles()` – Listet alle IAM-Rollen mit Trust Policies und Berechtigungen

**AWS APIs genutzt:**
- `iam:ListUsers` / `iam:ListRoles`
- `iam:GetUser` / `iam:GetRole`
- `iam:ListAttachedUserPolicies` / `iam:ListAttachedRolePolicies`
- `iam:ListAccessKeys` / `iam:GetAccessKeyLastUsed`
- `iam:GetRolePolicy` (Trust Policy für Cross-Account-Analyse)

**Ausgabe:** Liste von NHI-Dictionaries mit standardisierten Feldern (`type`, `name`, `age_days`, `policies`, `access_key_*_age_days`, `has_ip_condition`, etc.)

---

### 2.2 `src/cloudtrail_analyzer.py` – CloudTrail-Analyse

Analysiert AWS CloudTrail-Events zur Verhaltensanalyse und Anomalie-Erkennung.

**Kernfunktionen:**
- `get_nhi_activity(ct_client, days=90)` – Paginierter Abruf aller IAM-Events
- `find_unused_nhis(nhi_names, events)` – Identifiziert NHIs ohne CloudTrail-Aktivität
- `find_suspicious_activity(events)` – Anomalie-Erkennung nach drei Regeln:
  1. API-Call außerhalb Betriebszeiten (06:00–22:00 UTC)
  2. Sensitive IAM-APIs (`CreateUser`, `CreateAccessKey`, `AttachPolicy` etc.)
  3. Zugriff von nicht-privaten IP-Adressen
- `enrich_nhis_with_cloudtrail(nhis, events)` – Reichert NHI-Daten mit CloudTrail-Erkenntnissen an (setzt `suspicious_activity_flag`)

**Design:** Der CloudTrail-Client wird per Dependency Injection übergeben → vollständig mock-bar ohne AWS-Zugriff.

---

### 2.3 `src/iac_scanner.py` – Terraform/IaC-Scanner

Statische Analyse von Terraform-Dateien auf IAM-Sicherheitsprobleme.

**Erkennungsregeln:**

| Regel | Severity | Beispiel |
|-------|----------|---------|
| `Action: "*"` in Policy | CRITICAL | Vollständige AWS-Kontrolle |
| Trust Policy `Principal: "*"` | CRITICAL | Jeder kann die Rolle annehmen |
| Hardcodierter AWS Access Key (`AKIA...`) | CRITICAL | Credential-Leak im Code |
| `Resource: "*"` + Schreib-Actions | HIGH | Unrestricted Write-Zugriff |
| `aws_iam_access_key` Ressource in TF | HIGH | Credentials im State-File |
| Sensitive Actions ohne `Condition` | MEDIUM | IAM-Änderungen ohne Einschränkung |

**Technologie:** `python-hcl2` für HCL2-Parsing; Regex für Secret-Erkennung (Pattern: `AKIA[A-Z0-9]{16}`).

---

### 2.4 `src/risk_scoring.py` – Risk Scoring Engine

Herzstück des Tools. Berechnet einen CVSS-inspirierten Risk Score für jedes NHI.

**Formel:** `RISK_SCORE = round(sqrt(LIKELIHOOD × IMPACT) × 100)`

Sechs Teilkomponenten (Details → `docs/risk_model.md`):

```
LIKELIHOOD (0.0–1.0):
  ├── Exposure       (0.0–0.4)  Exposition gegenüber Angreifern
  ├── Vulnerability  (0.0–0.3)  Credential-Alter und Rotation
  └── Attack Vector  (0.0–0.2)  Fehlende Schutzmechanismen (MFA, Conditions)

IMPACT (0.0–1.0):
  ├── Privilege Level  (0.0–0.5)  Umfang der IAM-Berechtigungen
  ├── Data Sensitivity (0.0–0.3)  Zugriff auf sensible Dienste
  └── Blast Radius     (0.0–0.2)  Laterale Ausbreitung möglich
```

**Ausgabe:** `NHIRiskResult`-Dataclass mit Score, Level, allen Komponenten, Findings und Empfehlungen.

---

### 2.5 `src/cli.py` – CLI-Interface

Click-basierte Command-Line-Interface. Orchestriert alle Module.

| Command | Beschreibung |
|---------|-------------|
| `scan` | IAM-Scan, Scoring, DB-Speicherung |
| `scan --mock` | Demo-Modus ohne AWS-Credentials |
| `scan --deep` | + CloudTrail-Enrichment (90 Tage) |
| `scan --iac PATH` | + Terraform-Analyse des angegebenen Verzeichnisses |
| `report` | Letzten Scan als formatierte Tabelle |
| `report --verbose` | + Findings und Empfehlungen |
| `history` | Alle bisherigen Scans mit KPIs |
| `export --format csv/json` | Export des letzten Scans |
| `explain NHI_NAME` | LIKELIHOOD × IMPACT Breakdown für ein NHI |

---

### 2.6 `src/database.py` – Persistenzschicht

SQLite-basierte lokale Datenbank für Scan-Ergebnisse und Trendanalysen.

**Schema:**

```sql
-- Scan-Metadaten
CREATE TABLE scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT    NOT NULL,  -- ISO-8601 UTC
    aws_account    TEXT,
    total_nhis     INTEGER,
    critical_count INTEGER,
    high_count     INTEGER,
    medium_count   INTEGER,
    low_count      INTEGER
);

-- NHI-Ergebnisse (inkl. CVSS-Komponenten)
CREATE TABLE nhis (
    id                   INTEGER PRIMARY KEY,
    scan_id              INTEGER REFERENCES scans(id),
    type                 TEXT,    -- IAM_USER | IAM_ROLE
    name                 TEXT,
    risk_score           INTEGER, -- 0–100
    risk_level           TEXT,    -- CRITICAL|HIGH|MEDIUM|LOW
    likelihood           REAL,    -- CVSS Likelihood (0.0–1.0)
    impact               REAL,    -- CVSS Impact (0.0–1.0)
    exposure             REAL,    -- Teilkomponente
    vulnerability        REAL,    -- Teilkomponente
    attack_vector        REAL,    -- Teilkomponente
    privilege_level      REAL,    -- Teilkomponente
    data_sensitivity     REAL,    -- Teilkomponente
    blast_radius         REAL,    -- Teilkomponente
    policies             TEXT,    -- JSON-Array
    findings             TEXT,    -- JSON-Array
    recommendations      TEXT,    -- JSON-Array
    age_days             INTEGER,
    days_since_last_used INTEGER,
    access_key_age_days  INTEGER
);
```

**Migration:** Neue Spalten werden per `ALTER TABLE ADD COLUMN` idempotent hinzugefügt – bestehende Datenbanken bleiben kompatibel.

---

### 2.7 `src/dashboard.py` – Web-Dashboard

Streamlit-basiertes interaktives Dashboard für die visuelle Auswertung.

**Funktionen:**
- Kennzahlen-Übersicht (CRITICAL/HIGH/MEDIUM/LOW Counts)
- Risiko-Verteilungs-Chart (Plotly)
- Sortierbare NHI-Tabelle mit Score-Visualisierung
- Trend-Ansicht über mehrere Scans
- Direktlink zur Empfehlungsliste

---

## 3. Datenfluss

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Input                                                                  │
│  ┌─────────────┐  ┌──────────────────┐  ┌────────────────────────────┐ │
│  │ AWS IAM API │  │ AWS CloudTrail   │  │  .tf Dateien (Terraform)   │ │
│  └──────┬──────┘  └────────┬─────────┘  └───────────────┬────────────┘ │
└─────────┼──────────────────┼────────────────────────────┼──────────────┘
          │                  │                             │
          ▼                  ▼                             ▼
┌─────────────────┐  ┌──────────────────┐  ┌────────────────────────────┐
│ discovery.py    │  │cloudtrail_       │  │ iac_scanner.py             │
│                 │  │analyzer.py       │  │                            │
│ NHI-Liste:      │  │                  │  │ IaCScanResult:             │
│ [{               │  │ events=[{...}]   │  │   findings=[IaCFinding]    │
│   type, name,   │─►│                  │  │   total_resources=8        │
│   policies,     │  │ Enrichment:      │  │   critical_count=3         │
│   age_days,     │◄─│ suspicious_flag  │  └────────────────────────────┘
│   ...           │  │ days_since_used  │           │ (--iac Ausgabe)
│ }]              │  └──────────────────┘           │ → CLI-Tabelle
└────────┬────────┘                                 │
         │                                          │
         ▼                                          │
┌────────────────────────────────────────┐          │
│ risk_scoring.py                        │          │
│                                        │          │
│ Per NHI:                               │          │
│  calc_exposure()   → exposure          │          │
│  calc_vulnerability() → vulnerability  │          │
│  calc_attack_vector() → attack_vector  │          │
│  calc_privilege_level() → priv         │          │
│  calc_data_sensitivity() → sens        │          │
│  calc_blast_radius() → blast           │          │
│                                        │          │
│  score = round(sqrt(L × I) × 100)      │          │
│  → NHIRiskResult(score, level, ...)    │          │
└────────┬───────────────────────────────┘          │
         │                                          │
         ▼                                          │
┌────────────────────────────────────────┐          │
│ database.py                            │          │
│  save_scan(results) → scan_id          │          │
│  get_latest_scan() → {scan, nhis}      │          │
│  get_scan_history() → [scan, ...]      │          │
└────────┬───────────────────────────────┘          │
         │                                          │
         ▼                                          ▼
┌──────────────────────────────────────────────────────┐
│ Ausgabe / Präsentation                               │
│                                                      │
│  cli.py           → Rich-formatierte Terminalausgabe │
│  dashboard.py     → Streamlit Web-Interface          │
│  export (CSV/JSON) → Dateisystem                     │
└──────────────────────────────────────────────────────┘
```

---

## 4. Technologie-Stack

| Schicht | Technologie | Version | Zweck |
|---------|-------------|---------|-------|
| AWS-Anbindung | `boto3` | ≥ 1.34 | IAM + CloudTrail API-Zugriff |
| Datenverarbeitung | `pandas` | ≥ 2.0 | Trendanalysen im Dashboard |
| CLI | `click` | ≥ 8.1 | Command-Parsing, Option-Handling |
| Terminal-UI | `rich` | ≥ 13.0 | Farbige Tabellen, Panels, Trees |
| Web-Dashboard | `streamlit` | ≥ 1.35 | Interaktive Web-Oberfläche |
| Charts | `plotly` | ≥ 5.18 | Interaktive Diagramme |
| Datenbank | SQLite (stdlib) | – | Lokale Persistenz ohne Server |
| Konfiguration | `pyyaml` | ≥ 6.0 | `config.yaml` Parsing |
| IaC-Parsing | `python-hcl2` | ≥ 4.3 | Terraform HCL2 Parsing |
| Tests | `pytest` | – | 172 automatisierte Tests |
| Python | 3.10+ | – | `match`-Statement, `X | Y` Types |

---

## 5. Projektstruktur

```
nhi-discovery/
├── src/
│   ├── __init__.py
│   ├── discovery.py            # IAM-Scanning (AWS-Zugriff)
│   ├── cloudtrail_analyzer.py  # CloudTrail-Analyse + Anomalie-Erkennung
│   ├── iac_scanner.py          # Terraform/IaC-Sicherheitsanalyse
│   ├── risk_scoring.py         # CVSS-Scoring-Engine (Kernmodul)
│   ├── database.py             # SQLite-Persistenz
│   ├── cli.py                  # Click CLI (Einstiegspunkt)
│   └── dashboard.py            # Streamlit-Dashboard
│
├── tests/
│   ├── conftest.py             # Pytest-Fixtures (Mock-NHIs, Events)
│   ├── test_risk_scoring.py    # 85 Tests – Scoring-Engine
│   ├── test_cloudtrail_analyzer.py  # 46 Tests – CloudTrail-Modul
│   ├── test_iac_scanner.py     # 41 Tests – IaC-Scanner
│   └── fixtures/
│       ├── mock_iam_data.json          # 6 NHIs mit unterschiedlichen Profilen
│       ├── mock_cloudtrail_events.json # 10 Events (normal + verdächtig)
│       └── sample.tf                   # Terraform mit absichtlichen Problemen
│
├── docs/
│   ├── risk_model.md     # Wissenschaftliche Scoring-Dokumentation
│   └── architecture.md   # Diese Datei
│
├── data/                 # Auto-generiert: SQLite-DB + Exporte
├── config.yaml           # Konfiguration (Schwellwerte, Risk-Level-Grenzen)
├── requirements.txt      # Python-Dependencies
└── README.md
```

---

## 6. Deployment und Nutzung

### Voraussetzungen

- Python 3.10 oder neuer
- AWS-Credentials (für echte Scans): `aws configure` oder IAM Role
- Terraform (optional, nur für IaC-Scans nötig – das Tool analysiert nur `.tf` Dateien)

### Installation

```bash
git clone <repo-url>
cd nhi-discovery
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Minimale IAM-Berechtigungen für echte Scans

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "NHIDiscoveryReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",          "iam:ListRoles",
        "iam:GetUser",            "iam:GetRole",
        "iam:ListAccessKeys",     "iam:GetAccessKeyLastUsed",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudTrailReadOnly",
      "Effect": "Allow",
      "Action": ["cloudtrail:LookupEvents"],
      "Resource": "*"
    }
  ]
}
```

### Typischer Workflow

```bash
# 1. Demo-Scan ohne AWS-Credentials
python -m src.cli scan --mock

# 2. Score-Breakdown für ein einzelnes NHI
python -m src.cli explain svc-old-backup

# 3. Echter Scan mit CloudTrail-Analyse
python -m src.cli scan --deep --account 123456789012

# 4. Terraform-Repository analysieren
python -m src.cli scan --mock --iac ./terraform/

# 5. Report des letzten Scans
python -m src.cli report --verbose

# 6. Dashboard starten
streamlit run src/dashboard.py

# 7. Alle Tests ausführen
python -m pytest tests/ -v --tb=short
```

### Scan-Modi

| Modus | Command | AWS-Zugriff | Dauer |
|-------|---------|-------------|-------|
| Demo | `scan --mock` | Nein | < 1s |
| Standard | `scan` | IAM only | ~10s |
| Deep | `scan --deep` | IAM + CloudTrail | ~30s |
| IaC | `scan --iac PATH` | Nein (nur Dateien) | < 5s |
| Kombiniert | `scan --deep --iac ./tf` | IAM + CT | ~35s |
