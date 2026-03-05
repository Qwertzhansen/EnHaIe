# NHI Risk Scoring Model – Wissenschaftliche Dokumentation

## 1. Motivation und Einordnung

Non-Human Identities (NHIs) stellen in modernen Cloud-Umgebungen eine erhebliche Angriffsfläche dar. Im Gegensatz zu menschlichen Benutzern unterliegen sie selten Rotation, Multi-Faktor-Authentifizierung oder regelmäßiger Überprüfung. Eine wissenschaftlich fundierte Risikobewertung muss zwei Dimensionen unterscheiden:

1. **Likelihood**: Wie wahrscheinlich ist eine erfolgreiche Kompromittierung?
2. **Impact**: Welcher Schaden entsteht bei erfolgreicher Kompromittierung?

Dieses Modell adaptiert die Grundprinzipien von **CVSS 3.1** (Common Vulnerability Scoring System, FIRST 2019) für den NHI-Kontext. CVSS wurde gewählt, weil es (a) industriestandard-konform, (b) transparent und reproduzierbar, und (c) methodisch in der Literatur gut begründet ist (Mell et al., 2006; Spring et al., 2021).

---

## 2. Formel

```
RISK_SCORE = round( sqrt(LIKELIHOOD × IMPACT) × 100 )
```

### Begründung: Geometrisches Mittel statt Additiv

Das **geometrische Mittel** `sqrt(L × I)` wurde einer einfachen additiven Formel `(L + I) / 2 × 100` vorgezogen, weil:

| Eigenschaft | Additiv | Geometrisch (gewählt) |
|-------------|---------|----------------------|
| Hoher Score ohne Impact | möglich | unmöglich |
| Hoher Score ohne Likelihood | möglich | unmöglich |
| Entspricht CVSS-Philosophie | nein | ja |
| Strafe für extreme Asymmetrie | keine | ja (sqrt dämpft) |

**Beispiel**: L=0.9, I=0.1 (sehr exponiert, aber isoliert)
- Additiv: (0.9 + 0.1)/2 × 100 = 50 (MEDIUM) → überschätzt
- Geometrisch: sqrt(0.9 × 0.1) × 100 = 30 (LOW) → korrekt

Diese Eigenschaft entspricht dem CVSS 3.1-Prinzip, dass `BaseScore = Roundup(Minimum[(Impact + Exploitability), 10])` die Interaktion beider Dimensionen berücksichtigt.

### Skalierung

| Level    | Score  | Bedingung (sqrt(L×I)) | L×I Minimum |
|----------|--------|----------------------|-------------|
| CRITICAL | ≥ 80   | ≥ 0.80               | ≥ 0.64      |
| HIGH     | ≥ 60   | ≥ 0.60               | ≥ 0.36      |
| MEDIUM   | ≥ 40   | ≥ 0.40               | ≥ 0.16      |
| LOW      | < 40   | < 0.40               | < 0.16      |

---

## 3. LIKELIHOOD-Dimension (0.0 – 1.0)

Likelihood misst, wie wahrscheinlich eine erfolgreiche Angreifer-Exploitation ist. Sie setzt sich aus drei sub-additiven Komponenten zusammen (max. 0.9, da Attack Vector max 0.2 statt 0.3):

```
LIKELIHOOD = Exposure + Vulnerability + Attack_Vector
```

### 3.1 Exposure (0.0 – 0.4)

*Angelehnt an: CVSS Attack Complexity (AC)*

| Wert | Bedingung | Begründung |
|------|-----------|------------|
| 0.4  | Bekannt exponiert (CloudTrail: Zugriff von verdächtiger IP) | Aktiver Angriff läuft bereits |
| 0.2  | Potenziell exponiert (keine IP-Restriction-Condition) | Credential von überall verwendbar |
| 0.0  | Gut abgesichert (IP-Restrictions vorhanden) | Angreifer braucht Netzwerkzugang |

**Begründung für Maximalwert 0.4**: Exposure ist die wichtigste Vorbedingung für Likelihood. Ein bereits kompromittiertes Credential ist 2× gewichtiger als ein potenziell exponierbares.

**Datenquelle**: CloudTrail `LookupEvents` API (mit `suspicious_activity_flag`) sowie IAM Policy Condition-Analyse.

### 3.2 Vulnerability (0.0 – 0.3)

*Angelehnt an: CVSS User Interaction (UI) und CVSS Scope (S)*

| Wert | Bedingung | Begründung |
|------|-----------|------------|
| 0.3  | Key nie rotiert UND älter als 365 Tage | Credential langfristig kompromittierbar |
| 0.2  | Key nie rotiert ODER älter als 365 Tage | Eine Rotationsanforderung verletzt |
| 0.1  | Key älter als 90 Tage | Best Practice (AWS empfiehlt 90 Tage) |
| 0.0  | Key frisch oder IAM Role (keine Credentials) | Kein Key-Rotations-Risiko |

**Begründung**: AWS empfiehlt eine maximale Key-Lebensdauer von 90 Tagen (AWS Security Best Practices, 2023). Langlebige, nie rotierte Keys entsprechen dem CVSS-Parameter "No User Interaction Required" – ein Angreifer kann sie zeitunabhängig nutzen.

**Hinweis für IAM Roles**: Roles verwenden temporäre Credentials via STS (max. 12h). Das Rotation-Risiko entfällt, daher Vulnerability = 0.0 für Roles.

### 3.3 Attack Vector (0.0 – 0.2)

*Angelehnt an: CVSS Attack Vector (AV) und Privileges Required (PR)*

| Wert | Bedingung | Begründung |
|------|-----------|------------|
| 0.2  | Keine MFA-Condition und keine IP-Restriction | Credential von überall, ohne Zusatzfaktor |
| 0.1  | Nur eine der Bedingungen aktiv | Partial-Schutz, kombinierter Angriff möglich |
| 0.0  | MFA UND IP-Restriction vorhanden | Angreifer benötigt Netzwerkzugang UND physischen Faktor |

**Begründung**: NIST SP 800-63B empfiehlt Multi-Faktor-Authentifizierung für privilegierte Service Accounts. IAM Conditions reduzieren den Angriffsvektor von "Network" auf "Adjacent Network" im CVSS-Sinne.

---

## 4. IMPACT-Dimension (0.0 – 1.0)

Impact misst den maximalen Schaden nach einer erfolgreichen Kompromittierung. Summe aus drei Komponenten (max. 1.0):

```
IMPACT = Privilege_Level + Data_Sensitivity + Blast_Radius
```

### 4.1 Privilege Level (0.0 – 0.5)

*Angelehnt an: CVSS Confidentiality (C), Integrity (I), Availability (A) Impact*

| Wert | Policy-Kategorie | Begründung |
|------|-----------------|------------|
| 0.5  | AdministratorAccess, IAMFullAccess | Vollständige Kompromittierung aller CIA-Säulen |
| 0.3  | PowerUserAccess, *FullAccess | Hohe Service-Kontrolle, IAM eingeschränkt |
| 0.2  | Schreibrechte (ohne Full Access) | Integrity-Kompromittierung möglich |
| 0.05 | Leserechte | Nur Confidentiality-Risiko |
| 0.0  | Keine Policies | Kein direkter Schaden durch dieses NHI |

**Begründung für Maximalwert 0.5**: Privilege Level ist die gewichtigste Impact-Komponente, da `AdministratorAccess` die komplette AWS-Account-Kontrolle erlaubt (CVSS: C:H/I:H/A:H → Impact Score 5.9 von maximal 6.0).

### 4.2 Data Sensitivity (0.0 – 0.3)

*Angelehnt an: CVSS Confidentiality Impact (C)*

| Wert | Service-Zugriff | Begründung |
|------|----------------|------------|
| 0.3  | Secrets Manager, KMS, RDS | Schlüsselmaterial und Datenbankpasswörter direkt abrufbar |
| 0.2  | S3 | Potenziell PII, regulierte Daten (DSGVO-relevant) |
| 0.1  | CloudWatch, CloudTrail | Logs können Credentials, Tokens enthalten |
| 0.0  | Kein sensibles Service | Keine direkte Datenkompromittierung |

**Begründung**: AWS Macie klassifiziert S3-Daten nach Sensitivität; Secrets Manager/KMS enthalten per Definition schützenswerte Daten (NIST SP 800-57, Empfehlung zur Schlüsselverwaltung).

### 4.3 Blast Radius (0.0 – 0.2)

*Angelehnt an: CVSS Scope (S:Changed)*

| Wert | Bedingung | Begründung |
|------|-----------|------------|
| +0.1 | Cross-Account-Zugriff in Trust Policy | Angriff kann Account-Grenzen überschreiten |
| +0.1 | IAM-Eskalation möglich (CreateUser/AttachPolicy etc.) | Angreifer kann neue privilegierte Identitäten erstellen |
| 0.0  | Isoliert | Kein Scope:Changed im CVSS-Sinne |

**Begründung**: CVSS definiert `Scope:Changed` als Situation, in der eine Kompromittierung die Sicherheitsgrenzen der ursprünglichen Komponente überschreitet. Cross-Account-Zugriff und IAM-Eskalation sind die AWS-spezifischen Manifestationen dieses Konzepts (MITRE ATT&CK: TA0004 Privilege Escalation, T1098 Account Manipulation).

---

## 5. Vollständige Beispielberechnungen

Die folgenden vier Beispiele decken alle Risk Levels ab und demonstrieren die Sensitivität des Modells gegenüber Konfigurationsänderungen.

### Beispiel 1: LOW (Score 0) – Gut abgesicherte Lambda-Rolle

```
NHI:     role-lambda-processor  (IAM_ROLE)
Policies: AmazonSQSFullAccess
Trust Policy: Principal=lambda.amazonaws.com, Condition=aws:SourceAccount

LIKELIHOOD:
  Exposure      = 0.0  → IP-/Source-Condition in Trust Policy vorhanden
  Vulnerability = 0.0  → IAM Role: keine permanenten Access Keys
  Attack Vector = 0.0  → Condition in Trust Policy zählt als Schutz
  ─────────────────────────────────────────────────────
  L = min(1.0, 0.0 + 0.0 + 0.0) = 0.00

IMPACT:
  Privilege Level  = 0.3  → SQSFullAccess (∈ *FullAccess-Muster)
  Data Sensitivity = 0.0  → SQS: kein direkter Datenzugriff
  Blast Radius     = 0.0  → Service-Principal, kein Cross-Account
  ─────────────────────────────────────────────────────
  I = min(1.0, 0.3 + 0.0 + 0.0) = 0.30

RISK_SCORE = round(sqrt(0.00 × 0.30) × 100) = round(0.000 × 100) = 0
RISK_LEVEL = LOW  ✓

Interpretation: Wenn Likelihood = 0 (korrekte Absicherung), ist der Score
immer 0 – unabhängig vom Impact. Das Modell belohnt korrekte Konfiguration
und vermeidet damit das Problem additiver Modelle, die auch bei L=0 Score
vergeben könnten.
```

---

### Beispiel 2: MEDIUM (Score 50) – Unkonfigurierter CI/CD Service Account

```
NHI:     svc-deployment  (IAM_USER)
Policies: AmazonS3FullAccess, AmazonEC2FullAccess
Access Key: 95 Tage alt, aktiv
Keine IP-Restriction, kein MFA

LIKELIHOOD:
  Exposure      = 0.2  → keine IP-Restriction in User-Policies
  Vulnerability = 0.1  → Key 95d alt, Warnung-Threshold 90d überschritten
                          (key_age < 365 und nicht als "nie rotiert" klassifiziert,
                           da 95 < 180 × 0.9 = 162 → Tolleranzbereich: rotiert)
  Attack Vector = 0.2  → weder MFA- noch IP-Condition aktiv
  ─────────────────────────────────────────────────────
  L = min(1.0, 0.2 + 0.1 + 0.2) = 0.50

IMPACT:
  Privilege Level  = 0.3  → S3FullAccess + EC2FullAccess (∈ *FullAccess)
  Data Sensitivity = 0.2  → S3-Zugriff: potenziell PII/regulierte Daten
  Blast Radius     = 0.0  → kein Cross-Account, kein IAM-Write
  ─────────────────────────────────────────────────────
  I = min(1.0, 0.3 + 0.2 + 0.0) = 0.50

RISK_SCORE = round(sqrt(0.50 × 0.50) × 100) = round(0.500 × 100) = 50
RISK_LEVEL = MEDIUM  ✓

Empfehlungen:
→ [HOCH]   S3FullAccess + EC2FullAccess durch spezifischere Policies ersetzen
→ [MITTEL] Access Key rotieren (95 Tage alt, Warnschwelle 90 Tage)
→ [MITTEL] IP-Condition für CI/CD-Server-IP-Ranges hinzufügen
```

---

### Beispiel 3: HIGH (Score 65) – Alter Admin-Account, nie rotiert

```
NHI:     svc-old-backup  (IAM_USER)
Policies: AdministratorAccess
Access Key: 400 Tage alt, aktiv, nie rotiert (key_age ≥ user_age × 0.9)
Keine IP-Restriction, kein MFA, kein CloudTrail-Verdacht

LIKELIHOOD:
  Exposure      = 0.2  → kein suspicious_activity_flag; keine IP-Restriction
  Vulnerability = 0.3  → Key 400d (≥ 365) UND nie rotiert: 400 ≥ 400×0.9=360
                          → beide Bedingungen erfüllt → Maximum
  Attack Vector = 0.2  → keine MFA, keine IP-Condition
  ─────────────────────────────────────────────────────
  L = min(1.0, 0.2 + 0.3 + 0.2) = 0.70

IMPACT:
  Privilege Level  = 0.5  → AdministratorAccess (volle Kontrolle, CIA:H/H/H)
  Data Sensitivity = 0.0  → kein expliziter Secrets/S3-Zugriff in Policy-Name
  Blast Radius     = 0.1  → IAM-Eskalation: AdminAccess erlaubt CreateUser etc.
                             (kein Cross-Account-Trust)
  ─────────────────────────────────────────────────────
  I = min(1.0, 0.5 + 0.0 + 0.1) = 0.60

RISK_SCORE = round(sqrt(0.70 × 0.60) × 100) = round(sqrt(0.42) × 100)
           = round(0.648 × 100) = 65
RISK_LEVEL = HIGH  ✓

Sensitivitätsanalyse: Würde IP-Restriction hinzugefügt, sänke Exposure auf 0.0,
Likelihood auf 0.5, Score auf round(sqrt(0.5×0.6)×100) = 55 → MEDIUM.
→ Eine IAM-Condition allein senkt das Risk Level um eine Stufe.
```

---

### Beispiel 4: CRITICAL (Score 95) – Kompromittierter Admin mit Secrets-Zugriff

```
NHI:     svc-compromised  (IAM_USER)
Policies: AdministratorAccess, SecretsManagerReadWrite
Access Key: 500 Tage alt, aktiv, nie rotiert
CloudTrail: Zugriff von externer IP 203.0.113.42 um 03:17 UTC erkannt
            → suspicious_activity_flag = True (gesetzt durch cloudtrail_analyzer.py)
Trust Policy: Principal=AWS:arn:aws:iam::999999999999:root (Cross-Account, kein Condition)

LIKELIHOOD:
  Exposure      = 0.4  → suspicious_activity_flag gesetzt: bekannte Exposition
  Vulnerability = 0.3  → Key 500d (≥ 365) UND nie rotiert: 500 ≥ 500×0.9=450
  Attack Vector = 0.2  → keine MFA, keine Condition in Trust Policy
  ─────────────────────────────────────────────────────
  L = min(1.0, 0.4 + 0.3 + 0.2) = 0.90

IMPACT:
  Privilege Level  = 0.5  → AdministratorAccess (vollständige Account-Kontrolle)
  Data Sensitivity = 0.3  → SecretsManagerReadWrite: direkter Zugriff auf
                             Schlüsselmaterial und Credentials
  Blast Radius     = 0.2  → Cross-Account +0.1 (externes Principal)
                           + IAM-Eskalation +0.1 (AdminAccess)
  ─────────────────────────────────────────────────────
  I = min(1.0, 0.5 + 0.3 + 0.2) = 1.00

RISK_SCORE = round(sqrt(0.90 × 1.00) × 100) = round(sqrt(0.90) × 100)
           = round(0.9487 × 100) = 95
RISK_LEVEL = CRITICAL  ✓

Vergleich mit Beispiel 3 (gleiche Likelihood = 0.9, andere Policies):
  Ohne Secrets + ohne Cross-Account:  I=0.6  → Score=79 (HIGH, knapp verfehlt)
  Mit Secrets + mit Cross-Account:    I=1.0  → Score=95 (CRITICAL)
  → Der Unterschied liegt ausschließlich in der Impact-Dimension.

Empfehlungen (priorisiert nach Schweregrad):
→ [KRITISCH] Credentials sofort sperren und rotieren – aktiver Angriff wahrscheinlich
→ [KRITISCH] AdministratorAccess entfernen (Principle of Least Privilege)
→ [KRITISCH] SecretsManagerReadWrite auf spezifische Secret-ARNs einschränken
→ [KRITISCH] Cross-Account Trust Policy sofort widerrufen
→ [HOCH]    Security Incident Response-Prozess einleiten (SIEM, Forensik)
→ [HOCH]    Alle von diesem NHI zugreifbaren Secrets rotieren
```

---

## 6. Limitationen des Modells

### 6.1 Statische Policy-Analyse
Das Modell analysiert **zugewiesene** IAM-Policies, nicht die tatsächlich genutzten Berechtigungen. Ein NHI mit `AdministratorAccess` erhält hohen Impact, auch wenn es nur S3-APIs nutzt. AWS IAM Access Analyzer oder der IAM Credentials Report könnten dies verfeinern.

### 6.2 CloudTrail-Abhängigkeit für Exposition
Die Exposure-Bewertung auf 0.4 ("bekannte Exposition") setzt CloudTrail voraus. Ohne CloudTrail ist der maximale Exposure-Wert 0.2. In Accounts ohne CloudTrail ist das Modell konservativ (unterschätzt potenziell die Exposition).

### 6.3 Kein zeitlicher Kontext bei Policies
AdministratorAccess, das seit 5 Jahren besteht, wird identisch bewertet wie AdministratorAccess, das vor einem Tag zugewiesen wurde. Ein zeitgewichteter Impact wäre wissenschaftlich interessant, sprengt aber den Scope dieses Tools.

### 6.4 Keine Inline-Policy-Analyse
Nur `AWS managed policies` (bekannte Policy-Namen) werden kategorisiert. Custom/Inline-Policies werden nicht analysiert – dies würde das Parsen von IAM Policy Documents erfordern (Erweiterungsmöglichkeit für zukünftige Versionen).

### 6.5 Vereinfachter "nie rotiert"-Proxy
"Nie rotiert" wird über `key_age ≈ user_age × 0.9` approximiert. In seltenen Fällen (Key kurz nach Erstellung des Users angelegt) kann dies falsch-positiv sein.

---

## 7. Referenzen

- FIRST (2019). *CVSS v3.1 Specification Document*. https://www.first.org/cvss/v3-1/cvss-v3-1-specification.pdf
- Mell, P., Scarfone, K., Romanosky, S. (2006). *A Complete Guide to the Common Vulnerability Scoring System Version 2.0*. NIST.
- Spring, J., et al. (2021). *Time to Change the CVSS*. Proceedings of the IEEE European Symposium on Security and Privacy Workshops.
- AWS (2023). *Security best practices in IAM*. https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- NIST (2017). *SP 800-63B: Digital Identity Guidelines – Authentication and Lifecycle Management*.
- MITRE ATT&CK (2024). *Cloud Matrix – TA0004: Privilege Escalation*. https://attack.mitre.org/tactics/TA0004/
