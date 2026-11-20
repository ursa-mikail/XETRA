# Security Assurance Scanning Manual

### 7-Strata Evidence Collection for Certification: SOC 2 · ISO/IEC 27001 · PCI DSS v4.0 · NIST CSF 2.0 · FedRAMP · NYDFS 23 NYCRR 500 · NY Money Transmitter Law

**Purpose:** a repeatable, auditor-defensible scanning program using named, licensed, commercially/open-source-supported tools, organized by the corrected 7-strata model (attack-surface order), with each layer's output mapped to the specific evidence each certification framework requires. Every tool below has a documented license, vendor support path, and audit trail — a hard requirement for evidentiary admissibility under every framework listed; tools lacking that provenance (ARTEX included) are excluded on that basis alone, independent of any other concern.

**Program prerequisites (apply to every stratum):**

- Signed Rules of Engagement / scope authorization before any active scan
- Scan tool version + plugin/signature-date logged per run (evidence of currency)
- Chain of custody: raw scan output hashed and stored immutably (WORM/object-lock) before remediation begins
- Finding → ticket → remediation → re-scan loop closed and timestamped for every result

---

## Framework Shorthand Used in Tables

`SOC2` (Trust Services Criteria) · `ISO` (27001:2022 Annex A) · `PCI` (DSS v4.0 Req. #) · `CSF` (NIST CSF 2.0 Function.Category) · `FedRAMP` (NIST SP 800-53 control family) · `NYDFS` (23 NYCRR 500 §) · `NYMTL` (NY Dept. of Financial Services Money Transmitter supervisory guidance, which incorporates NYDFS §500 cybersecurity requirements for licensees)

---

## Stratum 1 — Infrastructure / Network

**Scope:** cloud account perimeter, VPC/subnet design, routing, VPN/remote access, CDN/edge, ASN exposure.

| Activity | Tool | Evidence Artifact |
| --- | --- | --- |
| External attack-surface discovery | **Shodan Enterprise**, **Censys Search**, **Amass** (OWASP) | Asset inventory diff report, timestamped |
| Authenticated cloud config audit | **Prowler** (AWS/Azure/GCP, open-source, CIS-benchmark aligned), **ScoutSuite** | CIS Benchmark compliance score + raw findings JSON |
| Network vulnerability scanning | **Tenable Nessus**, **Qualys VMDR**, **Rapid7 InsightVM** | Scan report w/ CVSS, scan-policy export |
| Cloud IAM permission analysis | **AWS IAM Access Analyzer**, **Azure AD Permissions Management** | Least-privilege gap report |
| External-facing cert/TLS hygiene | **testssl.sh**, **SSL Labs API** | Protocol/cipher compliance report |

| Control Mapping | Reference |
| --- | --- |
| SOC2 | CC6.1 (logical access to network), CC6.6 (boundary protection) |
| ISO | A.8.9 (config mgmt), A.8.20 (network security), A.8.22 (segregation) |
| PCI | Req. 1 (network security controls), Req. 11.3 (external/internal scanning) |
| CSF | ID.AM (Asset Mgmt), PR.IR (Infrastructure Resilience) |
| FedRAMP | CA-7 (continuous monitoring), SC-7 (boundary protection), RA-5 (vuln scanning) |
| NYDFS | §500.9 (risk assessment), §500.14 (monitoring) |
| NYMTL | Incorporates §500 network-perimeter control expectations for licensee IT infra |

---

## Stratum 2 — Service (Application / API / Database)

**Scope:** web apps, REST/GraphQL APIs, DBs, mail, CI/CD, partner/employee portals, SaaS integrations.

| Activity | Tool | Evidence Artifact |
| --- | --- | --- |
| DAST (web app) | **Burp Suite Enterprise**, **OWASP ZAP** | Vuln report mapped to OWASP Top 10 |
| SAST | **SonarQube**, **Checkmarx**, **Semgrep** | Code-scan report w/ severity, suppressions justified |
| API security testing | **42Crunch**, **Postman** + custom contract tests | Schema-conformance + authz test report |
| Dependency / SCA | **Snyk**, **OWASP Dependency-Check**, **GitHub Dependabot** | SBOM + CVE-matched dependency report |
| Database config audit | **DBProtect**, native CIS benchmarks (via **Prowler**/**CIS-CAT**) | DB hardening compliance score |
| Secrets-in-repo scanning | **GitGuardian**, **TruffleHog** | Exposed-secret findings + remediation timestamp |

| Control Mapping | Reference |
| --- | --- |
| SOC2 | CC7.1 (detection of vulnerabilities), CC8.1 (change management) |
| ISO | A.8.25 (secure development lifecycle), A.8.28 (secure coding), A.8.29 (security testing) |
| PCI | Req. 6 (develop/maintain secure systems), Req. 6.4.1-6.4.2 (public-facing app protection) |
| CSF | PR.PS (Platform Security), DE.CM (Continuous Monitoring) |
| FedRAMP | SA-11 (developer testing), RA-5, SI-10 (input validation) |
| NYDFS | §500.8 (application security) |
| NYMTL | Application-security expectations for payment/transfer-handling systems |

---

## Stratum 3 — System (OS / Identity / Endpoint)

**Scope:** OS patch level, kernel, filesystem permissions, AD/identity store, endpoint configuration, EDR coverage.

| Activity | Tool | Evidence Artifact |
| --- | --- | --- |
| OS vulnerability/patch scanning | **Nessus**, **Qualys**, **Microsoft Defender Vulnerability Management** | Patch-compliance report |
| AD security assessment | **Microsoft's PingCastle**, **BloodHound Enterprise** (licensed/commercial mode), **Purple Knight** | AD attack-path and exposure report |
| EDR coverage validation | **CrowdStrike Falcon** sensor-coverage report, **Microsoft Defender for Endpoint** inventory | Sensor-coverage gap report (% hosts unmonitored) |
| Configuration baseline audit | **CIS-CAT Pro**, **Microsoft Security Compliance Toolkit** | CIS Benchmark score per host class |
| Credential hygiene | **Microsoft LAPS** audit export, **Specops Password Auditor** | Weak/reused credential report |

| Control Mapping | Reference |
| --- | --- |
| SOC2 | CC6.1, CC6.2 (user access provisioning), CC6.3 (access removal) |
| ISO | A.8.1 (endpoint devices), A.5.17 (authentication info), A.8.5 (secure authentication) |
| PCI | Req. 2 (secure configurations), Req. 7-8 (access control/identity) |
| CSF | PR.AA (Identity Mgmt/AuthN), ID.AM |
| FedRAMP | AC-2 (account mgmt), IA-2/IA-5 (identification/authenticator mgmt), CM-6 (config settings) |
| NYDFS | §500.7 (access privileges), §500.12 (MFA) |
| NYMTL | Identity/access controls for systems handling customer funds transfer |

---

## Stratum 4 — Protocol-Level Controls (threaded through every layer above)

Rather than a standalone scan, protocol hygiene is validated *within* each stratum's scan: TLS/cipher checks at Stratum 1, SAML/OAuth/OIDC token validation at Stratum 2, Kerberos/SMB/LDAP hygiene at Stratum 3.

| Activity | Tool | Evidence Artifact |
| --- | --- | --- |
| SAML/OAuth config review | **SAML Raider** (Burp extension, authorized use), manual IdP metadata review | Token-signing/validation compliance report |
| SMB/Kerberos hygiene | **PingCastle**, native AD auditing (`Get-SmbServerConfiguration`, event log export) | SMB-signing enforcement + Kerberoasting-exposure report |
| DNS security posture | **dnsrecon**, registrar DNSSEC validation | DNS hardening report |

| Control Mapping | Reference |
| --- | --- |
| SOC2 | CC6.7 (data transmission controls) |
| ISO | A.8.24 (cryptography use), A.8.20 (network security) |
| PCI | Req. 4 (protect data in transit) |
| CSF | PR.DS (Data Security), PR.IR |
| FedRAMP | SC-8 (transmission confidentiality/integrity), SC-13 (crypto protection) |
| NYDFS | §500.15 (encryption) |
| NYMTL | Transmission-security requirements for funds-transfer messaging |

---

## Stratum 5 — Algorithm (Crypto & Business Logic)

**Scope:** crypto primitive strength, key management, RNG quality, authorization/business-logic correctness.

| Activity | Tool | Evidence Artifact |
| --- | --- | --- |
| Crypto-agility inventory | **cryptosense** (commercial), manual config review against **NIST SP 800-131A** | Algorithm/key-length inventory vs. approved list |
| Key management audit | **HashiCorp Vault** audit logs, **AWS KMS**/**Azure Key Vault** access reports | Key-rotation and access-control evidence |
| Business-logic test | Manual/authorized threat-modeling session + targeted test cases (not automatable) | Logic-flaw test case results, signed off by app owner |

| Control Mapping | Reference |
| --- | --- |
| SOC2 | CC6.1, CC6.7 |
| ISO | A.8.24 (cryptography) |
| PCI | Req. 3 (protect stored account data), Req. 4 |
| CSF | PR.DS |
| FedRAMP | SC-12 (key management), SC-13 |
| NYDFS | §500.15 |
| NYMTL | Encryption-standard requirements for stored/transmitted customer financial data |

---

## Stratum 6 — Software / Language

**Scope:** source code, memory safety, build toolchain, deserialization/parsing logic.

(Covered jointly with SAST/SCA tooling under Stratum 2 — the program treats "service" and "software/language" evidence as one combined code-security workstream, since certification auditors generally expect a single SDLC evidence package rather than two.)

| Additional Activity | Tool | Evidence Artifact |
| --- | --- | --- |
| Fuzzing (critical parsers) | **OSS-Fuzz** (for OSS components), **AFL++** (internal, authorized use only) | Crash/triage report |
| Build-pipeline integrity | **Sigstore/cosign** (artifact signing), **SLSA** provenance attestation | Signed-build + provenance evidence chain |

| Control Mapping | Reference |
| --- | --- |
| SOC2 | CC8.1 |
| ISO | A.8.25, A.8.28, A.8.31 (separation of environments) |
| PCI | Req. 6.3 (vulnerability identification/addressing) |
| CSF | PR.PS, ID.RA |
| FedRAMP | SA-11, SA-15 (development process/tools) |
| NYDFS | §500.8 |
| NYMTL | — (inherits §500.8 via NYDFS incorporation) |

---

## Stratum 7 — Hardware

**Scope:** firmware/UEFI, TPM/HSM, physical devices, supply-chain provenance.

| Activity | Tool | Evidence Artifact |
| --- | --- | --- |
| Firmware integrity / attestation | **Microsoft Defender Firmware Protection**, **Eclypsium** (commercial platform) | Firmware-hash baseline comparison report |
| HSM/TPM validation | Vendor attestation tools (e.g., **Thales Luna HSM** audit logs, **TPM 2.0** quote verification) | Attestation-pass/fail log |
| Hardware supply-chain provenance | Vendor-provided **SBOM for hardware** (per NIST guidance), chain-of-custody documentation | Procurement provenance file |

| Control Mapping | Reference |
| --- | --- |
| SOC2 | CC6.4 (physical access), CC6.1 |
| ISO | A.7 (physical controls), A.8.1 |
| PCI | Req. 9 (restrict physical access), Req. 3.5 (crypto hardware) |
| CSF | PR.PS, ID.SC (Supply Chain) |
| FedRAMP | PE (physical/environmental family), SR (supply chain risk mgmt family) |
| NYDFS | §500.9 (risk assessment covers physical/supply-chain risk) |
| NYMTL | Business-continuity/physical-security expectations for licensed money transmitters |

---

## Program Operating Cadence

| Framework | Typical required scan/assessment frequency |
| --- | --- |
| SOC2 (Type II) | Continuous monitoring over audit period (6–12 mo); vuln scans quarterly minimum, evidenced |
| ISO 27001 | Annual internal audit + surveillance audits; vuln scanning per risk-treatment plan (commonly quarterly) |
| PCI DSS v4.0 | External ASV scan quarterly (Req. 11.3.2); internal scans quarterly; penetration test annually + after significant change |
| NIST CSF 2.0 | No fixed cadence — organization-defined per risk tolerance; continuous monitoring expected under DE.CM |
| FedRAMP | Monthly vulnerability scanning (Low/Moderate), continuous monitoring per ConMon plan; annual assessment |
| NYDFS §500 | Annual penetration testing + biannual vulnerability assessment (§500.5) for non-exempt covered entities |
| NYMTL | Aligned to NYDFS §500 cadence where incorporated into licensee supervisory requirements |

---

## Evidence Package Assembly (per audit cycle)

1. Scan-tool inventory with license/version/signature-date proof
2. Raw findings (hashed, WORM-stored) per stratum
3. Control-mapping crosswalk (tables above) completed per finding
4. Remediation tickets with closure timestamps and re-scan confirmation
5. Management sign-off memo per cycle, referencing the specific framework clause satisfied
6. Residual-risk register for any finding accepted rather than remediated, with executive approval on record

This package structure is what satisfies an external auditor's sampling request under any of the frameworks above — the crosswalk tables let one evidence set serve multiple certifications simultaneously rather than running separate programs per standard.