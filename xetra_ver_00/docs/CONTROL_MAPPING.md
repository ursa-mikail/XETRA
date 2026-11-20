# Control Mapping

Each TTP library entry's `stratum` maps to certification-framework controls as follows. Use this to cross-walk an ATTEST evidence package to your auditor's sampling request.

| Stratum | SOC2 | ISO 27001 | PCI DSS v4.0 | NIST CSF 2.0 | FedRAMP (SP 800-53) | NYDFS §500 | NY MTL |
|---|---|---|---|---|---|---|---|
| infra_network | CC6.1, CC6.6 | A.8.9, A.8.20, A.8.22 | Req. 1, 11.3 | ID.AM, PR.IR | CA-7, SC-7, RA-5 | §500.9, §500.14 | via §500 incorporation |
| service | CC7.1, CC8.1 | A.8.25, A.8.28, A.8.29 | Req. 6, 6.4.1-6.4.2 | PR.PS, DE.CM | SA-11, RA-5, SI-10 | §500.8 | via §500 incorporation |
| system | CC6.1, CC6.2, CC6.3 | A.8.1, A.5.17, A.8.5 | Req. 2, 7-8 | PR.AA, ID.AM | AC-2, IA-2/IA-5, CM-6 | §500.7, §500.12 | via §500 incorporation |
| protocol | CC6.7 | A.8.24, A.8.20 | Req. 4 | PR.DS, PR.IR | SC-8, SC-13 | §500.15 | via §500 incorporation |
| algorithm | CC6.1, CC6.7 | A.8.24 | Req. 3, 4 | PR.DS | SC-12, SC-13 | §500.15 | via §500 incorporation |
| software | CC8.1 | A.8.25, A.8.28, A.8.31 | Req. 6.3 | PR.PS, ID.RA | SA-11, SA-15 | §500.8 | via §500 incorporation |
| hardware | CC6.4, CC6.1 | A.7, A.8.1 | Req. 9, 3.5 | PR.PS, ID.SC | PE family, SR family | §500.9 | via §500 incorporation |

See the companion **Security Assurance Scanning Manual** for the full tool-by-tool evidence breakdown this project automates.
