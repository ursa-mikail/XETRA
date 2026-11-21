"""
XETRA — eXtended Threat Evasion-Resilience & Takedown Architecture

The structural inverse of ARTEX (FBI FLASH-20261113-001).
ARTEX, reversed, is XETRA. Where ARTEX is an autonomous offensive agent
swarm, XETRA is an autonomous *validation* agent swarm: it runs the same
ATT&CK-mapped technique catalog against licensed, authorized testing
platforms on a continuous loop, and proves — with evidence — that each
technique is detected, contained, and recoverable.

XETRA does not attack anything. It orchestrates licensed BAS/SIEM/SOAR/EDR
products you already own, pointed only at scope you configure and sign off
on. See README.md and config/config.example.yaml before running anything
in `mode: live`.
"""

__version__ = "0.2.0"
