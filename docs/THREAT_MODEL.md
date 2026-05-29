# Threat Model

## Scope
WinSecLite is a defensive local endpoint scanner that complements Microsoft Defender.

## Out of scope
- Exploitation
- Credential extraction
- Stealth
- Kernel-mode tamper protection
- Packet sniffing
- Automatic destructive remediation

## Main risks
- False positives causing disruption
- Quarantine of critical files
- Malicious files crashing scanner
- Signature update tampering
- Logs leaking sensitive paths
- Running elevated longer than necessary

## Mitigations
- Scoring-based detection
- Known-good allowlists
- File size/time limits
- Signed updates in future phase
- Local-only logs by default
- Read-only scanners by default
- User confirmation for remediation
