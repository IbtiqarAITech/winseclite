# Codex instructions for WinSecLite

You are working on WinSecLite, a defensive-only Windows security scanner.

Hard safety constraints:
- Do not add offensive capabilities.
- Do not add stealth, evasion, credential theft, exploitation, ransomware, or destructive behavior.
- Prefer read-only scanners.
- Remediation must require explicit user approval.
- Never disable Microsoft Defender.
- Use quarantine before deletion.
- Avoid collecting secrets or private browser contents.

Engineering standards:
- Python 3.12+
- Small testable modules
- Unit tests for scanners/detection rules
- Graceful handling for AccessDenied/OSError
- No blocking GUI thread
- Explainable detection evidence
- False-positive reduction through scoring and allowlists

Immediate tasks:
1. Improve file scanner progress streaming.
2. Add Authenticode verification helper.
3. Add GUI background worker for quick scan.
4. Add detections table in PySide6.
5. Add signed update manifest format for rules.
