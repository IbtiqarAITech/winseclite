from __future__ import annotations
import psutil
from winseclite.core.models import Detection, ObjectType
from winseclite.core.risk_score import severity_from_score

SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337}


class NetworkScanner:
    """Lightweight network scanner. No packet sniffing."""

    def scan(self) -> list[Detection]:
        detections: list[Detection] = []
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:
                continue
            remote = f"{conn.raddr.ip}:{conn.raddr.port}"
            if conn.raddr.port in SUSPICIOUS_PORTS:
                score = 25
                detections.append(Detection(ObjectType.NETWORK, remote, score, severity_from_score(score),
                                            f"Connection uses commonly suspicious port {conn.raddr.port}",
                                            "Review owning process and destination reputation.",
                                            rule_name="network_connection_heuristics",
                                            metadata={"pid": conn.pid, "status": conn.status}))
        return detections
