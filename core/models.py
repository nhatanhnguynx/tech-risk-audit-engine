"""
TechRisk Audit Engine - Data Contract & Domain Models
Compliant with ISA 230 (Audit Documentation) & ISA 315 (Revised 2019)
"""

from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ISAStandard(str, Enum):
    ISA_230 = "ISA 230: Audit Documentation"
    ISA_240 = "ISA 240.32: The Auditor's Responsibilities Relating to Fraud - Management Override of Controls"
    ISA_315 = "ISA 315 (Revised 2019): Identifying and Assessing the Risks of Material Misstatement through Understanding the IT Environment"


@dataclass
class AuditFinding:
    """Standardized Electronic Audit Finding Model compliant with ISA 230."""
    finding_id: str
    isa_standard: str
    risk_category: str
    severity: SeverityLevel
    timestamp: str
    entity_affected: str
    technical_evidence: Dict[str, Any]
    audit_implication: str
    recommended_substantive_action: str
    detected_by_module: str

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class AuditSessionSummary:
    """Audit Engagement Session Metadata and Aggregated Working Paper."""
    session_id: str
    execution_timestamp: str
    total_logs_analyzed: int
    log_processing_time_ms: float
    cloud_policies_evaluated: int
    findings_count: int
    critical_risk_count: int
    findings: List[AuditFinding] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "execution_timestamp": self.execution_timestamp,
            "audit_metrics": {
                "total_logs_analyzed": self.total_logs_analyzed,
                "log_processing_time_ms": round(self.log_processing_time_ms, 2),
                "cloud_policies_evaluated": self.cloud_policies_evaluated,
                "total_findings": self.findings_count,
                "critical_findings": self.critical_risk_count
            },
            "electronic_working_papers": [f.to_dict() for f in self.findings]
        }
