"""
Cloud Infrastructure Security Auditor - Static Policy AST Analysis
Compliant with ISA 315 (General IT Controls over Access Security)
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger("TechRiskAuditEngine.CloudAuditor")


class CloudSecurityAuditEngine:
    """Performs static structural AST inspection on cloud IAM policies to detect least privilege violations."""

    def __init__(self, policy_payload: Dict[str, Any]):
        self.policy = policy_payload

    def inspect_policy_violations(self) -> List[Dict[str, Any]]:
        """Scans statements for dangerous wildcard permissions and unrestricted access grants."""
        violations = []
        statements = self.policy.get("Statement", [])
        logger.info(f"Analyzing {len(statements)} IAM Policy statements for security and compliance violations...")

        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                continue

            action = stmt.get("Action")
            principal = stmt.get("Principal")
            resource = stmt.get("Resource")
            sid = stmt.get("Sid", f"Statement_{idx}")

            # 1. Detect SuperAdmin Wildcard in Action
            has_action_wildcard = action == "*" or (isinstance(action, list) and "*" in action)

            # 2. Detect Unrestricted / Anonymous Public Access in Principal
            has_principal_wildcard = (
                principal == "*" or
                (isinstance(principal, dict) and principal.get("AWS") == "*") or
                (isinstance(principal, list) and "*" in principal)
            )

            if has_action_wildcard or has_principal_wildcard:
                vuln_types = []
                if has_action_wildcard:
                    vuln_types.append("SUPERADMIN_ACTION_WILDCARD")
                if has_principal_wildcard:
                    vuln_types.append("UNRESTRICTED_PUBLIC_PRINCIPAL")

                violations.append({
                    "statement_index": idx,
                    "sid": sid,
                    "vulnerability_types": vuln_types,
                    "violating_action": action,
                    "violating_principal": principal,
                    "target_resource": resource,
                    "raw_statement": stmt
                })

        logger.info(f"Policy inspection completed: Flagged {len(violations)} ITGC security violations.")
        return violations
