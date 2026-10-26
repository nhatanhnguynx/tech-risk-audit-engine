"""
Generative AI Domain Compiler - Automated Technical-to-Audit Translation Engine
Translates low-level Cloud Security JSON into formal ISA 315 Audit Risk Memoranda
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from core.models import AuditFinding, SeverityLevel, ISAStandard

logger = logging.getLogger("TechRiskAuditEngine.GenAICompiler")


class GenAIAuditCompiler:
    """Uses LLMs (Gemini) as a specialized Domain Compiler bridging Cloud DevOps and Financial Audit."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")

    def compile_cloud_violations(self, violations: List[Dict[str, Any]]) -> List[AuditFinding]:
        if not violations:
            return []

        logger.info(f"Synthesizing {len(violations)} technical cloud violations via GenAI Domain Compiler...")
        findings = []

        for v in violations:
            opinion = self._invoke_llm_or_fallback(v)
            is_critical = "SUPERADMIN_ACTION_WILDCARD" in v.get("vulnerability_types", [])

            finding = AuditFinding(
                finding_id=f"FIND-ITGC-CLOUD-{v['sid']}",
                isa_standard=ISAStandard.ISA_315.value,
                risk_category="General IT Controls (ITGC) / Cloud Identity & Access Governance",
                severity=SeverityLevel.CRITICAL if is_critical else SeverityLevel.HIGH,
                timestamp=datetime.now(timezone.utc).isoformat(),
                entity_affected="Cloud Infrastructure (AWS Production Tenant)",
                technical_evidence={
                    "statement_id": v["sid"],
                    "vulnerabilities": v["vulnerability_types"],
                    "target_resource": v["target_resource"],
                    "action_granted": v["violating_action"],
                    "principal_granted": v["violating_principal"]
                },
                audit_implication=opinion["audit_implication"],
                recommended_substantive_action=opinion["recommended_action"],
                detected_by_module="GenAIAuditCompiler.Gemini" if self.api_key else "GenAIAuditCompiler.DeterministicRule"
            )
            findings.append(finding)

        return findings

    def _invoke_llm_or_fallback(self, violation: Dict[str, Any]) -> Dict[str, str]:
        """Calls Google Gemini API or triggers deterministic audit risk fallback."""
        if not self.api_key:
            logger.warning("No GEMINI_API_KEY detected in environment. Triggering deterministic fallback rule...")
            return self._generate_simulated_audit_memorandum(violation)

        try:
            logger.info("Dispatching prompt to Google Gemini API (gemini-1.5-flash)...")
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel("gemini-1.5-flash")

            prompt = f"""
            You are a Senior Digital Forensic & Tech Risk Director at a Big 4 accounting firm.
            Translate the following technical AWS IAM Policy vulnerability into a formal Financial Audit Risk Assessment Memorandum
            strictly compliant with ISA 315 (Revised 2019) - General IT Controls (ITGC) and Risk of Material Misstatement (RMM).

            Technical Violation Details:
            - Policy Statement ID: {violation.get('sid')}
            - Vulnerability Class: {violation.get('vulnerability_types')}
            - Action Scope: {violation.get('violating_action')}
            - Principal Scope: {violation.get('violating_principal')}
            - Target Resource: {violation.get('target_resource')}

            RETURN STRICTLY A JSON OBJECT WITH TWO KEYS:
            {{
              "audit_implication": "<Detailed explanation of ITGC failure, segregation of duties breach, data integrity compromise, and RMM on financial statements>",
              "recommended_action": "<Specific substantive audit testing procedures and mandatory management remediation>"
            }}
            """

            response = model.generate_content(prompt)
            clean_text = response.text.strip().replace("```json", "").replace("```", "")
            data = json.loads(clean_text)
            logger.info("Successfully received and parsed structured AI audit risk opinion.")
            return {
                "audit_implication": data.get("audit_implication", ""),
                "recommended_action": data.get("recommended_action", "")
            }
        except Exception as exc:
            logger.error(f"Gemini API communication error: {str(exc)}. Falling back to deterministic rule synthesis.")
            return self._generate_simulated_audit_memorandum(violation)

    def _generate_simulated_audit_memorandum(self, violation: Dict[str, Any]) -> Dict[str, str]:
        sid = violation.get("sid")
        resource = violation.get("target_resource")
        
        implication = (
            f"Under ISA 315.A152, policy statement '{sid}' represents a material weakness in General IT Controls (ITGC). "
            f"Granting unrestricted wildcard access ('*') across financial resource '{resource}' bypasses access controls, "
            "allowing unauthorized personnel to alter or erase ledger entries without an audit trail. "
            "Consequently, the Risk of Material Misstatement (RMM) due to fraud is elevated to CRITICAL."
        )
        recommendation = (
            "1. Management must immediately enforce the Principle of Least Privilege by revoking wildcard privileges. "
            "2. Engagement teams must refuse reliance on ITGCs and execute 100% substantive testing on all ledger balances "
            "hosted within this cloud environment."
        )
        return {"audit_implication": implication, "recommended_action": recommendation}
