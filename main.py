"""
========================================================================================
TechRisk Audit Engine - Master CLI Execution Pipeline
Topic:    AI in Audit Planning and Risk Assessment: A Systematic Literature Review & Agenda
Standard: ISA 230 (Working Papers), ISA 240 (Fraud & Override), ISA 315 (ITGC & RMM)
Stack:    Vectorized Pandas, Structural AST Analysis, Google Gemini LLM API
Language: English (Academic & Big 4 Engagement Standard)
========================================================================================
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path

# Add project root directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure Industrial Logging (No amateur print statements)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("TechRiskAuditEngine.MainPipeline")

from core.models import AuditSessionSummary, SeverityLevel
from core.log_forensics import EnterpriseLogSynthesizer, ERPLogForensicEngine
from core.cloud_auditor import CloudSecurityAuditEngine
from core.genai_compiler import GenAIAuditCompiler


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TechRisk Audit Platform: AI-Assisted Unstructured IT Forensics CLI"
    )
    parser.add_argument(
        "--records", 
        type=int, 
        default=100_000, 
        help="Number of synthetic SAP audit log records to generate for benchmarking (default: 100,000)"
    )
    parser.add_argument(
        "--output", 
        type=str, 
        default="output/audit_working_papers_isa230.json", 
        help="Output filepath for ISA 230 Electronic Working Papers JSON"
    )
    parser.add_argument(
        "--api-key", 
        type=str, 
        default=None, 
        help="Google Gemini API key for live GenAI risk compilation (optional, defaults to GEMINI_API_KEY env var)"
    )
    return parser.parse_args()


def execute_engagement_pipeline():
    args = parse_arguments()
    session_start = datetime.now(timezone.utc)
    session_id = f"AUD-SESSION-{session_start.strftime('%Y%m%d-%H%M%S')}"

    logger.info("=" * 80)
    logger.info("TECH RISK AUDIT PLATFORM - BIG 4 ENGAGEMENT EXECUTION PIPELINE")
    logger.info(f"Engagement Session ID : {session_id}")
    logger.info(f"Target Regulatory Scope: ISA 230, ISA 240, ISA 315 (Revised 2019)")
    logger.info("=" * 80)

    findings_registry = []

    # -------------------------------------------------------------------------
    # STAGE 1: VECTORIZED ERP LOG FORENSICS (ISA 240 - JOURNAL ENTRY TESTING)
    # -------------------------------------------------------------------------
    logger.info(">>> [STAGE 1]: Initializing High-Performance ERP Log Forensic Engine (SAP SM20/CDHDR)...")
    log_dataset = EnterpriseLogSynthesizer.generate_large_scale_logs(n_records=args.records)
    forensic_engine = ERPLogForensicEngine(log_dataset)
    jet_findings, jet_duration_ms = forensic_engine.run_journal_entry_tripwire()
    findings_registry.extend(jet_findings)

    # -------------------------------------------------------------------------
    # STAGE 2 & 3: CLOUD ITGC INSPECTOR & GENAI DOMAIN COMPILER (ISA 315)
    # -------------------------------------------------------------------------
    logger.info(">>> [STAGE 2 & 3]: Initiating Cloud IAM Security Audit & GenAI Risk Compilation...")
    
    mock_aws_iam_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "FinancePayrollBucketPublicLeakage",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::enterprise-payroll-ledger-2026/*"
            },
            {
                "Sid": "TemporaryInternPrivilegedSuperAdmin",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:user/intern_temp_dev"},
                "Action": "*",
                "Resource": "arn:aws:rds:ap-southeast-1:123456789012:db:sap_hana_financial_ledger"
            }
        ]
    }

    cloud_auditor = CloudSecurityAuditEngine(mock_aws_iam_policy)
    detected_violations = cloud_auditor.inspect_policy_violations()

    genai_compiler = GenAIAuditCompiler(api_key=args.api_key)
    compiled_cloud_findings = genai_compiler.compile_cloud_violations(detected_violations)
    findings_registry.extend(compiled_cloud_findings)

    # -------------------------------------------------------------------------
    # STAGE 4: AGGREGATE WORKING PAPERS & EXPORT (ISA 230 COMPLIANT)
    # -------------------------------------------------------------------------
    critical_findings_count = sum(1 for f in findings_registry if f.severity == SeverityLevel.CRITICAL)

    audit_summary = AuditSessionSummary(
        session_id=session_id,
        execution_timestamp=session_start.isoformat(),
        total_logs_analyzed=len(log_dataset),
        log_processing_time_ms=jet_duration_ms,
        cloud_policies_evaluated=len(mock_aws_iam_policy.get("Statement", [])),
        findings_count=len(findings_registry),
        critical_risk_count=critical_findings_count,
        findings=findings_registry
    )

    project_root = Path(__file__).parent
    output_file_path = project_root / args.output
    output_file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file_path, "w", encoding="utf-8") as f_out:
        json.dump(audit_summary.to_json(), f_out, indent=2, ensure_ascii=False)

    logger.info(f"Electronic Audit Working Papers successfully exported to: {output_file_path.resolve()}")

    # -------------------------------------------------------------------------
    # EXECUTIVE AUDIT SUMMARY REPORT (OUTPUT THROUGH LOGGING)
    # -------------------------------------------------------------------------
    logger.info("-" * 80)
    logger.info("EXECUTIVE AUDIT RISK SUMMARY (ENGAGEMENT PARTNER BRIEFING)")
    logger.info("-" * 80)
    logger.info(f"Total Log Records Analyzed    : {len(log_dataset):,} events")
    logger.info(f"Vectorized Processing Latency : {jet_duration_ms:.2f} ms")
    logger.info(f"Cloud IAM Statements Audited  : {len(mock_aws_iam_policy.get('Statement', []))} policies")
    logger.info(f"Total Audit Findings Flagged  : {len(findings_registry)} issues")
    logger.info(f"Critical Severity Findings    : {critical_findings_count} issues")
    logger.info("-" * 80)

    for idx, finding in enumerate(findings_registry[:5], 1):  # Display top 5 key audit matters
        logger.info(
            f"Key Matter #{idx} [{finding.severity.value}] {finding.finding_id} | Standard: {finding.isa_standard}"
        )
        logger.info(f"  Target Entity : {finding.entity_affected}")
        logger.info(f"  Audit Impact  : {finding.audit_implication[:120]}...")
        logger.info(f"  Action Reqd   : {finding.recommended_substantive_action[:120]}...")

    if len(findings_registry) > 5:
        logger.info(f"... [{len(findings_registry) - 5} additional findings recorded in electronic working paper artifact]")

    logger.info("=" * 80)
    logger.info("PIPELINE EXECUTION CONCLUDED: 0 RUNTIME EXCEPTIONS | AUDIT READY")
    logger.info("=" * 80)


if __name__ == "__main__":
    execute_engagement_pipeline()
