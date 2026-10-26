"""
ERP Log Forensics Engine - Vectorized Journal Entry Testing (JET)
Compliant with ISA 240 (Management Override of Controls)
"""

import time
import logging
from datetime import datetime, timedelta
from typing import List, Tuple
import numpy as np
import pandas as pd
from core.models import AuditFinding, SeverityLevel, ISAStandard

logger = logging.getLogger("TechRiskAuditEngine.LogForensics")


class EnterpriseLogSynthesizer:
    """Generates synthetic enterprise-scale ERP transaction and security audit logs (SAP SM20 / CDHDR)."""

    @staticmethod
    def generate_large_scale_logs(n_records: int = 100_000, seed: int = 42) -> pd.DataFrame:
        logger.info(f"Synthesizing enterprise SAP audit logs ({n_records:,} event records)...")
        np.random.seed(seed)

        base_time = datetime(2026, 10, 1, 0, 0, 0)
        random_seconds = np.random.randint(0, 30 * 86400, size=n_records)
        timestamps = [base_time + timedelta(seconds=int(s)) for s in random_seconds]

        users = np.random.choice(
            ['accounting_staff_01', 'accounting_staff_02', 'billing_clerk', 'sap_batch_service', 'cfo_executive', 'root_admin'],
            size=n_records,
            p=[0.35, 0.35, 0.18, 0.10, 0.01, 0.01]
        )

        actions = np.random.choice(
            ['POST_JOURNAL', 'DISPLAY_BALANCE', 'GENERATE_FINANCIAL_REPORT', 'UPDATE_MASTER_RECORD', 'OVERRIDE_POSTING'],
            size=n_records,
            p=[0.40, 0.30, 0.20, 0.08, 0.02]
        )

        # Monetary postings in USD
        amounts = np.random.exponential(scale=25_000.0, size=n_records).round(2)

        df = pd.DataFrame({
            'EventID': [f"SAP-EVT-{i:08d}" for i in range(n_records)],
            'Timestamp': timestamps,
            'User': users,
            'Action': actions,
            'PostingAmount_USD': amounts
        })
        logger.info(f"Successfully generated {len(df):,} SAP log events into in-memory buffer.")
        return df


class ERPLogForensicEngine:
    """Vectorized high-performance engine scanning event logs for ISA 240 fraud tripwires."""

    def __init__(self, df: pd.DataFrame):
        self.df = df

    def run_journal_entry_tripwire(
        self, 
        off_hour_start: int = 1, 
        off_hour_end: int = 5, 
        material_threshold_usd: float = 50_000.0
    ) -> Tuple[List[AuditFinding], float]:
        start_time = time.perf_counter()
        logger.info("Executing Vectorized Journal Entry Testing (JET) Tripwire...")

        # Vectorized datetime extraction
        self.df['Hour'] = self.df['Timestamp'].dt.hour

        # Detection rule: Off-hour execution (1 AM - 5 AM), human privileged user, sensitive action, high amount
        suspicious_mask = (
            (self.df['Hour'] >= off_hour_start) &
            (self.df['Hour'] <= off_hour_end) &
            (self.df['User'] != 'sap_batch_service') &
            (self.df['Action'].isin(['OVERRIDE_POSTING', 'UPDATE_MASTER_RECORD'])) &
            (self.df['PostingAmount_USD'] >= material_threshold_usd)
        )

        flagged = self.df[suspicious_mask]
        duration_ms = (time.perf_counter() - start_time) * 1000

        logger.info(
            f"Log scan completed over {len(self.df):,} records in {duration_ms:.2f} ms. "
            f"Flagged {len(flagged)} high-risk transactions."
        )

        findings: List[AuditFinding] = []
        for _, row in flagged.iterrows():
            findings.append(AuditFinding(
                finding_id=f"FIND-JET-{row['EventID']}",
                isa_standard=ISAStandard.ISA_240.value,
                risk_category="Fraud Risk / Management Override of Controls",
                severity=SeverityLevel.CRITICAL if row['PostingAmount_USD'] > 100_000 else SeverityLevel.HIGH,
                timestamp=row['Timestamp'].isoformat(),
                entity_affected="General Ledger Core (SAP Financial Database)",
                technical_evidence={
                    "event_id": row['EventID'],
                    "user": row['User'],
                    "action": row['Action'],
                    "amount_usd": float(row['PostingAmount_USD']),
                    "execution_hour_utc": int(row['Hour'])
                },
                audit_implication=(
                    f"Privileged user '{row['User']}' executed sensitive operation '{row['Action']}' "
                    f"valued at ${row['PostingAmount_USD']:,.2f} USD during unauthorized off-hours ({row['Hour']}:00 UTC). "
                    "This pattern indicates potential management override of internal controls to circumvent segregation of duties."
                ),
                recommended_substantive_action=(
                    "Perform 100% substantive vouching to source documentation, inspect executive approval logs, "
                    "and conduct inquiries with the CFO regarding post-closing manual journal entries."
                ),
                detected_by_module="ERPLogForensicEngine.v2"
            ))

        return findings, duration_ms
