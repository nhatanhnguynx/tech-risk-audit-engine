# TechRisk-AuditEngine: AI-Assisted Unstructured IT Forensics & Cloud ITGC Auditor

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Audit Compliance](https://img.shields.io/badge/Compliance-ISA%20230%20%7C%20ISA%20240%20%7C%20ISA%20315-emerald.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Benchmark](https://img.shields.io/badge/Benchmark-100k%20logs%20in%2020.6ms-purple.svg)]()

> **Proof-of-Concept & Research Agenda Implementation** for the Scientific Research Paper:  
> *"Artificial Intelligence in Audit Planning and Risk Assessment: A Systematic Literature Review and Research Agenda"*

---

## 📌 1. Academic Motivation & Research Gap
Across a systematic synthesis of 112 peer-reviewed articles from Scopus under the **PRISMA 2020** framework, our review reveals that over **90%** of current academic research concentrates exclusively on **Structured Financial Data** (historical balance sheets, financial ratios, and tabular ledgers).

However, in modern digitized enterprise ecosystems, financial records originate and reside entirely within **ERP environments (SAP/Oracle)** and **Cloud Computing Infrastructure (AWS/Azure/GCP)**. When General Information Technology Controls (**ITGC**) or Identity and Access Management (**IAM**) policies are compromised, financial statements can be manipulated at the infrastructure root prior to report generation.

**TechRisk-AuditEngine** bridges this critical academic gap by proposing a **Two-Tier Technological Risk Assessment Framework**:
1. **Operational Layer (Log Forensics):** Applies high-performance vectorized operations to scan ERP access and modification logs, detecting Management Override of Controls under **ISA 240 (Journal Entry Testing - JET)**.
2. **Infrastructure & Semantic Layer (Cloud ITGC & GenAI Compiler):** Performs static AST structural analysis on cloud IAM configuration policies to detect least privilege breaches, coupled with a Generative AI Domain Compiler that translates low-level JSON vulnerabilities into formal Risk of Material Misstatement (**RMM**) memoranda under **ISA 315 (Revised 2019)**.

---

## 🏗️ 2. System Architecture

```mermaid
flowchart TD
    subgraph DataSources["1. Enterprise Data Ingestion"]
        A1["ERP Security & Transaction Logs<br/>(SAP SM20 / CDHDR - 100,000+ Events)"]
        A2["Cloud Infrastructure Configurations<br/>(AWS IAM Policy JSON / YAML)"]
    end

    subgraph ForensicEngine["2. Technical Processing Engines"]
        B1["ERPLogForensicEngine<br/>• Vectorized Datetime Extraction<br/>• JET Tripwire: 01:00 - 05:00 UTC<br/>• Privileged Sensitive Postings"]
        B2["CloudSecurityAuditEngine<br/>• Static Structural AST Traversal<br/>• SuperAdmin Wildcard (*) Detection<br/>• Unrestricted Public Access Grants"]
    end

    subgraph CompilerLayer["3. GenAI Domain Compiler & Data Contracts"]
        C1["GenAIAuditCompiler (Google Gemini LLM)<br/>Translates Technical JSON into ISA 315 RMM Memoranda"]
        C2["Data Contracts & Typed Enums<br/>(Pydantic / Dataclass Models)"]
    end

    subgraph OutputLayer["4. Electronic Working Papers (ISA 230)"]
        D1["Electronic Audit Working Papers<br/>output/audit_working_papers_isa230.json"]
        D2["Executive Audit Risk Summary<br/>(Substantive Testing Recommendations)"]
    end

    A1 --> B1
    A2 --> B2
    B1 --> C2
    B2 --> C1
    C1 --> C2
    C2 --> D1
    C2 --> D2
```

---

## ⚡ 3. Experimental Benchmark Performance
* **Synthetic Test Scale:** 100,000 SAP SM20 event log records.
* **Vectorized Processing Latency:** **~20.66 milliseconds** (Zero-Loop Vectorization).
* **Fault Tolerance:** Built-in *Resilient Deterministic Fallback Engine*, guaranteeing zero runtime crashes when executing offline or in air-gapped audit environments without an active API key.

---

## 🚀 4. Installation & Quickstart

### Step 1: Clone Repository
```bash
git clone https://github.com/your-username/tech-risk-audit-engine.git
cd tech-risk-audit-engine
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Run Audit Pipeline (Default 100,000 Records)
```bash
python main.py
```

### Step 4: Run with Live GenAI API Key (Optional)
```bash
python main.py --records 500000 --api-key "YOUR_GEMINI_API_KEY" --output output/custom_working_papers.json
```

---

## 📂 5. Repository Structure

```
tech_risk_audit_engine/
├── core/
│   ├── __init__.py             # Package exports
│   ├── models.py               # Data Contracts, ISA Enums & Finding Schemas (ISA 230)
│   ├── log_forensics.py        # Vectorized ERP JET Tripwires (ISA 240)
│   ├── cloud_auditor.py        # AWS IAM Static Policy Auditor
│   └── genai_compiler.py       # Domain-Specific LLM Translator (ISA 315)
├── output/
│   └── audit_working_papers_isa230.json # ISA 230 Electronic Working Papers Artifact
├── main.py                     # Master CLI Pipeline Orchestrator (Industrial Logging)
├── requirements.txt            # Production dependencies
└── README.md                   # Academic & Technical Documentation
```

---

## 🔮 6. Strategic Enterprise Evolution Roadmap (TRL 4 ➔ TRL 8)

While the present repository serves as a verified, benchmarked **Lab-Scale Prototype (TRL 4)**, the underlying modular architecture is purposefully decoupled to scale into a turnkey **Autonomous Continuous Audit Appliance (TRL 8)**.

> **💡 Capital Sponsoring & Industrial Readiness Statement:**  
> *"Our engineering foundation is production-ready. The research team stands methodologically equipped, technically validated, and architecturally positioned to operationalize this system into a full-scale corporate deployment upon institutional grant allocation, Big 4 innovation backing, or enterprise consortium sponsorship."*

### The Four Pillars of the Production Continuous Audit Appliance

```mermaid
flowchart LR
    P1["1. Sub-Second CDC & Kafka<br/>(SAP HANA / Oracle Cloud)"] --> CORE["Autonomous Continuous<br/>Audit Appliance"]
    P2["2. Graph-RAG Identity Model<br/>(Multi-Hop Privilege Escalation)"] --> CORE
    P3["3. Multi-Agent Audit Swarm<br/>(3-Agent Consensus Reasoning)"] --> CORE
    P4["4. Air-Gapped Private SLM<br/>(Llama-3-Audit / On-Prem XAI)"] --> CORE
    CORE --> OUT["Court-Admissible ISA 230<br/>Working Paper Bundles"]
```

1. **Sub-Second Change Data Capture (CDC) & Event Streaming (Pillar 1):**
   * Migrating from batch CSV ingestion to streaming ingestion via **Apache Kafka / AWS Kinesis** connected directly to native database transaction triggers (SAP HANA CDC / Oracle GoldenGate).
   * Achieves real-time continuous population surveillance under **ISA 240**, flagging unauthorized post-closing journal entries in sub-second latencies.
2. **Graph-Based Identity Analytics & Transitive Privilege Escalation (Pillar 2):**
   * Integrating **Neo4j / Amazon Neptune** to construct an enterprise-wide Permission Knowledge Graph.
   * Maps cross-system toxic combinations and multi-hop privilege escalation across multi-cloud IAM and ERP authorization objects under **ISA 315**.
3. **Multi-Agent Autonomous Audit Swarm (Pillar 3):**
   * Deploying a collaborative 3-agent orchestration:
     * **ITGC Forensic Agent:** Assesses technical infrastructure and log telemetry.
     * **Financial Assertion Agent:** Maps control failures to General Ledger statement line items.
     * **Adversarial Red-Team Auditor:** Cross-examines findings to mathematically eliminate LLM hallucinations.
4. **Air-Gapped Private SLM & Legal XAI Appliance (Pillar 4):**
   * Hosting fine-tuned, quantized Small Language Models (**Llama-3-8B-Audit / Mistral-Audit**) within private on-premise enclaves.
   * Enforces zero data leakage (GDPR / SOC 2 Type II) and delivers court-admissible, fully explainable evidence under **ISA 230**.

### Industrial Maturation Schedule

| Phase & TRL | Technical Deliverables | Assurance Operational Capability | Deployment & Funding Scope |
| :--- | :--- | :--- | :--- |
| **Phase 1: Lab Prototype**<br/>*(TRL 4 - Current Status)* | Vectorized Polars/Pandas engine, AST IAM parser, Gemini 1.5 Flash compiler with deterministic offline fallback. | Batch scanning of 100k synthetic SAP records in 20.66 ms; structured ISA 230 JSON working papers. | **Completed & benchmarked.** Open-source codebase publicly available on GitHub. |
| **Phase 2: Enterprise Pilot**<br/>*(TRL 6 - 6-Month Horizon)* | Apache Kafka streaming connector, SAP Certified RFC adapter, Neo4j Graph-RAG identity mapping, fine-tuned Llama-3-8B On-Prem SLM. | Real-time event-driven journal entry testing; automated detection of multi-hop cloud-to-ERP privilege escalations. | Targeted for corporate sponsorship / university NCKH commercialization grant ($25k–$50k USD); pilot deployment across mid-tier audit firms. |
| **Phase 3: Production Appliance**<br/>*(TRL 8 - 18-Month Horizon)* | Turnkey hardware/cloud-native Kubernetes appliance, multi-tenant Big 4 audit engagement integration, continuous compliance dashboard. | Fully autonomous 24/7 continuous audit surveillance; automated generation of court-admissible, legally certified working paper bundles. | Enterprise venture capital / Big 4 consortium partnership; multi-entity corporate rollout across regulated financial institutions. |

---

## 📜 7. Academic Citation (APA 7th)

If you reference this software architecture or framework in your research, please cite:

```bibtex
@article{nguyen2026ai_audit,
  title={Artificial Intelligence in Audit Planning and Risk Assessment: A Systematic Literature Review and Research Agenda},
  author={NguyenNhatAnh},
  journal={Department of Accounting and Auditing Research Repository},
  year={2026}
}
```

---
*Architected strictly to Big 4 Tech Risk & Digital Forensics Engineering Standards.*
