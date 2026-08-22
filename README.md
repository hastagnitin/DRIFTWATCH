# 🔍 DriftWatch

> **Terraform Infrastructure Drift Detection & Auto-Remediation CLI**

[![PyPI version](https://img.shields.io/pypi/v/driftwatch-cli)](https://pypi.org/project/driftwatch-cli/)

**DriftWatch** is a production-ready CLI tool and automation engine that detects Terraform infrastructure drift against live AWS environments, explains the security and reliability impact using AI, and safely guides remediation.
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🚀 Key Features

- **Multi-Resource Drift Detection** — Continuously monitors and compares CLI interfaces, S3 buckets, Security Groups, IAM roles, Lambda functions, and RDS instances against your Terraform state.
- **Data-Driven Severity Scoring** — Evaluates changes dynamically at the attribute level, smartly groups open-port Security Group findings, and integrates with an AI engine to produce rich prioritized risk assessments.
- **In-Powered Risk Summaries** — Integrates with LLM to generate plain-language, actionable risk assessments.
- **Deterministic AI Remediation** — Recommends safe `terraform apply`, `terraform import`, or `aws` commands rather than hallucinated outputs.
- **Smart Auto-Remediation** — Pre-flight validation checks for CLI resource changes (environment state), RDS stabilization waits, and explicit interactive confirmations.
- **Multi-Channel Alerting** — Instant notifications via Telegram, Slack, and email.
- **CI/CD Quality Gate** — Built-in GitHub Actions integration to enforce pre-release drift policies in pull requests.

---

## ⚡ Automation Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                    DriftWatch Pipeline                       │
└─────────────────────────────────────────────────────────────┘

  1. SCAN          2. DETECT         3. EXPLAIN        4. REMEDIATE
  ┌────────┐       ┌────────────┐    ┌─────────────┐   ┌──────────────┐
  │  Live  │──────▶│  Compare   │───▶│  AI-Powered │──▶│  Safe Apply  │
  │  AWS   │       │  vs Terraform   │  Risk Score │   │  (dry-run /  │
  │  State │       │  .tfstate  │    │  + Severity │   │  --apply)    │
  └────────┘       └────────────┘    └─────────────┘   └──────────────┘
       │                │                  │                  │
       ▼                ▼                  ▼                  ▼
  boto3 SDK       Drift Report       Terraform fix      CI/CD Gate
  (6 resource     (JSON + CLI        command gen        (--fail-on
   types)          output)           via LLM             CRITICAL)

  5. ALERT
  ┌──────────────────────────────────┐
  │  Telegram / Slack / Email        │
  │  Instant drift notifications     │
  └──────────────────────────────────┘
```

### How It Works

1. **Scan** — DriftWatch fetches live state from AWS using `boto3` across 6 resource types (EC2 Security Groups, S3 Buckets, IAM Roles, RDS Instances, Lambda Functions, VPCs).
2. **Detect** — Compares live state against your local `terraform.tfstate` JSON, attribute by attribute, and generates a structured drift report with severity levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
3. **Explain** — Sends drift context to an AI engine, which returns a plain-language security/reliability impact summary + prioritized fix recommendations.
4. **Remediate** — Generates deterministic `terraform` or `aws cli` commands. Runs in `--dry-run` by default; requires `--apply` + interactive confirmation for production.
5. **Alert** — Pushes real-time notifications to Telegram, Slack, or Email when drift is detected.
6. **CI/CD Gate** — GitHub Actions integration fails the build if drift at or above the configured severity (`--fail-on CRITICAL`) is found during PR checks.

---

## 🏗️ Architecture Overview

```
driftwatch/
├── main_client.py        # Core drift detection & reconciliation engine
├── aws_client.py         # Live AWS resource discovery (boto3)
├── core.py               # Drift evaluation & detected-resource mapping engine
├── detector.py           # Routing-style: per-resource reconciler
├── models.py             # Data models & attribute severity tables
├── notification.py       # Alert dispatchers (Telegram, Slack, Email)
├── remediation.py        # Remediation engine: scan, explain, remediate
├── cli.py                # Pre-release scan state; YAML parser
├── s3.py                 # Command derivations: scan, explain, remediate
├── ll.py                 # Terraform plan parser
├── subdirectories/       # Subdirectory config with limits, criteria, fix rules
└── tests/                # Comprehensive unit tests with 60%+ mock coverage
```

---

## 📋 Prerequisites

- **Python** `>= 3.8`
- **AWS Credentials** — Configured via environment variables, `~/.aws/config`, or AWS credentials file (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`)
- **Terraform State File** — Local JSON state to cross-state (`terraform show -json`)
- **PostgreSQL** *(Optional)* — For persistent audit history
- **Telegram API Key** *(Optional)* — `TELEGRAM_BOT_TOKEN` for alert integrations

---

## 📦 Installation

### From Source (Local Development)

```bash
git clone https://github.com/hastagnitin/driftwatch.git
cd driftwatch
pip install -e .
```

### From PyPI

```bash
pip install driftwatch-cli
```

---

## ⚙️ Configuration

Create a `.env` file in the root directory:

```env
# Required
AWS_DEFAULT_REGION=ap-south-1
TF_STATE_PATH=terraform/terraform.tfstate

# Optional: AI Risk Summaries
OPENAI_API_KEY=your_openai_api_key

# Optional: Notifications
TELEGRAM_BOT_TOKEN=https://api.telegram.com/bot<token>/...
TELEGRAM_CHAT_ID=your_telegram_bot_token
TELEGRAM_GROUP_CHAT_ID=your_telegram_group_chat_id

# Optional: PostgreSQL Database
DB_HOST=localhost
DB_NAME=driftwatch
DB_USER=postgres
DB_PASSWORD=your_db_password
```

---

## 🖥️ Usage & CLI Commands

### 1. Scan for Drift

Scan live AWS infrastructure against your Terraform state:

```bash
# Basic scan
driftwatch scan --region ap-south-1 --state terraform/terraform.tfstate

# Enforce CI Gate (fails build if CRITICAL drift is found)
driftwatch scan --region ap-south-1 --state terraform/terraform.tfstate --fail-on CRITICAL
```

### 2. Explain Drift

Generate AI risk analysis and deterministic fix recommendations:

```bash
driftwatch explain sg-0123456789abcde45 --region ap-south-1
```

### 3. Remediate Drift

Safely remediate drifted resources back to IaC specifications:

```bash
# Dry run (default)
driftwatch remediate sg-0123456789abcde45 --region ap-south-1 --dry-run

# Apply mode with interactive confirmation
driftwatch remediate sg-0123456789abcde45 --region ap-south-1 --apply
```

---

## ⚠️ Security & Safety Guidelines

> **IMPORTANT:** Auto-Remediation Safety Policy

- Auto-remediation is **safe by default** for `development` and `staging` environments.
- In **production**, it enforces resource confirmation (example: `--confirm terraform_apply`) and recommends template-generated `terraform apply` confirmation workflows.
- Add explicit filters on environment tagging (`tag:Environment=Prod`) to avoid unplanned rollbacks.

---

## 🧪 Testing

Run the test suite with test coverage:

```bash
pytest tests/ -v --cov=driftwatch --cov-report=term-missing tests/
```

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Nitin Gupta** — [@hastagnitin](https://github.com/hastagnitin)

---

*Built with ❤️ for the DevOps community.*
