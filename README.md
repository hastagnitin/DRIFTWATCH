# DriftWatch 🛡️

**DriftWatch** is a production-ready CLI tool and automation engine that detects Terraform infrastructure drift against live AWS environments, explains the security and reliability impact using AI, and safely guides remediation.

---

## 🚀 Key Features

- **Multi-Resource Drift Detection**: Continuously monitors and compares EC2 instances, S3 buckets, Security Groups, RDS databases, Lambda functions, and IAM roles against your Terraform state.
- **Data-Driven Severity Scoring**: Evaluates changes dynamically at the attribute level (e.g., security group open ingress ports vs. description updates) to classify drifts as `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- **AI-Powered Risk Summaries**: Integrates with LLMs (Groq API) via lightweight direct HTTP requests to provide concise security analysis and compliance impact assessments.
- **Deterministic IaC Remediation**: Recommends safe, template-generated `terraform import` and `terraform apply` commands rather than hallucinated AI scripts.
- **Guarded Auto-Remediation**: Pre-flight validation checks for EC2 (EBS verification, Spot skip, running state), RDS maintenance-window defaults, and explicit interactive confirmations with `--yes` / `--force` automation overrides for CI/CD.
- **Batch Remediation & Scan Caching**: Remediate all drifted resources at once (`--all`), and pass scan outputs (`--from-scan`) to `explain` and `remediate` to avoid redundant AWS API sweeps.
- **Machine-Readable Outputs**: Export full scan reports in structured JSON format (`--json` or `--output json`).
- **Multi-Channel Alerting**: Instant notifications via Telegram, Slack, and Email.
- **Strict CI/CD Quality Gate**: Built-in gate enforcement (`--fail-on`) that halts pipelines with non-zero exit codes on threshold breaches, missing state, corrupted state, or AWS authentication failures.

---

## 🏛️ Architecture Overview

```
driftwatch/
├── drift_engine/              # Core drift detection & reconciliation engine
│   ├── __init__.py           # Core exports (detect_drift, get_severity, models)
│   ├── aws_client.py         # Live AWS discovery & Cost Explorer lookup (boto3)
│   ├── core.py               # Diff evaluation & severity engine
│   ├── database.py           # PostgreSQL scan history recorder (optional)
│   ├── explain.py            # AI risk summaries & deterministic IaC templates
│   ├── models.py             # Data models & attribute severity tables
│   ├── notifications.py      # Alert dispatcher (Telegram, Slack, Email)
│   ├── remediation.py        # Guarded auto-remediation handlers
│   └── tf_parser.py          # Terraform state JSON parser
├── driftwatch/               # CLI Entrypoint (Typer)
│   ├── __init__.py           # Package version & engine alias (driftwatch.engine)
│   └── cli.py                # Commands: scan, explain, remediate
├── terraform/                # Example infrastructure and state configuration
├── kubernetes/               # Kubernetes CronJob deployment
└── tests/                    # Comprehensive unit tests with moto AWS mocks
```

---

## 📋 Prerequisites

- **Python**: `>= 3.10`
- **AWS Credentials**: Configured via environment variables, IAM roles, or AWS CLI profiles (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`, or `--profile`).
- **Terraform State File**: Local JSON state or remote state (`terraform.tfstate`).
- **PostgreSQL** *(Optional)*: For persistent scan audit history.
- **Groq API Key** *(Optional)*: `GROQ_API_KEY` for AI risk explanations.

---

## 📦 Installation

### From PyPI (Recommended)
```bash
pip install driftwatch-cli

# With PostgreSQL support for persistent audit history
pip install "driftwatch-cli[postgres]"
```

### From Source (Local Development)
```bash
git clone https://github.com/hastagnitin/driftwatch.git
cd driftwatch
pip install -e .[dev]
```

---

## ⚙️ Configuration

Create a `.env` file in the root directory:

```env
AWS_DEFAULT_REGION=ap-south-1
TF_STATE_PATH=terraform/terraform.tfstate

# Optional: AWS Named Profile
# AWS_PROFILE=prod-profile

# Optional: AI Risk Summaries
GROQ_API_KEY=your_groq_api_key

# Optional: Notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_telegram_chat_id

# Optional: PostgreSQL Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=driftwatch
DB_USER=postgres
DB_PASSWORD=your_db_password
```

---

## 💻 Usage & CLI Commands

Check CLI version and help:
```bash
driftwatch --version        # or: driftwatch -v
driftwatch --help           # or: driftwatch -h
```

### 1. Scan for Drift (`driftwatch scan`)
Scan live AWS infrastructure against your Terraform state:

```bash
# Standard scan
driftwatch scan --region ap-south-1 --state terraform/terraform.tfstate

# Using a named AWS profile
driftwatch scan --region us-east-1 --profile staging-admin

# CI/CD Drift Gate (fails build with exit code 1 if CRITICAL drift is detected)
driftwatch scan --region ap-south-1 --fail-on CRITICAL

# Output as structured JSON (for dashboards or piped automation)
driftwatch scan --region ap-south-1 --output json > scan_results.json
# Or use shorthand:
driftwatch scan --region ap-south-1 --json > scan_results.json
```

**Options for `driftwatch scan`:**
- `--state`: Path to Terraform state file (default: `terraform/terraform.tfstate`).
- `--region`: Target AWS region (or defaults to `AWS_DEFAULT_REGION`).
- `--profile`: Named AWS CLI profile to use for credentials.
- `--fail-on`: Severity threshold to trigger non-zero exit code (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). Case-insensitive.
- `--output`, `-o`: Output format: `text` (default) or `json`.
- `--json`: Shorthand flag for `--output json`.

> [!NOTE]
> **CI Gate Reliability**: If the Terraform state file is missing or corrupted, or if live AWS resource fetching fails (e.g. invalid credentials or expired sessions), `driftwatch scan` immediately aborts with a non-zero exit code (`1`), preventing false-green builds in your CI/CD pipeline.

---

### 2. Explain Drift (`driftwatch explain`)
Generate AI risk analysis and deterministic IaC fix recommendations for a drifted resource:

```bash
# Live query (fetches live AWS state for resource)
driftwatch explain sg-0123456789abcdef0 --region ap-south-1

# Zero-sweep query from previous scan file (instant, 0 AWS API calls)
driftwatch explain sg-0123456789abcdef0 --from-scan scan_results.json
```

**Options for `driftwatch explain`:**
- `RESOURCE_ID`: ID of the resource to explain (e.g. `sg-xxx`, `i-xxx`).
- `--state`: Path to Terraform state file.
- `--region`: Target AWS region.
- `--profile`: Named AWS CLI profile.
- `--from-scan`: Path to JSON output from a previous `driftwatch scan --json`.

---

### 3. Remediate Drift (`driftwatch remediate`)
Safely reconcile live infrastructure back to Terraform IaC specifications:

```bash
# Dry run mode for a specific resource (default)
driftwatch remediate sg-0123456789abcdef0 --region ap-south-1 --dry-run

# Apply mode (requires interactive confirmation in prod/unrecognized environments)
driftwatch remediate sg-0123456789abcdef0 --region ap-south-1 --apply

# Batch remediation: Fix ALL detected drifted resources at once
driftwatch remediate --all --region ap-south-1 --apply

# Non-interactive CI/CD execution (auto-approve all prompts)
driftwatch remediate --all --region ap-south-1 --apply --yes

# Remediate from a saved scan (avoids re-scanning live AWS)
driftwatch remediate --all --from-scan scan_results.json --apply --yes
```

**Options for `driftwatch remediate`:**
- `RESOURCE_ID`: Target resource ID (optional if `--all` is supplied).
- `--all`, `-a`: Remediate all detected drifted resources in batch.
- `--dry-run / --apply`: Dry run mode (default) or execute changes.
- `--yes`, `-y`, `--force`: Automatically approve prompts without confirmation (essential for CI runners and cron jobs).
- `--from-scan`: Path to saved scan JSON file.
- `--profile`: Named AWS CLI profile.

---

## 🐍 Python Engine API

You can also import and use DriftWatch programmatically:

```python
from driftwatch.engine import detect_drift, get_severity, DriftType

# Or import directly from drift_engine
from drift_engine import detect_drift, get_severity

results, total_scanned = detect_drift(
    tf_state_path="terraform/terraform.tfstate",
    region="ap-south-1",
    profile="default"
)

for r in results:
    severity = get_severity(r.resource_type, r.drift_type, r.diff)
    print(f"[{r.drift_type.value}] {r.resource_type} ({r.resource_id}) -> Severity: {severity}")
```

---

## ⚠️ Security & Safety Guidelines

> [!WARNING]
> **Auto-Remediation Safety**:
> - Automated drift remediation without confirmation is intended for **Development** and **Staging** environments.
> - In **Production**, DriftWatch enforces manual confirmation prompts (`confirm_action()`) and will safely fail-closed (`return False`) in non-interactive terminals unless an explicit `--yes` / `--force` flag is provided.
> - RDS modifications default to maintenance windows (`ApplyImmediately=False`) to prevent unplanned database reboots.

---

## 🧪 Testing

Run the full test suite with coverage:
```bash
pytest tests/ -v --cov=drift_engine --cov=driftwatch --cov-report=term-missing
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
