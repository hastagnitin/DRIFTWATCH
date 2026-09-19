# DriftWatch 🛡️

> **TL;DR** — DriftWatch catches when someone (or something) changed your AWS infrastructure outside of Terraform, tells you how risky it is, and helps you fix it — in one CLI.

[![PyPI version](https://img.shields.io/pypi/v/driftwatch-cli?style=flat-square&color=blue)](https://pypi.org/project/driftwatch-cli/)
[![Downloads](https://img.shields.io/pypi/dm/driftwatch-cli?style=flat-square&color=green)](https://pypi.org/project/driftwatch-cli/)
[![Python versions](https://img.shields.io/pypi/pyversions/driftwatch-cli?style=flat-square)](https://pypi.org/project/driftwatch-cli/)
[![License](https://img.shields.io/pypi/l/driftwatch-cli?style=flat-square)](LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/hastagnitin/driftwatch?style=flat-square)](https://github.com/hastagnitin/driftwatch/commits/main)
[![Open issues](https://img.shields.io/github/issues/hastagnitin/driftwatch?style=flat-square)](https://github.com/hastagnitin/driftwatch/issues)

---

## When should I use this?

**Scenario 1 — The Console Cowboy**
A teammate opens a security group in the AWS Console to debug a prod issue. They forget to revert it. DriftWatch catches the open port and flags it as `CRITICAL` before your next audit.

**Scenario 2 — The CI/CD Gatekeeper**
You want your deployment pipeline to fail automatically if someone has drifted your staging infrastructure. Add `driftwatch scan --fail-on HIGH` as a pipeline step. Done.

**Scenario 3 — The Weekly Drift Report**
You run DriftWatch as a Kubernetes CronJob. Every Monday morning, you get a Slack notification listing every resource that drifted that week — with AI explanations attached.

---

## When should I NOT use this?

- **Multi-account enterprise setups** — DriftWatch scans one AWS account and region per run. It does not cross account boundaries.
- **Terraform Cloud / remote state without local access** — You need the state file accessible on disk (local path or pre-downloaded).
- **Non-AWS infrastructure** — Only AWS resources are supported. GCP and Azure are not.
- **Real-time event streaming** — DriftWatch runs on-demand or scheduled. It does not hook into CloudTrail events in real time.

---

## ⚡ Quick Start (under 2 minutes)

```bash
# 1. Install
pip install driftwatch-cli

# 2. Set your region and state file path
export AWS_DEFAULT_REGION=ap-south-1
export TF_STATE_PATH=terraform/terraform.tfstate

# 3. Make sure AWS credentials are configured
aws sts get-caller-identity    # should return your account ID

# 4. Run your first scan
driftwatch scan --region ap-south-1 --state terraform/terraform.tfstate

# 5. Explain a drifted resource
driftwatch explain sg-0123456789abcdef0 --region ap-south-1
```

---

## 🔄 End-to-End Workflow

```bash
# Step 1 — Scan and save results (avoids repeated AWS API calls)
driftwatch scan \
  --region ap-south-1 \
  --state terraform/terraform.tfstate \
  --output json > scan_results.json

# Step 2 — Understand the risk (reads from saved file, 0 extra AWS calls)
driftwatch explain sg-0abc123 --from-scan scan_results.json

# Step 3 — Preview the fix first
driftwatch remediate sg-0abc123 --from-scan scan_results.json --dry-run

# Step 4 — Apply the fix (prompts for confirmation in prod)
driftwatch remediate sg-0abc123 --from-scan scan_results.json --apply
```

---

## 🔁 Pipeline: How DriftWatch Fits In

```
┌─────────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│   terraform.tfstate │────▶│     DriftWatch        │────▶│   Live AWS Account  │
│  (your IaC source   │     │  (drift_engine/core)  │     │  (boto3 API calls)  │
│   of truth)         │     └──────────┬────────────┘     └─────────────────────┘
└─────────────────────┘                │
                                       ▼
                         ┌─────────────────────────────┐
                         │  Drift Report + AI Analysis  │
                         │  ┌──────────────────────┐   │
                         │  │ CRITICAL: sg-0abc123 │   │
                         │  │ ingress 0.0.0.0/0:22 │   │
                         │  └──────────────────────┘   │
                         └──────────┬──────────────────┘
                                    │
                    ┌───────────────┼────────────────┐
                    ▼               ▼                ▼
               Slack Alert    CI/CD Gate Fail    Auto-Remediate
```

---

## 🚀 Features

- **Drift Detection across 6 resource types** — EC2, S3, Security Groups, RDS, Lambda, and IAM Roles. Compares live AWS state attribute-by-attribute against your Terraform state file.
- **Severity Scoring per attribute** — Not all drift is equal. An open ingress rule is `CRITICAL`. A changed tag is `LOW`. DriftWatch scores each attribute individually.
- **AI Risk Summaries** — Connects to Groq API to generate a plain-English explanation of what the drift means and what could go wrong.
- **Deterministic Remediation Commands** — Outputs exact `terraform import` and `terraform apply` commands. Never hallucinates fix scripts.
- **Guarded Auto-Remediation** — Requires explicit confirmation in production. Skips Spot instances and EC2 instances not in `running` state automatically.
- **Scan Caching via `--from-scan`** — Run the scan once, reuse the JSON output for `explain` and `remediate` without hitting AWS again.
- **JSON Output for Automation** — `--output json` gives you a structured report ready for dashboards, SIEM tools, or custom scripts.
- **Multi-Channel Alerts** — Sends notifications to Slack, Telegram, and Email when drift is found.
- **CI/CD Gate** — `--fail-on CRITICAL` exits with code `1` when drift at or above the threshold is detected. Also fails on missing state or broken AWS auth.

---

## 📊 Severity Reference Table

| Severity | What it means | Real examples |
|----------|---------------|---------------|
| `CRITICAL` | Active security risk. Fix immediately. | Security group ingress `0.0.0.0/0` added manually · IAM role policy attached outside Terraform |
| `HIGH` | Functional or cost impact. Fix in 24h. | EC2 instance type changed · RDS multi-AZ disabled · Lambda execution role changed |
| `MEDIUM` | Operational deviation. Fix this sprint. | Lambda memory/timeout changed · RDS storage increased manually · AMI changed |
| `LOW` | Cosmetic or metadata change. Track it. | Tag value changed · Security group description updated |

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

## 🔬 How It Works Under the Hood

1. **State Parsing** — `tf_parser.py` reads your local `terraform.tfstate` JSON file and extracts the declared attributes for every supported resource type.
2. **Live Discovery** — `aws_client.py` queries your live AWS account via boto3 for the same resources and normalises the responses into a common attribute schema.
3. **Diff Engine** — `core.py` compares the two attribute sets key-by-key. For each differing attribute it looks up the `ATTRIBUTE_SEVERITY` table in `models.py` and assigns a severity level.
4. **AI & Remediation** — `explain.py` sends a structured prompt to the Groq API for a risk summary, then builds a deterministic `terraform import` / `terraform apply` command from a template — no AI involved in the fix itself.

---

## 📋 Prerequisites

| Requirement | Details |
|-------------|---------|
| Python | `>= 3.10` |
| AWS Credentials | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`, or IAM role, or `--profile` |
| Terraform State | Local `terraform.tfstate` file (JSON format) |
| Groq API Key *(optional)* | `GROQ_API_KEY` — enables AI risk summaries |
| PostgreSQL *(optional)* | For persistent scan history — `pip install "driftwatch-cli[postgres]"` |

---

## 📦 Installation

```bash
# Standard install
pip install driftwatch-cli

# With PostgreSQL support for persistent audit history
pip install "driftwatch-cli[postgres]"
```

**From source (for contributors):**
```bash
git clone https://github.com/hastagnitin/driftwatch.git
cd driftwatch
pip install -e ".[dev]"
```

---

## ⚙️ Configuration

Create a `.env` file in your project root (copy from `.env.example`):

```env
# Required
AWS_DEFAULT_REGION=ap-south-1
TF_STATE_PATH=terraform/terraform.tfstate

# Optional: Use a named AWS CLI profile instead of env vars
# AWS_PROFILE=prod-profile

# Optional: AI risk summaries (Groq)
GROQ_API_KEY=your_groq_api_key

# Optional: Slack / Telegram alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_telegram_chat_id

# Optional: PostgreSQL scan history
DB_HOST=localhost
DB_PORT=5432
DB_NAME=driftwatch
DB_USER=postgres
DB_PASSWORD=your_db_password
```

---

## 💻 CLI Reference

```bash
driftwatch --version    # Show installed version
driftwatch --help       # Show all commands
```

### `driftwatch scan` — Detect infrastructure drift

```bash
# Basic scan
driftwatch scan --region ap-south-1 --state terraform/terraform.tfstate

# Use a named AWS profile
driftwatch scan --region us-east-1 --profile staging-admin

# CI/CD gate: exit code 1 if any CRITICAL drift is found
driftwatch scan --region ap-south-1 --fail-on CRITICAL

# Save results as JSON for use with explain / remediate
driftwatch scan --region ap-south-1 --output json > scan_results.json
```

**Example output:**
```
Scanning AWS Infrastructure in ap-south-1...

=== DRIFTWATCH SCAN REPORT ===
Scan time: 2026-09-19 14:32:01 | Resources scanned: 14

[MODIFIED] aws_security_group: sg-0123456789abcdef0
  Severity: CRITICAL
  Attribute: ingress
  Terraform: [{'from_port': 22, 'to_port': 22, 'cidr_blocks': ['10.0.0.0/8']}]
  Live AWS:  [{'from_port': 22, 'to_port': 22, 'cidr_blocks': ['0.0.0.0/0']}]
  AI Analysis: SSH is now open to the entire internet. This allows brute-force
               attacks on port 22 from any IP. Revert immediately.

[UNMANAGED] aws_instance: i-0deadbeef1234567
  Type: t3.medium (created manually in console)
  Severity: HIGH | Cost: +$28.34/month (untracked)
  AI Analysis: This instance is running but not tracked in Terraform state.
               It will not be managed, patched, or destroyed by your IaC pipeline.

Total drift found: 2 resources  |  CRITICAL: 1  HIGH: 1

Tip: run 'driftwatch remediate <resource_id>' to fix a specific resource.
```

**Options:**

| Flag | Description |
|------|-------------|
| `--state` | Path to Terraform state file (default: `terraform/terraform.tfstate`) |
| `--region` | AWS region (falls back to `AWS_DEFAULT_REGION`) |
| `--profile` | Named AWS CLI profile |
| `--fail-on` | Severity threshold for non-zero exit: `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `--output`, `-o` | `text` (default) or `json` |
| `--json` | Shorthand for `--output json` |
| `--allow-partial` | Continue scanning if some AWS services fail to respond |

> **CI Gate note:** If the state file is missing, corrupted, or AWS auth fails, `driftwatch scan` exits with code `1` immediately — no false-green builds.

---

### `driftwatch explain` — Get AI risk analysis for a drifted resource

```bash
# Live query (makes AWS API calls to get fresh data)
driftwatch explain sg-0123456789abcdef0 --region ap-south-1

# From saved scan file (no AWS calls — instant)
driftwatch explain sg-0123456789abcdef0 --from-scan scan_results.json
```

**Example output:**
```
Loaded drift state for sg-0123456789abcdef0 from 'scan_results.json'...
Generating AI Risk Analysis...

AI Risk Analysis:
The security group sg-0123456789abcdef0 now allows inbound SSH (port 22)
from 0.0.0.0/0 instead of the private CIDR 10.0.0.0/8 defined in Terraform.
This exposes all instances in this group to brute-force attacks from the
open internet. Severity: CRITICAL.

Recommended IaC Remediation Command:
terraform import aws_security_group.main sg-0123456789abcdef0
terraform apply -target=aws_security_group.main
```

**Options:**

| Flag | Description |
|------|-------------|
| `RESOURCE_ID` | The AWS resource ID to explain (e.g. `sg-xxx`, `i-xxx`) |
| `--state` | Path to Terraform state file |
| `--region` | Target AWS region |
| `--profile` | Named AWS CLI profile |
| `--from-scan` | Path to JSON output from a previous `driftwatch scan --json` |

---

### `driftwatch remediate` — Reconcile live AWS back to Terraform state

```bash
# Preview what would change — safe to run anywhere (default)
driftwatch remediate sg-0123456789abcdef0 --region ap-south-1 --dry-run

# Apply a fix for one resource (prompts for confirmation in prod)
driftwatch remediate sg-0123456789abcdef0 --region ap-south-1 --apply

# Fix ALL drifted resources at once
driftwatch remediate --all --region ap-south-1 --apply

# CI/CD non-interactive: auto-approve, read from saved scan
driftwatch remediate --all --from-scan scan_results.json --apply --yes
```

**Example dry-run output:**
```
[MODIFIED] aws_security_group: sg-0123456789abcdef0
  ingress: terraform=[{'cidr': '10.0.0.0/8'}]  live=[{'cidr': '0.0.0.0/0'}]

[DRY RUN] No changes made. Re-run with --apply to remediate.
```

**Options:**

| Flag | Description |
|------|-------------|
| `RESOURCE_ID` | Target resource (optional if `--all` is used) |
| `--all`, `-a` | Remediate all drifted resources in batch |
| `--dry-run` / `--apply` | Preview only (default) or apply changes |
| `--yes`, `-y`, `--force` | Skip confirmation prompts — use in CI/CD only |
| `--from-scan` | Path to saved scan JSON file |
| `--profile` | Named AWS CLI profile |

---

## ⚠️ Common Mistakes

```bash
# ❌ Wrong: remediate without a saved scan in CI/CD
driftwatch remediate --all --apply
# This re-scans live AWS on every run — slow and wasteful in pipelines

# ✅ Correct: scan once, remediate from the saved file
driftwatch scan --output json > scan.json
driftwatch remediate --all --from-scan scan.json --apply --yes

# ❌ Wrong: no region configured
driftwatch scan --state terraform.tfstate
# Error: No AWS region found. Pass --region or set AWS_DEFAULT_REGION.

# ✅ Correct
export AWS_DEFAULT_REGION=ap-south-1
driftwatch scan --state terraform.tfstate

# ❌ Wrong: using --yes without understanding the consequence
driftwatch remediate --all --apply --yes
# --yes skips ALL confirmation prompts. Only safe in non-prod or trusted CI.
```

---

## 🐍 Python API

Use DriftWatch as a library inside your own scripts:

```python
from drift_engine import detect_drift, get_severity

# Returns list of DriftResult objects + total resources scanned
results, total_scanned = detect_drift(
    tf_state_path="terraform/terraform.tfstate",
    region="ap-south-1",
    profile="default"          # optional: named AWS CLI profile
)

for r in results:
    severity = get_severity(r.resource_type, r.drift_type, r.diff)
    print(f"[{severity}] {r.resource_type} ({r.resource_id}): {r.drift_type.value}")
    # e.g.: [CRITICAL] aws_security_group (sg-0abc123): MODIFIED
```

---

## ⚠️ Security & Safety

> **Auto-remediation is off by default.** Every `remediate` command runs in `--dry-run` mode unless you explicitly pass `--apply`.

- In **production**, DriftWatch requires interactive confirmation before applying any change. Pass `--yes` only in trusted CI/CD pipelines.
- **RDS changes** default to maintenance-window scheduling (`ApplyImmediately=False`) to avoid surprise reboots.
- **EC2 Spot instances** and instances not in `running` state are automatically skipped during remediation.

---

## 🧪 Testing

```bash
# Run full test suite with coverage report
pytest tests/ -v --cov=drift_engine --cov=driftwatch --cov-report=term-missing
```

Tests use [`moto`](https://github.com/getmoto/moto) to mock AWS services — no real AWS account needed to run them.

---

## 🤝 Contributing

1. **Fork** the repo and clone locally
2. **Install dev dependencies**: `pip install -e ".[dev]"`
3. **Create a branch**: `git checkout -b feat/your-feature`
4. **Write tests** for any new behavior in `tests/`
5. **Lint**: `ruff check . && ruff format .`
6. **Open a PR** — describe what changed and why

Report bugs via [GitHub Issues](https://github.com/hastagnitin/driftwatch/issues).

---

## ❓ FAQ

**Q: Does DriftWatch modify my Terraform state file?**
No. DriftWatch is read-only against your state file. All AWS changes go through boto3 and match what `terraform apply` would do.

**Q: Do I need a Groq API key?**
No. AI explanations are optional. Without `GROQ_API_KEY`, drift detection and severity scoring still work — you just won't get AI-generated risk summaries.

**Q: Will DriftWatch delete unmanaged resources?**
No. For `UNMANAGED` resources (things created outside Terraform), DriftWatch reports them and their estimated cost but does not delete them. Remediation outputs a `terraform import` command to bring them under IaC management.

**Q: How do I run this on a schedule?**
Use the Kubernetes CronJob manifest in `kubernetes/`, or set up a system cron with `driftwatch scan --output json > scan.json` and pipe the output to your alerting stack.

**Q: The scan says "partial scan" — what does that mean?**
One or more AWS services failed to respond (e.g., IAM throttling or missing permissions). Use `--allow-partial` to accept results for services that did respond, or check your IAM policy for the required read permissions.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

