DriftWatch CLI — Independent QA & Flaw Report
pip install driftwatch-cli==0.1.0  ·  tested 23 Aug 2026  ·  prepared for Build With Bharat 2.0 prep
Heads up —  you asked me to test 0.1.0 specifically, and everything below is confirmed on exactly that version. PyPI's current latest is 3.0.1 — a 3-major-version jump from what's tested here. If 3.0.x has already re-architected things, some of this may already be fixed; treat it as a regression checklist for that version too. Happy to re-run the same battery against 3.0.1 if you want a second report.
Executive Summary
Installed the exact version you asked for into a clean virtual environment (no leftover state from any other project), ran every subcommand the CLI exposes, read all nine source files that actually ship inside the wheel, and cross-checked the PyPI listing itself. 18 distinct issues came out of that, grouped by how much they'd actually hurt you in front of judges or in real use:
Severity	Count	What it means
CRITICAL	2	Breaks the tool's core promise — can report “all clear” when it isn't, or crash outright inside automation.
HIGH	3	Packaging/dependency issues that bloat every single install without adding any function.
MEDIUM	8	Missing CLI conveniences and inefficiencies that show up as soon as you use it seriously.
LOW	5	Polish, packaging hygiene, and one latent code smell.

The one that matters most: the tool's whole pitch is being a CI/CD drift gate, but a missing state file, a corrupted state file, or a total AWS authentication failure all get reported as “No drift detected” with exit code 0 — the same as a genuinely clean scan. That's covered first, in detail, below.
How I Tested This
●	Fresh virtualenv, Python 3.12.3, exactly: pip install driftwatch-cli==0.1.0
●	Ran scan, explain, and remediate with no arguments, with valid arguments, and with deliberately broken inputs (missing file, corrupt JSON, no AWS credentials, invalid flag values, non-interactive stdin).
●	Read every shipped source file: driftwatch/cli.py and all eight files under drift_engine/ (core, aws_client, database, explain, models, notifications, remediation, tf_parser).
●	Pulled the PyPI JSON metadata for 0.1.0 (classifiers, keywords, README as published) and measured the actual installed footprint on disk.
Critical Issues
[CRITICAL] C1 — Scan reports “no drift” even when it completely failed to scan
What I found:  Three different failure modes — a missing state file, a corrupted state file, and a total AWS authentication failure — all end the same way: a green “No drift detected. Infrastructure matches IaC.” message and exit code 0. This happens even with --fail-on CRITICAL set.
$ driftwatch scan --region us-east-1
Scanning AWS Infrastructure in us-east-1...

Error: Terraform state file not found at 'terraform/terraform.tfstate'
=== DRIFTWATCH SCAN REPORT ===
Scan time: 2026-08-23 09:35:51 | Resources scanned: 0

No drift detected. Infrastructure matches IaC.
$ echo $?
0
Root cause (source):  tf_parser.py catches FileNotFoundError and JSONDecodeError, prints the message, and returns {} instead of signaling failure. core.py then sees an empty tf_resources and short-circuits: “if not tf_resources: return [], 0”. cli.py's _render_report only checks “if not results” to decide the scan was clean — it never asks whether the scan actually ran. Even the live-AWS-fetch failures are caught internally (a failed_types set exists specifically to avoid false positives) but that signal is thrown away before it reaches the exit code.
Why it matters:  This is the exact scenario a CI/CD gate exists to catch — something went wrong and nobody should assume the infrastructure is fine. Right now, a typo'd --state path or an expired AWS session produces the same green checkmark as a genuinely clean account.
Fix:  Have load_terraform_state and the fetch_live_* functions signal failure distinctly from “legitimately zero resources.” Then have _render_report / _check_gate treat “couldn't complete the scan” as a hard failure (non-zero exit), not a pass.
[CRITICAL] C2 — remediate --apply crashes with a raw traceback in any non-interactive shell
What I found:  Any resource whose Environment tag isn't dev or staging requires an interactive y/n confirmation via Python's input(). There's no --yes / --force flag. In a CI runner, cron job, or any piped/non-TTY context, that input() call raises an uncaught EOFError — and unlike scan(), the remediate() command in cli.py has no try/except around it at all, so the raw traceback goes straight to the user.
>>> confirm_action('Change EC2 i-xxxx instance type', env='prod', is_disruptive=True)
[!] [PROD] Protection Active. Manual action required.
[!] WARNING: This is a disruptive action -> Downtime risk!
⚠️ Change EC2 i-xxxx instance type. Proceed? (y/n): Traceback (most recent call last):
  File "remediation.py", line 25, in confirm_action
    choice = input(f"⚠️ {action_desc}. Proceed? (y/n): ").strip().lower()
EOFError: EOF when reading a line
Why it matters:  A DevOps tool that hangs or crashes the moment it's run outside an interactive terminal defeats its own purpose — remediation is exactly the kind of step teams want to automate, and “prod” or an untagged resource are precisely the cases where you can't rely on someone sitting at a keyboard.
Fix:  Wrap remediate()'s body in the same try/except pattern scan() already uses, and add an explicit --yes/--force flag that skips the prompt for scripted/CI use — separate from the existing dev/staging auto-approve, which is env-based, not operator-based.
High — Dependency & Packaging Bloat
[HIGH] H1 — Two hard dependencies are never actually used in the code
What I found:  pip show lists groq and python-telegram-bot as required dependencies. Neither is imported anywhere in the shipped source. The “AI explanation” feature in explain.py calls the Groq HTTP endpoint directly with requests; the Telegram alert in notifications.py calls the Telegram Bot HTTP API directly with requests too. Both official SDKs are installed and then never touched.
$ grep -rn "import groq\|from groq" drift_engine/ driftwatch/
NOT FOUND — groq SDK unused
$ grep -n "requests.post" drift_engine/notifications.py drift_engine/explain.py
notifications.py:  response = requests.post(url, json=payload, timeout=15)   # Telegram, raw HTTP
explain.py:        response = requests.post(url, json=payload, headers=headers, timeout=15)  # Groq, raw HTTP
Fix:  Remove groq and python-telegram-bot from pyproject.toml/setup.py. No code changes needed elsewhere — it's a two-line edit and a re-publish.
[HIGH] H2 — psycopg2-binary is required, even though the README calls it optional
What I found:  database.py does genuinely use psycopg2 — this one isn't dead code — but only for an opt-in “save scan history to Postgres” feature that's gated behind DB_USER/DB_PASSWORD env vars. Your own README lists “PostgreSQL (Optional): for persistent scan audit history.” Packaging disagrees: it's a hard requirement, so every single pip install driftwatch-cli pulls it in whether or not anyone ever sets those env vars.
Fix:  Move it into an extras group — pip install driftwatch-cli[postgres] — so the package matches what the README already promises.
[HIGH] H3 — Net effect: roughly a third of the install is dead weight or forced-optional
What I found:  Total site-packages footprint after installing 0.1.0 into an empty venv: 99 MB. Breakdown of the biggest pieces:
●	botocore — 30 MB (genuinely needed, this is the AWS SDK core)
●	psycopg2_binary — 11 MB (optional feature per the README — see H2)
●	telegram (python-telegram-bot) — 7.7 MB (unused — see H1)
●	pydantic + pydantic_core — 9 MB (pulled in only because groq needs it — unused — see H1)
●	groq — 1.6 MB (unused — see H1)
That's roughly 28–30 MB — close to a third of the total install — spent on one unused SDK, its own transitive dependencies, and one feature that's documented as optional but packaged as mandatory. For a tool whose whole pivot story was “become a lightweight, pip-installable CLI” instead of a k3s service, this undercuts that pitch a bit.
Medium — Missing Functionality & Inefficiencies
[MEDIUM] M1 — No --version flag
driftwatch --version errors with “No such option: --version.” The only way to confirm what's installed is pip show driftwatch-cli. A three-line fix via a Typer version callback.
[MEDIUM] M2 — --fail-on accepts any string, silently
Passing --fail-on totallyInvalidSeverityXYZ didn't error — it ran the scan, then printed “BUILD FAILED: highest severity found is LOW (gate: TOTALLYINVALIDSEVERITYXYZ).” A typo turns into a confusing false build failure instead of a clear “invalid value, choose LOW/MEDIUM/HIGH/CRITICAL” error. Worth restricting the option to an actual choice list.
[MEDIUM] M3 — No -h shorthand for help
Only --help works; -h errors with “No such option.” Minor, but it's a one-line Typer/Click config to support both.
[MEDIUM] M4 — No --profile flag for named AWS profiles
--region is configurable, but there's no way to pick a named AWS CLI profile — only the default credential chain. Anyone juggling multiple AWS accounts (very common in real DevOps work) has to fight environment variables instead of just adding --profile client-prod.
[MEDIUM] M5 — No machine-readable output
The scan report is colored terminal text only — no --json or --output flag. Beyond the exit code, there's no clean way to feed results into a dashboard or another system without scraping stdout.
[MEDIUM] M6 — Every command re-fetches all six AWS resource types from scratch
explain <id> and remediate <id> both call the exact same full detect_drift() that scan does — hitting EC2, S3, Security Groups, RDS, Lambda, and IAM every time, with no caching between commands. Looking up one resource after a scan re-runs the entire account-wide sweep.
[MEDIUM] M7 — No batch remediation, despite the engine supporting it
remediate takes exactly one resource_id. The underlying process_remediation() in remediation.py is already written to loop over a list of drift results, but the CLI only ever calls it with a single-item list. Fixing 10 drifted resources means running the command 10 times — and per M6, that's 10 full re-scans.
[MEDIUM] M8 — Cost estimate is narrow, and fails silently to $0.00
The “+$X/month (untracked)” line only shows up for one specific case: an UNMANAGED EC2 instance. RDS, Lambda, and MODIFIED EC2 drift never get a cost estimate. It also relies on AWS Cost Explorer's per-resource filter, which most accounts haven't opted into — and on any failure it just returns 0.0, so a displayed “$0.00” can mean “verified free” or “couldn't check.” Same blind spot as Critical #1, smaller scale.
Low — Polish & Packaging Hygiene
[LOW] L1 — Empty PyPI classifiers and no keywords
The published 0.1.0 metadata shows classifiers: [] and keywords: None — despite license: MIT being set correctly. No Python-version or topic classifiers either. Costs nothing to add and helps people actually find the package on PyPI.
[LOW] L2 — README's install section never mentions pip install
The “Installation” section only documents git clone + pip install -e .[dev]. It doesn't mention pip install driftwatch-cli anywhere — which is the easier path, the whole point of publishing to PyPI, and literally the command you asked me to run for this test.
[LOW] L3 — drift_engine ships as a bare top-level package
It installs alongside driftwatch as its own top-level import (import drift_engine), not nested under it — this matches the README's documented layout, so it's intentional, but a generic name like drift_engine risks colliding with anything else in someone's environment. Namespacing it under driftwatch (e.g. driftwatch/engine/...) would be cleaner.
[LOW] L4 — Unguarded .lower() in get_environment_tag
In remediation.py, the dict-shaped tags branch safely does value.lower() if value else 'unknown' — but the list-of-dicts branch two lines below just does tag.get('Value').lower(), no None-guard. Looks unreachable today since tags are normalized to dicts before they reach this function, but it's inconsistent with the code right next to it, and one refactor away from an AttributeError.
[LOW] L5 — A couple of remediate_* helpers drop the region
remediate_s3_bucket and remediate_iam_role build their boto3 client without region_name=region, unlike every other function in the same file. Defensible since S3/IAM are near-global services, but worth being consistent given the whole tool is built around an explicit --region flag.
