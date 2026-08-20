import typer
import os
import boto3
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

from drift_engine.core import detect_drift, get_severity
from drift_engine.aws_client import get_resource_cost
from drift_engine.explain import get_drift_explanation
from drift_engine.models import DriftType
from drift_engine.notifications import process_alerts
from drift_engine.database import save_drift_to_db
from drift_engine.remediation import process_remediation

app = typer.Typer()

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

@app.command()
def scan(
    state: str = typer.Option("terraform/terraform.tfstate"),
    region: str = typer.Option(None),
    fail_on: str = typer.Option(None)
):
    actual_region = region or os.environ.get("AWS_DEFAULT_REGION") or boto3.Session().region_name
    
    if not actual_region:
        typer.secho("No AWS region found. Pass --region or set AWS_DEFAULT_REGION.", fg=typer.colors.RED)
        raise typer.Exit(1)

    typer.echo(f"Scanning AWS Infrastructure in {actual_region}...\n")
    os.environ["TF_STATE_PATH"] = state
    os.environ["AWS_DEFAULT_REGION"] = actual_region

    try:
        results, total_scanned = detect_drift(state, actual_region)
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S IST")
        total_drift = len(results)

        typer.echo("=== DRIFTWATCH SCAN REPORT ===")
        typer.echo(f"Scan time: {current_time} | Resources scanned: {total_scanned}\n")

        if not results:
            typer.secho("No drift detected. Infrastructure matches IaC.", fg=typer.colors.GREEN)
            return

        highest_severity_found = "LOW"
        crit_count = 0
        high_count = 0

        for r in results:
            severity = get_severity(r.resource_type, r.drift_type)

            if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(highest_severity_found, 0):
                highest_severity_found = severity

            if severity == "CRITICAL":
                crit_count += 1
                color = typer.colors.RED
            elif severity == "HIGH":
                high_count += 1
                color = typer.colors.YELLOW
            else:
                color = typer.colors.BLUE

            typer.secho(f"[{r.drift_type.value}] {r.resource_type}: {r.resource_id}", fg=color, bold=True)
            ai_text = ""

            if r.drift_type == DriftType.UNMANAGED and r.resource_type == "aws_instance":
                cost = "{:,.2f}".format(get_resource_cost(r.resource_id))
                inst_type = r.live_attributes.get("instance_type", "unknown")
                typer.echo(f"  Type: {inst_type} (created manually in console)")
                typer.echo(f"  Severity: {severity} | Cost: +${cost}/month (untracked)")
                ai_text = get_drift_explanation(r.resource_type, r.resource_id, r.live_attributes, r.drift_type.value)
            elif r.diff:
                typer.echo(f"  Severity: {severity}")
                for attr, vals in r.diff.items():
                    typer.echo(f"  Attribute: {attr}")
                    typer.echo(f"  Terraform: {vals['terraform']}")
                    typer.echo(f"  Live AWS:  {vals['live']}")
                ai_text = get_drift_explanation(r.resource_type, r.resource_id, r.diff, r.drift_type.value)
            else:
                typer.echo(f"  Severity: {severity}")
                ai_text = get_drift_explanation(r.resource_type, r.resource_id, {"status": "missing"}, r.drift_type.value)

            if ai_text:
                typer.echo(f"  AI Analysis: {ai_text}\n")
                r.ai_analysis = ai_text
            else:
                typer.echo("\n")

        typer.echo(f"Total drift found: {total_drift} resources  |  CRITICAL: {crit_count}  HIGH: {high_count}\n")

        process_alerts(results)
        save_drift_to_db(results)
        
        if results:
            typer.echo("Tip: run 'driftwatch remediate <resource_id>' to fix a specific resource.\n")

        if fail_on and SEVERITY_RANK.get(highest_severity_found, 0) >= SEVERITY_RANK.get(fail_on.upper(), 0):
            typer.secho(
                f"\nBUILD FAILED: highest severity found is {highest_severity_found} (gate: {fail_on.upper()})",
                fg=typer.colors.RED, bold=True,
            )
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as e:
        typer.secho(f"Error during execution: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

@app.command()
def explain(
    resource_id: str,
    state: str = typer.Option("terraform/terraform.tfstate"),
    region: str = typer.Option(None)
):
    actual_region = region or os.environ.get("AWS_DEFAULT_REGION") or boto3.Session().region_name
    
    if not actual_region:
        typer.secho("No AWS region found. Pass --region or set AWS_DEFAULT_REGION.", fg=typer.colors.RED)
        raise typer.Exit(1)

    os.environ["AWS_DEFAULT_REGION"] = actual_region
        
    typer.echo(f"Fetching current drift state for {resource_id}...")
    results, _ = detect_drift(state, actual_region)
    match = [r for r in results if r.resource_id == resource_id]
    
    if not match:
        typer.secho(f"No current drift found for {resource_id}.", fg=typer.colors.YELLOW)
        raise typer.Exit(code=1)
        
    r = match[0]
    diff_data = r.diff if r.diff else r.live_attributes
    
    typer.echo(f"Generating AI explanation...")
    ai_text = get_drift_explanation(r.resource_type, r.resource_id, diff_data, r.drift_type.value)
    typer.echo(f"\nAI Analysis:\n{ai_text}")

@app.command()
def remediate(
    resource_id: str,
    state: str = typer.Option("terraform/terraform.tfstate"),
    region: str = typer.Option(None),
    dry_run: bool = typer.Option(True, "--dry-run/--apply"),
):
    actual_region = region or os.environ.get("AWS_DEFAULT_REGION") or boto3.Session().region_name
    
    if not actual_region:
        typer.secho("No AWS region found. Pass --region or set AWS_DEFAULT_REGION.", fg=typer.colors.RED)
        raise typer.Exit(1)

    os.environ["AWS_DEFAULT_REGION"] = actual_region

    results, _ = detect_drift(state, actual_region)
    match = [r for r in results if r.resource_id == resource_id]

    if not match:
        typer.secho(f"No current drift found for {resource_id}. Run 'driftwatch scan' first.", fg=typer.colors.YELLOW)
        raise typer.Exit(code=1)

    r = match[0]
    typer.secho(f"[{r.drift_type.value}] {r.resource_type}: {r.resource_id}", bold=True)
    for attr, vals in (r.diff or {}).items():
        typer.echo(f"  {attr}: terraform={vals['terraform']}  live={vals['live']}")

    if dry_run:
        typer.secho("\n[DRY RUN] No changes made. Re-run with --apply to remediate.", fg=typer.colors.BLUE)
        return

    process_remediation(match)

if __name__ == "__main__":
    app()