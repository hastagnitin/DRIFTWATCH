import os
import typer
import boto3
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

from drift_engine.core import detect_drift, get_severity
from drift_engine.aws_client import get_resource_cost
from drift_engine.explain import get_drift_explanation, get_deterministic_remediation_suggestion
from drift_engine.models import DriftType
from drift_engine.notifications import process_alerts
from drift_engine.database import save_drift_to_db
from drift_engine.remediation import process_remediation

app = typer.Typer(help="DriftWatch CLI - Detect, Explain, and Remediate Terraform Infrastructure Drift.")

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

def _resolve_region(region: str = None) -> str:
    actual_region = region or os.environ.get("AWS_DEFAULT_REGION")
    if not actual_region:
        try:
            actual_region = boto3.Session().region_name
        except Exception:
            actual_region = None
    return actual_region

def _run_scan(state_path: str, region: str) -> tuple:
    os.environ["TF_STATE_PATH"] = state_path
    os.environ["AWS_DEFAULT_REGION"] = region
    return detect_drift(state_path, region)

def _render_report(results: list, total_scanned: int) -> tuple[str, int, int]:
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    typer.echo("=== DRIFTWATCH SCAN REPORT ===")
    typer.echo(f"Scan time: {current_time} | Resources scanned: {total_scanned}\n")

    if not results:
        typer.secho("No drift detected. Infrastructure matches IaC.", fg=typer.colors.GREEN)
        return "LOW", 0, 0

    highest_severity_found = "LOW"
    crit_count = 0
    high_count = 0

    for r in results:
        severity = get_severity(r.resource_type, r.drift_type, r.diff)

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
                typer.echo(f"  Terraform: {vals.get('terraform')}")
                typer.echo(f"  Live AWS:  {vals.get('live')}")
            ai_text = get_drift_explanation(r.resource_type, r.resource_id, r.diff, r.drift_type.value)
        else:
            typer.echo(f"  Severity: {severity}")
            ai_text = get_drift_explanation(r.resource_type, r.resource_id, {"status": "missing"}, r.drift_type.value)

        if ai_text:
            typer.echo(f"  AI Analysis: {ai_text}\n")
            r.ai_analysis = ai_text
        else:
            typer.echo("\n")

    typer.echo(f"Total drift found: {len(results)} resources  |  CRITICAL: {crit_count}  HIGH: {high_count}\n")
    return highest_severity_found, crit_count, high_count

def _dispatch_alerts(results: list):
    process_alerts(results)
    save_drift_to_db(results)

def _check_gate(highest_severity_found: str, fail_on: str = None):
    if fail_on and SEVERITY_RANK.get(highest_severity_found, 0) >= SEVERITY_RANK.get(fail_on.upper(), 0):
        typer.secho(
            f"\nBUILD FAILED: highest severity found is {highest_severity_found} (gate: {fail_on.upper()})",
            fg=typer.colors.RED, bold=True,
        )
        raise typer.Exit(code=1)

@app.command()
def scan(
    state: str = typer.Option("terraform/terraform.tfstate", help="Path to Terraform state file."),
    region: str = typer.Option(None, help="Target AWS region."),
    fail_on: str = typer.Option(None, help="Severity threshold to trigger non-zero exit code.")
):
    """Scan infrastructure against Terraform state and identify drift."""
    actual_region = _resolve_region(region)
    if not actual_region:
        typer.secho("No AWS region found. Pass --region or set AWS_DEFAULT_REGION.", fg=typer.colors.RED)
        raise typer.Exit(1)

    typer.echo(f"Scanning AWS Infrastructure in {actual_region}...\n")
    try:
        results, total_scanned = _run_scan(state, actual_region)
        highest_severity, _, _ = _render_report(results, total_scanned)
        
        if results:
            _dispatch_alerts(results)
            typer.echo("Tip: run 'driftwatch remediate <resource_id>' to fix a specific resource.\n")
            
        _check_gate(highest_severity, fail_on)
    except typer.Exit:
        raise
    except Exception as e:
        typer.secho(f"Error during execution: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

@app.command()
def explain(
    resource_id: str,
    state: str = typer.Option("terraform/terraform.tfstate", help="Path to Terraform state file."),
    region: str = typer.Option(None, help="Target AWS region.")
):
    """Explain the security/operational impact of detected drift using AI and suggest IaC fixes."""
    actual_region = _resolve_region(region)
    if not actual_region:
        typer.secho("No AWS region found. Pass --region or set AWS_DEFAULT_REGION.", fg=typer.colors.RED)
        raise typer.Exit(1)

    typer.echo(f"Fetching current drift state for {resource_id} in {actual_region}...")
    results, _ = _run_scan(state, actual_region)
    match = [r for r in results if r.resource_id == resource_id]
    
    if not match:
        typer.secho(f"No current drift found for {resource_id}.", fg=typer.colors.YELLOW)
        raise typer.Exit(code=1)
        
    r = match[0]
    diff_data = r.diff if r.diff else r.live_attributes
    
    typer.echo("Generating AI Risk Analysis...")
    ai_text = get_drift_explanation(r.resource_type, r.resource_id, diff_data, r.drift_type.value)
    typer.echo(f"\nAI Risk Analysis:\n{ai_text}\n")
    
    deterministic_remediation = get_deterministic_remediation_suggestion(r.resource_type, r.resource_id, diff_data, r.drift_type.value)
    typer.echo(f"Recommended IaC Remediation Command:\n{deterministic_remediation}\n")

@app.command()
def remediate(
    resource_id: str,
    state: str = typer.Option("terraform/terraform.tfstate", help="Path to Terraform state file."),
    region: str = typer.Option(None, help="Target AWS region."),
    dry_run: bool = typer.Option(True, "--dry-run/--apply", help="Dry run mode (default) or apply changes."),
):
    """Safely reconcile live infrastructure back to Terraform state."""
    actual_region = _resolve_region(region)
    if not actual_region:
        typer.secho("No AWS region found. Pass --region or set AWS_DEFAULT_REGION.", fg=typer.colors.RED)
        raise typer.Exit(1)

    results, _ = _run_scan(state, actual_region)
    match = [r for r in results if r.resource_id == resource_id]

    if not match:
        typer.secho(f"No current drift found for {resource_id}. Run 'driftwatch scan' first.", fg=typer.colors.YELLOW)
        raise typer.Exit(code=1)

    r = match[0]
    typer.secho(f"[{r.drift_type.value}] {r.resource_type}: {r.resource_id}", bold=True)
    for attr, vals in (r.diff or {}).items():
        typer.echo(f"  {attr}: terraform={vals.get('terraform')}  live={vals.get('live')}")

    if dry_run:
        typer.secho("\n[DRY RUN] No changes made. Re-run with --apply to remediate.", fg=typer.colors.BLUE)
        return

    process_remediation(match)

if __name__ == "__main__":
    app()