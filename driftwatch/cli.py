import os
import json
import typer
import boto3
import importlib.metadata
from enum import Enum
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

from drift_engine.core import detect_drift, get_severity
from drift_engine.aws_client import get_resource_cost
from drift_engine.explain import get_drift_explanation, get_deterministic_remediation_suggestion
from drift_engine.models import DriftResult, DriftType
from drift_engine.notifications import process_alerts
from drift_engine.database import save_drift_to_db
from drift_engine.remediation import process_remediation

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

class SeverityChoice(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class OutputFormat(str, Enum):
    text = "text"
    json = "json"

def version_callback(value: bool):
    if value:
        try:
            ver = importlib.metadata.version("driftwatch-cli")
        except Exception:
            ver = "0.1.0"
        typer.echo(f"driftwatch-cli version {ver}")
        raise typer.Exit()

app = typer.Typer(
    help="DriftWatch CLI - Detect, Explain, and Remediate Terraform Infrastructure Drift.",
    context_settings={"help_option_names": ["-h", "--help"]}
)

@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show DriftWatch CLI version and exit."
    )
):
    pass

def _resolve_region(region: str = None, profile: str = None) -> str:
    actual_region = region or os.environ.get("AWS_DEFAULT_REGION")
    if not actual_region:
        try:
            actual_region = boto3.Session(profile_name=profile or os.environ.get("AWS_PROFILE")).region_name
        except Exception:
            actual_region = None
    return actual_region

def _run_scan(state_path: str, region: str, profile: str = None) -> tuple:
    os.environ["TF_STATE_PATH"] = state_path
    os.environ["AWS_DEFAULT_REGION"] = region
    return detect_drift(state_path, region, profile=profile)

def _load_from_scan(from_scan_path: str) -> tuple[list, str]:
    try:
        with open(from_scan_path) as f:
            data = json.load(f)
    except Exception as e:
        typer.secho(f"Error loading scan file '{from_scan_path}': {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    scan_region = data.get("region")
    results = []
    for item in data.get("results", []):
        drift_type_str = item.get("drift_type", "MODIFIED")
        try:
            d_type = DriftType(drift_type_str)
        except Exception:
            d_type = DriftType.MODIFIED
        r = DriftResult(
            resource_type=item.get("resource_type", "unknown"),
            resource_id=item.get("resource_id", "unknown"),
            drift_type=d_type,
            resource_name=item.get("resource_name", "Unknown"),
            tf_attributes=item.get("tf_attributes", {}),
            live_attributes=item.get("live_attributes", {}),
            diff=item.get("diff", {})
        )
        r.ai_analysis = item.get("ai_analysis", "")
        results.append(r)
    return results, scan_region

def _render_report(results: list, total_scanned: int, profile: str = None) -> tuple[str, int, int]:
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

        cost_val = None
        if r.resource_type in ["aws_instance", "aws_db_instance", "aws_lambda_function"]:
            cost_val = get_resource_cost(r.resource_id, profile=profile)

        if r.drift_type == DriftType.UNMANAGED:
            cost_str = f"+${cost_val:,.2f}/month (untracked)" if cost_val is not None else "unavailable"
            if r.resource_type == "aws_instance":
                inst_type = r.live_attributes.get("instance_type", "unknown")
                typer.echo(f"  Type: {inst_type} (created manually in console)")
            typer.echo(f"  Severity: {severity} | Cost: {cost_str}")
            ai_text = get_drift_explanation(r.resource_type, r.resource_id, r.live_attributes, r.drift_type.value)
        elif r.diff:
            if cost_val is not None:
                typer.echo(f"  Severity: {severity} | Estimated 30d Cost: ${cost_val:,.2f}")
            elif r.resource_type in ["aws_instance", "aws_db_instance", "aws_lambda_function"]:
                typer.echo(f"  Severity: {severity} | Estimated 30d Cost: unavailable")
            else:
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

def _render_json_report(results: list, total_scanned: int, region: str, state_path: str, profile: str = None) -> tuple[str, dict]:
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    highest_severity_found = "LOW" if results else "NONE"
    formatted_results = []

    for r in results:
        sev = get_severity(r.resource_type, r.drift_type, r.diff)
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(highest_severity_found, 0):
            highest_severity_found = sev

        cost_val = None
        if r.resource_type in ["aws_instance", "aws_db_instance", "aws_lambda_function"]:
            cost_val = get_resource_cost(r.resource_id, profile=profile)

        ai_text = getattr(r, "ai_analysis", "") or ""
        if not ai_text:
            diff_data = r.diff if r.diff else (r.live_attributes or {"status": "missing"})
            ai_text = get_drift_explanation(r.resource_type, r.resource_id, diff_data, r.drift_type.value)
            r.ai_analysis = ai_text

        formatted_results.append({
            "resource_id": r.resource_id,
            "resource_type": r.resource_type,
            "resource_name": r.resource_name,
            "drift_type": r.drift_type.value,
            "severity": sev,
            "diff": r.diff or {},
            "live_attributes": r.live_attributes or {},
            "tf_attributes": r.tf_attributes or {},
            "ai_analysis": ai_text,
            "cost_estimate": cost_val
        })

    report = {
        "scan_time": current_time,
        "region": region,
        "state_path": state_path,
        "total_scanned": total_scanned,
        "drift_count": len(results),
        "highest_severity": highest_severity_found,
        "results": formatted_results
    }
    typer.echo(json.dumps(report, indent=2))
    return highest_severity_found, report

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
    profile: str = typer.Option(None, help="AWS CLI profile name to use."),
    fail_on: SeverityChoice = typer.Option(
        None,
        "--fail-on",
        case_sensitive=False,
        help="Severity threshold to trigger non-zero exit code (LOW, MEDIUM, HIGH, CRITICAL)."
    ),
    output: OutputFormat = typer.Option(OutputFormat.text, "--output", "-o", case_sensitive=False, help="Output format: 'text' or 'json'."),
    json_output: bool = typer.Option(False, "--json", help="Shorthand for --output json.")
):
    """Scan infrastructure against Terraform state and identify drift."""
    actual_region = _resolve_region(region, profile=profile)
    if not actual_region:
        typer.secho("No AWS region found. Pass --region or set AWS_DEFAULT_REGION.", fg=typer.colors.RED)
        raise typer.Exit(1)

    is_json = (output == OutputFormat.json or json_output)

    if not is_json:
        typer.echo(f"Scanning AWS Infrastructure in {actual_region}...\n")

    try:
        results, total_scanned = _run_scan(state, actual_region, profile=profile)

        if is_json:
            highest_severity, _ = _render_json_report(results, total_scanned, actual_region, state, profile=profile)
        else:
            highest_severity, _, _ = _render_report(results, total_scanned, profile=profile)

        if results:
            _dispatch_alerts(results)
            if not is_json:
                typer.echo("Tip: run 'driftwatch remediate <resource_id>' to fix a specific resource.\n")

        _check_gate(highest_severity, fail_on.value if fail_on else None)
    except typer.Exit:
        raise
    except Exception as e:
        typer.secho(f"Error during execution: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

@app.command()
def explain(
    resource_id: str,
    state: str = typer.Option("terraform/terraform.tfstate", help="Path to Terraform state file."),
    region: str = typer.Option(None, help="Target AWS region."),
    profile: str = typer.Option(None, help="AWS CLI profile name to use."),
    from_scan: str = typer.Option(None, "--from-scan", help="Path to JSON file from a previous 'driftwatch scan --json'.")
):
    """Explain the security/operational impact of detected drift using AI and suggest IaC fixes."""
    try:
        if from_scan:
            results, scan_region = _load_from_scan(from_scan)
            actual_region = region or scan_region or _resolve_region(None, profile=profile)
            typer.echo(f"Loaded drift state for {resource_id} from '{from_scan}'...")
        else:
            actual_region = _resolve_region(region, profile=profile)
            if not actual_region:
                typer.secho("No AWS region found. Pass --region or set AWS_DEFAULT_REGION.", fg=typer.colors.RED)
                raise typer.Exit(1)
            typer.echo(f"Fetching current drift state for {resource_id} in {actual_region}...")
            results, _ = _run_scan(state, actual_region, profile=profile)

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
    except typer.Exit:
        raise
    except Exception as e:
        typer.secho(f"Error during execution: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

@app.command()
def remediate(
    resource_id: str = typer.Argument(None, help="Resource ID to remediate (optional if --all is used)."),
    all_resources: bool = typer.Option(False, "--all", "-a", help="Remediate all detected drifted resources."),
    state: str = typer.Option("terraform/terraform.tfstate", help="Path to Terraform state file."),
    region: str = typer.Option(None, help="Target AWS region."),
    profile: str = typer.Option(None, help="AWS CLI profile name to use."),
    from_scan: str = typer.Option(None, "--from-scan", help="Path to JSON file from a previous 'driftwatch scan --json'."),
    dry_run: bool = typer.Option(True, "--dry-run/--apply", help="Dry run mode (default) or apply changes."),
    yes: bool = typer.Option(False, "--yes", "-y", "--force", help="Automatically approve remediation prompts without confirmation."),
):
    """Safely reconcile live infrastructure back to Terraform state."""
    if not resource_id and not all_resources:
        typer.secho("Error: Must specify a resource_id or pass --all to remediate all drifted resources.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    try:
        if from_scan:
            results, scan_region = _load_from_scan(from_scan)
            actual_region = region or scan_region or _resolve_region(None, profile=profile)
            if not actual_region:
                actual_region = "ap-south-1"
        else:
            actual_region = _resolve_region(region, profile=profile)
            if not actual_region:
                typer.secho("No AWS region found. Pass --region or set AWS_DEFAULT_REGION.", fg=typer.colors.RED)
                raise typer.Exit(1)
            results, _ = _run_scan(state, actual_region, profile=profile)

        if all_resources:
            matches = results
        else:
            matches = [r for r in results if r.resource_id == resource_id]

        if not matches:
            target_name = "all resources" if all_resources else resource_id
            typer.secho(f"No current drift found for {target_name}. Run 'driftwatch scan' first.", fg=typer.colors.YELLOW)
            raise typer.Exit(code=1)

        for r in matches:
            typer.secho(f"[{r.drift_type.value}] {r.resource_type}: {r.resource_id}", bold=True)
            for attr, vals in (r.diff or {}).items():
                typer.echo(f"  {attr}: terraform={vals.get('terraform')}  live={vals.get('live')}")

        if dry_run:
            typer.secho("\n[DRY RUN] No changes made. Re-run with --apply to remediate.", fg=typer.colors.BLUE)
            return

        process_remediation(matches, auto_approve=yes, profile=profile)
    except typer.Exit:
        raise
    except Exception as e:
        typer.secho(f"Error during execution: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()