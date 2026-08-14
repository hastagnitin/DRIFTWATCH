import typer
import os
import sys
from datetime import datetime

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
sys.path.append(os.path.join(base_dir, "drift_engine"))

env_file = os.path.join(base_dir, ".env")
if os.path.exists(env_file):
    with open(env_file, "r") as f:
        for line in f:
            stripped_line = line.strip()
            if stripped_line and not stripped_line.startswith("#"):
                if "=" in stripped_line:
                    k, v = stripped_line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

from drift_engine.core import detect_drift, get_severity, get_resource_cost, process_drift_results
from drift_engine.explain import get_drift_explanation
from drift_engine.models import DriftType
from drift_engine.notifications import process_alerts
from drift_engine.database import save_drift_to_db
from drift_engine.remediation import process_remediation

app = typer.Typer()

@app.command()
def scan(
    state: str = typer.Option("terraform/terraform.tfstate"),
    region: str = typer.Option("ap-south-1"),
    fail_on: str = typer.Option(None)
):
    typer.echo("Scanning AWS Infrastructure...\n")
    os.environ["TF_STATE_PATH"] = state
    os.environ["AWS_DEFAULT_REGION"] = region
    
    try:
        results, total_scanned = detect_drift(state, region)
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
            
            if severity == "CRITICAL":
                crit_count += 1
                highest_severity_found = "CRITICAL"
                color = typer.colors.RED
            elif severity == "HIGH":
                high_count += 1
                if highest_severity_found != "CRITICAL":
                    highest_severity_found = "HIGH"
                color = typer.colors.YELLOW
            else:
                color = typer.colors.BLUE

            typer.secho(f"[{r.drift_type.value}] {r.resource_type}: {r.resource_id}", fg=color, bold=True)
            ai_text = ""
            
            if r.drift_type == DriftType.UNMANAGED and r.resource_type == "aws_instance":
                cost = "{:,.2f}".format(get_resource_cost(r.resource_id))
                inst_type = r.live_attributes.get("instance_type", "unknown")
                typer.echo(f"  Type: {inst_type} (created manually in console)")
                typer.echo(f"  Severity: {severity} | Cost: +Rs.{cost}/month (untracked)")
                
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
                
            process_drift_results(r.resource_id, r.drift_type.value, ai_text)
            
        typer.echo(f"Total drift found: {total_drift} resources  |  CRITICAL: {crit_count}  HIGH: {high_count}\n")
        
        process_alerts(results)
        save_drift_to_db(results)
        process_remediation(results)
            
        if fail_on and highest_severity_found == fail_on.upper():
            typer.secho(f"\nBUILD FAILED: {fail_on} drift detected!", fg=typer.colors.RED, bold=True)
            raise typer.Exit(code=1)

    except Exception as e:
        typer.secho(f"Error during execution: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

@app.command()
def explain(resource_id: str):
    typer.echo(f"Fetching AI explanation for {resource_id} (using Groq)...")
    ai_text = get_drift_explanation("unknown", resource_id, {}, "UNKNOWN")
    typer.echo(f"\nAI Analysis:\n{ai_text}")

if __name__ == "__main__":
    app()