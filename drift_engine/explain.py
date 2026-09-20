import os
import re
import json
import requests

SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|secret|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|auth)",
    re.IGNORECASE
)
ACCOUNT_ID_PATTERN = re.compile(r"\b\d{12}\b")
AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PRIVATE_IP_PATTERN = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?:/\d{1,2})?\b"
)

def sanitize_value(val):
    if isinstance(val, str):
        val = ACCOUNT_ID_PATTERN.sub("[ACCOUNT_ID]", val)
        val = AWS_KEY_PATTERN.sub("[AWS_ACCESS_KEY]", val)
        val = PRIVATE_IP_PATTERN.sub("[PRIVATE_IP_OR_CIDR]", val)
        return val
    elif isinstance(val, dict):
        sanitized = {}
        for k, v in val.items():
            if SENSITIVE_KEY_PATTERN.search(str(k)):
                sanitized[k] = "[REDACTED_SECRET]"
            else:
                sanitized[k] = sanitize_value(v)
        return sanitized
    elif isinstance(val, list):
        return [sanitize_value(item) for item in val]
    elif isinstance(val, tuple):
        return tuple(sanitize_value(item) for item in val)
    return val

def sanitize_diff_for_ai(diff_data: dict) -> dict:
    if not isinstance(diff_data, dict):
        return diff_data
    return sanitize_value(diff_data)

def get_deterministic_remediation_suggestion(resource_type: str, resource_id: str, diff_data: dict, drift_type: str) -> str:

    safe_name = resource_id.replace("-", "_").replace(".", "_").replace("/", "_")

    if drift_type == "UNMANAGED":
        return (
            f"# To bring this unmanaged {resource_type} into Terraform state:\n"
            f"terraform import {resource_type}.{safe_name} {resource_id}"
        )
    elif drift_type == "MISSING":
        return (
            f"# To recreate this missing {resource_type} defined in IaC:\n"
            f"terraform apply -target={resource_type}.{safe_name}"
        )
    elif drift_type == "MODIFIED":
        lines = [f"# To align live {resource_type} ({resource_id}) with Terraform configuration:"]
        if diff_data:
            for attr, vals in diff_data.items():
                if isinstance(vals, dict) and "terraform" in vals:
                    lines.append(f"# Set attribute '{attr}' to: {vals['terraform']}")
        lines.append(f"terraform apply -target={resource_type}.{safe_name}")
        return "\n".join(lines)

    return "terraform refresh"

def get_drift_explanation(resource_type: str, resource_id: str, diff_data: dict, drift_type: str) -> str:
    api_key = os.environ.get("GROQ_API_KEY", "").strip()

    if not api_key:
        return "AI explanation unavailable: GROQ_API_KEY not set in environment."

    url = "https://api.groq.com/openai/v1/chat/completions"
    sanitized_id = sanitize_value(resource_id)
    sanitized_diff = sanitize_diff_for_ai(diff_data)
    formatted_diff = json.dumps(sanitized_diff, indent=2)

    prompt = (
        f"You are a strict AWS Cloud Security and Reliability expert. Analyze the following infrastructure drift:\n"
        f"Resource Type: {resource_type}\n"
        f"Resource ID: {sanitized_id}\n"
        f"Drift Type: {drift_type}\n"
        f"Diff Details:\n{formatted_diff}\n\n"
        f"Provide a concise, plain-English summary (2-3 sentences max) explaining ONLY the security risks, "
        f"compliance implications, or operational impact of this drift. "
        f"Do NOT generate or guess CLI commands or Terraform scripts."
    )


    preferred_model = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
    candidate_models = [preferred_model]
    for fallback in ["llama-3.3-70b-versatile", "openai/gpt-oss-20b", "llama-3.1-8b-instant"]:
        if fallback not in candidate_models:
            candidate_models.append(fallback)

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    last_error = None
    for model_name in candidate_models:
        payload = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": "You are an AWS infrastructure and security analyst. Provide concise risk analyses only."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2
        }

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            return data.get("choices", [{}])[0].get("message", {}).get("content", "No risk analysis generated.")

        except requests.exceptions.HTTPError as http_err:
            status_code = getattr(http_err.response, "status_code", None)
            err_msg = str(http_err)
            try:
                err_json = http_err.response.json()
                err_msg = err_json.get("error", {}).get("message", err_msg)
            except Exception:
                pass

            # If model was retired / not found (404), try next candidate model
            if status_code == 404 and model_name != candidate_models[-1]:
                continue

            return f"AI API Error (Groq): {err_msg}"

        except requests.exceptions.RequestException as req_err:
            return f"AI API Network Error (Groq): {req_err}"
        except Exception as e:
            return f"AI API Error (Groq): {str(e)}"

    return f"AI API Error (Groq): {last_error or 'No available Groq model could fulfill the request.'}"
