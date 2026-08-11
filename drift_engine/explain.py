import os
import json
import requests

def get_drift_explanation(resource_type, resource_id, diff_data, drift_type):
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    
    if not api_key:
        return "AI explanation unavailable: GROQ_API_KEY not set in environment."

    url = "https://api.groq.com/openai/v1/chat/completions"
    
    prompt = (
        f"You are a strict AWS DevOps expert. Analyze this infrastructure drift.\n"
        f"Resource Type: {resource_type}\n"
        f"Resource ID: {resource_id}\n"
        f"Drift Type: {drift_type}\n"
        f"Diff Data: {json.dumps(diff_data)}\n\n"
        f"Strict Remediation Rules based on Drift Type:\n"
        f"- UNMANAGED: This resource exists in AWS but is not tracked by Terraform state. The ONLY fix is to provide an exact `terraform import` command. Do NOT create a resource block.\n"
        f"- MISSING: This resource exists in Terraform state but was manually deleted from AWS. The fix is to provide a fresh Terraform resource block to recreate it.\n"
        f"- MODIFIED: This resource attributes in AWS differ from Terraform state. Provide a short Terraform snippet to correct the drift.\n\n"
        f"Provide a brief, plain-English explanation of the security or operational risk (max 3 sentences). "
        f"Then, provide the exact Terraform fix as instructed above."
    )

    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": "You are a helpful AWS DevOps assistant."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
    }
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"AI API Error (Groq): {e}"