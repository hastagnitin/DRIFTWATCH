import os
import json
import requests
import urllib.parse

def get_drift_explanation(resource_type, resource_id, diff_data):
    raw_key = os.environ.get("GEMINI_API_KEY", "")
    api_key = "".join(raw_key.split())
    
    if not api_key:
        return "AI explanation unavailable: GEMINI_API_KEY not set in environment."

    safe_key = urllib.parse.quote(api_key)
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={safe_key}"
    
    prompt = (
        f"You are a strict AWS DevOps expert. Analyze this infrastructure drift.\n"
        f"Resource Type: {resource_type}\n"
        f"Resource ID: {resource_id}\n"
        f"Diff Data: {json.dumps(diff_data)}\n\n"
        f"Provide a brief, plain-English explanation of the security or operational risk (max 3 sentences). "
        f"Then, provide a short Terraform code snippet to fix it."
    )

    payload = {
        "contents": [{"parts": [{"text": prompt}]}]
    }
    
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        error_msg = str(e).replace(safe_key, "[HIDDEN_API_KEY]").replace(api_key, "[HIDDEN_API_KEY]")
        return f"AI API Error: {error_msg}"