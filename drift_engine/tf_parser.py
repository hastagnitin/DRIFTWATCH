import json

def load_terraform_state(state_path: str) -> dict:
    try:
        with open(state_path) as f:
            state = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Terraform state file not found at '{state_path}'")
    except json.JSONDecodeError as e:
        raise ValueError(f"Terraform state file at '{state_path}' is corrupted or invalid JSON: {e}")
        
    resources = {}
    
    for resource in state.get("resources", []):
        r_type = resource["type"]
        
        if r_type == "archive_file":
            continue
            
        for instance in resource.get("instances", []):
            attrs = instance.get("attributes", {})
            
            if r_type == "aws_iam_role_policy_attachment":
                role_name = attrs.get("role")
                policy_arn = attrs.get("policy_arn")
                if role_name and policy_arn:
                    if role_name not in resources:
                        resources[role_name] = {
                            "type": "aws_iam_role", 
                            "name": role_name, 
                            "attributes": {"id": role_name, "name": role_name, "attached_policies": []}
                        }
                    if "attached_policies" not in resources[role_name]["attributes"]:
                        resources[role_name]["attributes"]["attached_policies"] = []
                    resources[role_name]["attributes"]["attached_policies"].append(policy_arn)
                    resources[role_name]["attributes"]["attached_policies"].sort()
                continue

            resource_id = attrs.get("id")
            
            tags = attrs.get("tags", {})
            if tags and tags.get("Name"):
                name = tags.get("Name")
            elif r_type == "aws_lambda_function":
                name = attrs.get("function_name", "Unknown")
            elif r_type == "aws_db_instance":
                name = attrs.get("identifier", "Unknown")
            elif r_type == "aws_iam_role":
                name = attrs.get("name", "Unknown")
                if "attached_policies" not in attrs:
                    attrs["attached_policies"] = []
            else:
                name = "Unknown"
            
            if resource_id:
                if resource_id in resources and r_type == "aws_iam_role":
                    existing_policies = resources[resource_id]["attributes"].get("attached_policies", [])
                    attrs["attached_policies"] = sorted(set(
                        attrs.get("attached_policies", []) + existing_policies
                    ))
                    
                resources[resource_id] = {
                    "type": r_type, 
                    "name": name, 
                    "attributes": attrs
                }
                
    return resources