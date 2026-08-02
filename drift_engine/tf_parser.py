import json

def load_terraform_state(state_path: str) -> dict:
    try:
        with open(state_path) as f:
            state = json.load(f)
    except FileNotFoundError:
        print(f"Error: Terraform state file not found at '{state_path}'")
        return {}
        
    resources = {}
    for resource in state.get("resources", []):
        r_type = resource["type"]
        
        if r_type in ["archive_file", "aws_iam_role_policy_attachment"]:
            continue
            
        for instance in resource.get("instances", []):
            attrs = instance.get("attributes", {})
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
            else:
                name = "Unknown"
            
            if resource_id:
                resources[resource_id] = {
                    "type": r_type, 
                    "name": name, 
                    "attributes": attrs
                }
    return resources