import json

class StateResourceDict(dict):
    """Resource dictionary keyed by (resource_type, resource_id) to prevent collisions.

    F5: Key resources by (resource_type, resource_id) throughout parsing/comparison.
    Supports backwards-compatible lookups and assignments by string resource_id.
    """
    def __getitem__(self, key):
        if isinstance(key, tuple):
            return super().__getitem__(key)
        for (rtype, rid), val in self.items():
            if rid == key:
                return val
        raise KeyError(key)

    def __contains__(self, key):
        if isinstance(key, tuple):
            return super().__contains__(key)
        for (rtype, rid) in self.keys():
            if rid == key:
                return True
        return False

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __setitem__(self, key, value):
        if isinstance(key, tuple):
            super().__setitem__(key, value)
        else:
            r_type = value.get("type", "unknown") if isinstance(value, dict) else "unknown"
            super().__setitem__((r_type, key), value)

def load_terraform_state(state_path: str, profile: str = None) -> StateResourceDict:
    if state_path.startswith("s3://"):
        parts = state_path[5:].split("/", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError(f"Invalid S3 state URI '{state_path}'. Expected format: s3://<bucket>/<key>")
        bucket, key = parts
        try:
            from drift_engine.aws_client import get_boto3_client
            s3 = get_boto3_client("s3", profile=profile)
            response = s3.get_object(Bucket=bucket, Key=key)
            content = response["Body"].read().decode("utf-8")
            state = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Terraform state file at '{state_path}' is corrupted or invalid JSON: {e}")
        except Exception as e:
            err_str = str(e)
            if "NoSuchBucket" in err_str or "NoSuchKey" in err_str or "404" in err_str:
                raise FileNotFoundError(f"Terraform state file not found in S3 at '{state_path}': {e}")
            raise RuntimeError(f"Failed to fetch Terraform state from S3 '{state_path}': {e}")
    else:
        try:
            with open(state_path) as f:
                state = json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Terraform state file not found at '{state_path}'")
        except json.JSONDecodeError as e:
            raise ValueError(f"Terraform state file at '{state_path}' is corrupted or invalid JSON: {e}")

    resources = StateResourceDict()

    for resource in state.get("resources", []):
        r_type = resource.get("type", "")

        if r_type == "archive_file":
            continue

        for instance in resource.get("instances", []):
            attrs = instance.get("attributes", {})

            if r_type == "aws_iam_role_policy_attachment":
                role_name = attrs.get("role")
                policy_arn = attrs.get("policy_arn")
                if role_name and policy_arn:
                    role_key = ("aws_iam_role", role_name)
                    if role_key not in resources:
                        resources[role_key] = {
                            "type": "aws_iam_role",
                            "name": role_name,
                            "attributes": {"id": role_name, "name": role_name, "attached_policies": []}
                        }
                    if "attached_policies" not in resources[role_key]["attributes"]:
                        resources[role_key]["attributes"]["attached_policies"] = []
                    resources[role_key]["attributes"]["attached_policies"].append(policy_arn)
                    resources[role_key]["attributes"]["attached_policies"].sort()
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
                composite_key = (r_type, resource_id)
                if composite_key in resources and r_type == "aws_iam_role":
                    existing_policies = resources[composite_key]["attributes"].get("attached_policies", [])
                    attrs["attached_policies"] = sorted(set(
                        attrs.get("attached_policies", []) + existing_policies
                    ))

                resources[composite_key] = {
                    "type": r_type,
                    "name": name,
                    "attributes": attrs
                }

    return resources
