from drift_engine.core import compare_attributes, DriftType

def test_ignored_attributes_do_not_trigger_drift():
    tf = {"id": "i-123", "private_ip": "10.0.0.5"}
    live = {"id": "i-123", "private_ip": "10.0.0.9"}
    
    diff = compare_attributes(tf, live, "aws_instance")
    
    assert diff == {}

def test_real_attribute_change_is_detected():
    tf = {"id": "i-123", "instance_type": "t3.micro"}
    live = {"id": "i-123", "instance_type": "t3.small"}
    
    diff = compare_attributes(tf, live, "aws_instance")
    
    assert "instance_type" in diff
    assert diff["instance_type"]["terraform"] == "t3.micro"
    assert diff["instance_type"]["live"] == "t3.small"

def test_security_group_changes_are_detected():
    tf_attrs = {"id": "sg-123", "description": "Managed by TF"}
    live_attrs = {"id": "sg-123", "description": "Manual edit in AWS"}
    
    diff = compare_attributes(tf_attrs, live_attrs, "aws_security_group")
    
    assert "description" in diff
    assert diff["description"]["terraform"] == "Managed by TF"
    assert diff["description"]["live"] == "Manual edit in AWS"