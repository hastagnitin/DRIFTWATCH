"""DriftWatch Core Engine

Provides multi-resource Terraform infrastructure drift detection, diff calculation,
data-driven severity scoring, and guarded remediation handlers.
"""

from drift_engine.core import detect_drift, get_severity
from drift_engine.models import DriftResult, DriftType, MONITORED_ATTRIBUTES, ATTRIBUTE_SEVERITY

__all__ = [
    "detect_drift",
    "get_severity",
    "DriftResult",
    "DriftType",
    "MONITORED_ATTRIBUTES",
    "ATTRIBUTE_SEVERITY",
]
