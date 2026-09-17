__version__ = "3.0.2"

try:
    import drift_engine as engine
except ImportError:
    engine = None

__all__ = ["__version__", "engine"]
