from .builtin import BUILTIN
from .external import EXTERNAL

REGISTRY = {t.id: t for t in EXTERNAL + BUILTIN}
CATEGORIES = ["Recon", "Scanning", "Web", "Network", "Passwords"]


def describe_all():
    return [t.to_dict() for t in REGISTRY.values()]
