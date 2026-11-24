from app.core.base import ReconModule

_REGISTRY: dict[str, ReconModule] = {}


def register(cls):
    """Class decorator: creates one instance and files it under its id."""
    instance = cls()
    if instance.id in _REGISTRY:
        raise ValueError(f"Duplicate module id: {instance.id}")
    _REGISTRY[instance.id] = instance
    return cls


def get_module(module_id: str) -> ReconModule | None:
    return _REGISTRY.get(module_id)


def all_modules() -> list[ReconModule]:
    return list(_REGISTRY.values())