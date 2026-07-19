import dynamiclib.handlers


def handle_dynamic(action: str) -> None:
    name = f"handle_{action}"
    handler = getattr(dynamiclib.handlers, name)
    handler()
