from dangerlib.vuln import dangerous_call


def handle_direct() -> None:
    dangerous_call("user-input")
