from sample_app.direct import handle_direct
from sample_app.dynamic import handle_dynamic
from sample_app.unused_import import harmless


def main() -> None:
    handle_direct()
    harmless()
    handle_dynamic("run")


if __name__ == "__main__":
    main()
