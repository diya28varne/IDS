"""Allow `python -m threatlens` as a foundation sanity check."""

from threatlens import __version__


def main() -> None:
    print(f"threatlens {__version__}")
    print("foundation ok — no models or datasets loaded")


if __name__ == "__main__":
    main()
