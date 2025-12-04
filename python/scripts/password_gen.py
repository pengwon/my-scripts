from __future__ import annotations

import argparse
import secrets
import string


def generate(length: int, digits: bool = True, symbols: bool = False) -> str:
    alphabet = string.ascii_letters
    if digits:
        alphabet += string.digits
    if symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?"
    if not alphabet:
        raise ValueError("Alphabet is empty")
    return "".join(secrets.choice(alphabet) for _ in range(length))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a random password")
    parser.add_argument("length", type=int)
    parser.add_argument("--no-digits", dest="digits", action="store_false", default=True)
    parser.add_argument("--symbols", action="store_true", default=False)
    args = parser.parse_args(argv)
    print(generate(args.length, digits=args.digits, symbols=args.symbols))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

