from __future__ import annotations

import string

from scripts.password_gen import generate


def test_password_length_and_alphabet() -> None:
    password = generate(12, digits=False, symbols=False)
    assert len(password) == 12
    assert all(char in string.ascii_letters for char in password)


def test_password_with_symbols() -> None:
    password = generate(20, digits=True, symbols=True)
    allowed = set(string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?")
    assert len(password) == 20
    assert set(password) <= allowed

