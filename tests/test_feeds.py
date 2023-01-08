"""Tests for feeds.py
"""

from modules.utils.feeds import generate_hostname_expressions_


def test_generate_hostname_expressions_() -> None:
    """Test `generate_hostname_expressions_`"""

    test_cases: list[tuple[str, list[str]]] = [
        ("", []),  # Empty string
        (" ", []),  # Empty space
        ("1.1.1.1", ["1.1.1.1"]),  # IPv4 Address
        ("1.1.1.1/a/b/c", ["1.1.1.1/a/b/c"]),  # IPv4 Address + Path
        ("localhost", ["localhost"]),  # Invalid Domain
        ("localhost/a/b/c", ["localhost/a/b/c"]),  # Invalid Domain + Path
        ("example.com", ["www.example.com", "example.com", "www.example.com", "example.com"]),  # Domain
        ("example.com/a/b/c", ["www.example.com", "example.com", "www.example.com/a/b/c", "example.com/a/b/c"]),  # Domain + Path
        ("www.example.com", ["www.example.com", "example.com", "www.example.com", "example.com"]),  # www SubDomain + Domain
        (
            "www.example.com/a/b/c",
            ["www.example.com", "example.com", "www.example.com/a/b/c", "example.com/a/b/c"],
        ),  # www SubDomain + Domain + Path
        ("monty.example.com", ["monty.example.com", "example.com", "monty.example.com", "www.example.com"]),  # Non-www SubDomain + Domain
        (
            "monty.example.com/a/b/c",
            ["monty.example.com", "example.com", "monty.example.com/a/b/c", "www.example.com"],
        ),  # Non-www SubDomain + Domain + Path
        (
            "monty.pythons.flying.circus.example.com",
            [
                "monty.pythons.flying.circus.example.com",
                "example.com",
                "circus.example.com",
                "flying.circus.example.com",
                "pythons.flying.circus.example.com",
                "monty.pythons.flying.circus.example.com",
                "www.example.com",
            ],
        ),  # Length 4 Non-www SubDomain + Domain
        (
            "monty.pythons.flying.circus.example.com/a/b/c",
            [
                "monty.pythons.flying.circus.example.com",
                "example.com",
                "circus.example.com",
                "flying.circus.example.com",
                "pythons.flying.circus.example.com",
                "monty.pythons.flying.circus.example.com/a/b/c",
                "www.example.com",
            ],
        ),  # Length 4 Non-www SubDomain + Domain + Path
        (
            "the.monty.pythons.flying.circus.example.com",
            [
                "the.monty.pythons.flying.circus.example.com",
                "example.com",
                "circus.example.com",
                "flying.circus.example.com",
                "pythons.flying.circus.example.com",
                "the.monty.pythons.flying.circus.example.com",
                "www.example.com",
            ],
        ),  # Length 5 Non-www SubDomain + Domain
        (
            "the.monty.pythons.flying.circus.example.com/a/b/c",
            [
                "the.monty.pythons.flying.circus.example.com",
                "example.com",
                "circus.example.com",
                "flying.circus.example.com",
                "pythons.flying.circus.example.com",
                "the.monty.pythons.flying.circus.example.com/a/b/c",
                "www.example.com",
            ],
        ),  # Length 5 Non-www SubDomain + Domain + Path
    ]
    for url, expected in test_cases:
        assert generate_hostname_expressions_(url) == expected, f"{url} expressions incorrect"
