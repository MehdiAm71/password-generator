#!/usr/bin/env python3
"""Secure password and passphrase generator with a CLI."""

from __future__ import annotations

import argparse
import math
import re
import secrets
import shutil
import string
import sys
import textwrap
from dataclasses import dataclass

ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _visible_len(text: str) -> int:
    return len(ANSI_RE.sub("", text))

AMBIGUOUS_CHARS = "lI1O0oB8S5Z2"

DEFAULT_WORDLIST = [
    "apple", "river", "stone", "cloud", "flame", "tiger", "ocean", "brave",
    "eagle", "frost", "grape", "haven", "ivory", "jolly", "karma", "lemon",
    "mango", "noble", "olive", "piano", "quartz", "rapid", "solar", "tulip",
    "urban", "vivid", "wagon", "xenon", "yield", "zebra", "amber", "birch",
    "coral", "delta", "ember", "fable", "grove", "honey", "input", "joker",
    "kayak", "lunar", "mirth", "nexus", "orbit", "pearl", "quiet", "ridge",
    "sable", "trend", "unity", "vapor", "willow", "xerox", "yacht", "zonal",
    "mouse", "floor", "leo", "fly", "back", "hero", "really", "fake",
    "forest", "shadow", "silver", "thunder", "crystal", "wolf", "sunset",
    "arrow", "meadow", "storm", "candle", "falcon", "winter", "mirror",
    "rocket", "island", "velvet", "dragon", "maple", "secret", "comet",
]

LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}


# --------------------------------------------------------------------------
# terminal colors
# --------------------------------------------------------------------------

class Style:
    ENABLED = sys.stdout.isatty()
    BOLD = "\033[1m" if ENABLED else ""
    DIM = "\033[2m" if ENABLED else ""
    GREEN = "\033[92m" if ENABLED else ""
    CYAN = "\033[96m" if ENABLED else ""
    YELLOW = "\033[93m" if ENABLED else ""
    RED = "\033[91m" if ENABLED else ""
    RESET = "\033[0m" if ENABLED else ""


RATING_COLOR = {
    "Very weak": Style.RED,
    "Weak": Style.RED,
    "Fair": Style.YELLOW,
    "Strong": Style.GREEN,
    "Very strong": Style.GREEN,
}


# --------------------------------------------------------------------------
# password policy
# --------------------------------------------------------------------------

@dataclass
class PasswordPolicy:
    length: int = 16
    use_lower: bool = True
    use_upper: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    avoid_ambiguous: bool = False
    symbols: str = "!@#$%^&*()-_=+[]{};:,.<>?/"
    min_of_each: bool = True

    def charset(self) -> str:
        pool = ""
        if self.use_lower:
            pool += string.ascii_lowercase
        if self.use_upper:
            pool += string.ascii_uppercase
        if self.use_digits:
            pool += string.digits
        if self.use_symbols:
            pool += self.symbols

        if not pool:
            raise ValueError("Enable at least one character type (lower/upper/digits/symbols).")

        if self.avoid_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)

        return pool

    def active_groups(self) -> list[str]:
        groups = []
        if self.use_lower:
            groups.append(string.ascii_lowercase)
        if self.use_upper:
            groups.append(string.ascii_uppercase)
        if self.use_digits:
            groups.append(string.digits)
        if self.use_symbols:
            groups.append(self.symbols)

        if self.avoid_ambiguous:
            groups = ["".join(c for c in g if c not in AMBIGUOUS_CHARS) for g in groups]
            groups = [g for g in groups if g]

        return groups


# --------------------------------------------------------------------------
# generation
# --------------------------------------------------------------------------

def _secure_shuffle(items: list) -> None:
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def generate_password(policy: PasswordPolicy) -> str:
    if policy.length < 4:
        raise ValueError("Length must be at least 4.")

    charset = policy.charset()
    groups = policy.active_groups()

    if policy.min_of_each and len(groups) > policy.length:
        raise ValueError(
            f"Length ({policy.length}) is too short to fit one character from each "
            f"enabled type ({len(groups)} types)."
        )

    chars: list[str] = []
    if policy.min_of_each:
        for group in groups:
            chars.append(secrets.choice(group))
        chars.extend(secrets.choice(charset) for _ in range(policy.length - len(chars)))
    else:
        chars = [secrets.choice(charset) for _ in range(policy.length)]

    _secure_shuffle(chars)
    return "".join(chars)


def _transform_keyword(keyword: str) -> str:
    """Turn a user-supplied word into a less predictable chunk (leetspeak + random case)."""
    out = []
    for ch in keyword:
        lower = ch.lower()
        mapped = LEET_MAP.get(lower, ch)
        if mapped.isalpha():
            mapped = mapped.upper() if secrets.choice([True, False]) else mapped.lower()
        out.append(mapped)
    return "".join(out)


def generate_personalized_password(policy: PasswordPolicy, keyword: str) -> str:
    """Blend a transformed keyword into an otherwise random password."""
    keyword = keyword.strip()
    if not keyword:
        return generate_password(policy)

    transformed = list(_transform_keyword(keyword))
    charset = policy.charset()

    if len(transformed) >= policy.length:
        transformed = transformed[: policy.length]
        chars = transformed
    else:
        padding = [secrets.choice(charset) for _ in range(policy.length - len(transformed))]
        chars = transformed + padding

    _secure_shuffle(chars)
    return "".join(chars)


def generate_passphrase(
    word_count: int = 5,
    separator: str = "-",
    capitalize: bool = True,
    add_number: bool = True,
    wordlist: list[str] | None = None,
) -> str:
    words = wordlist or DEFAULT_WORDLIST
    if word_count < 3:
        raise ValueError("Use at least 3 words for a meaningful passphrase.")

    chosen = [secrets.choice(words) for _ in range(word_count)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]

    phrase = separator.join(chosen)
    if add_number:
        phrase += separator + str(secrets.randbelow(900) + 100)

    return phrase


# --------------------------------------------------------------------------
# strength estimation
# --------------------------------------------------------------------------

@dataclass
class StrengthReport:
    length: int
    charset_size: int
    entropy_bits: float
    rating: str
    crack_time_estimate: str


def estimate_strength(password: str) -> StrengthReport:
    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation)
    if any(c.isspace() for c in password):
        pool_size += 1

    if pool_size == 0 or len(password) == 0:
        return StrengthReport(0, 0, 0.0, "Empty", "-")

    entropy = len(password) * math.log2(pool_size)

    guesses_per_second = 1e10
    seconds_to_crack = (2 ** entropy) / (2 * guesses_per_second)
    crack_time = _human_readable_time(seconds_to_crack)

    if entropy < 28:
        rating = "Very weak"
    elif entropy < 36:
        rating = "Weak"
    elif entropy < 60:
        rating = "Fair"
    elif entropy < 80:
        rating = "Strong"
    else:
        rating = "Very strong"

    return StrengthReport(len(password), pool_size, round(entropy, 1), rating, crack_time)


def _human_readable_time(seconds: float) -> str:
    if seconds < 1:
        return "less than a second"

    units = [
        ("centuries", 60 * 60 * 24 * 365 * 100),
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    ]

    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            if value > 1e12:
                return f"over {value:.1e} {name}"
            return f"~{value:,.0f} {name}"

    return "less than a second"


# --------------------------------------------------------------------------
# pretty output
# --------------------------------------------------------------------------

def _box_width() -> int:
    term_width = shutil.get_terminal_size(fallback=(80, 20)).columns
    return max(40, min(term_width - 2, 64))


def _render_box(title: str, sections: list[list[str]]) -> None:
    """sections is a list of groups of lines; groups are separated by a divider."""
    width = _box_width()

    def line(text: str = "") -> str:
        pad = max(width - 3 - _visible_len(text), 0)
        return "║ " + text + " " * pad + "║"

    print("╔" + "═" * (width - 1) + "╗")
    print(line(f"{Style.BOLD}{title}{Style.RESET}"))
    for group in sections:
        print("╟" + "─" * (width - 1) + "╢")
        for raw_line in group:
            for wrapped in textwrap.wrap(raw_line, width - 3) or [""]:
                print(line(wrapped))
    print("╚" + "═" * (width - 1) + "╝")


def print_password_box(password: str, report: StrengthReport, note: str | None = None) -> None:
    color = RATING_COLOR.get(report.rating, "")
    stats = [
        f"Strength     {color}{report.rating}{Style.RESET}",
        f"Entropy      {report.entropy_bits} bits",
        f"Crack time   {report.crack_time_estimate}",
    ]
    sections = [[f"{Style.BOLD}{Style.GREEN}{password}{Style.RESET}"], stats]
    if note:
        sections.append([f"{Style.DIM}{note}{Style.RESET}"])
    _render_box("Generated password", sections)


def print_passphrase_box(phrase: str, report: StrengthReport) -> None:
    color = RATING_COLOR.get(report.rating, "")
    stats = [
        f"Strength     {color}{report.rating}{Style.RESET}",
        f"Entropy      {report.entropy_bits} bits",
        f"Crack time   {report.crack_time_estimate}",
    ]
    sections = [[f"{Style.BOLD}{Style.GREEN}{phrase}{Style.RESET}"], stats]
    _render_box("Generated passphrase", sections)


def print_check_box(password: str, report: StrengthReport) -> None:
    color = RATING_COLOR.get(report.rating, "")
    masked = password[:2] + "*" * max(len(password) - 2, 0)
    stats = [
        f"Input        {masked}",
        f"Strength     {color}{report.rating}{Style.RESET}",
        f"Entropy      {report.entropy_bits} bits",
        f"Crack time   {report.crack_time_estimate}",
    ]
    _render_box("Password check", [stats])


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password_generator",
        description="Generate cryptographically secure passwords and passphrases.",
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--passphrase", action="store_true", help="generate a word-based passphrase instead of a random password")
    mode.add_argument("--check", metavar="PASSWORD", help="evaluate the strength of a given password instead of generating one")

    parser.add_argument("-l", "--length", type=int, default=16, help="password length (default: 16)")
    parser.add_argument("-n", "--count", type=int, default=1, help="how many to generate (default: 1)")
    parser.add_argument("--no-lower", action="store_true", help="exclude lowercase letters")
    parser.add_argument("--no-upper", action="store_true", help="exclude uppercase letters")
    parser.add_argument("--no-digits", action="store_true", help="exclude digits")
    parser.add_argument("--no-symbols", action="store_true", help="exclude special symbols")
    parser.add_argument("--avoid-ambiguous", action="store_true", help="avoid visually similar characters (l, 1, O, 0...)")

    parser.add_argument("--words", type=int, default=5, help="number of words in a passphrase (default: 5)")
    parser.add_argument("--separator", default="-", help="word separator for passphrases (default: -)")

    parser.add_argument("--personalize", metavar="WORD", help="blend a word or name into the password")
    parser.add_argument("--no-personalize", action="store_true", help="skip the personalization prompt")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")

    return parser


def _maybe_ask_for_personalization(args: argparse.Namespace) -> str | None:
    """In an interactive terminal, offer the option to season the password with a personal word."""
    if args.personalize:
        return args.personalize
    if args.no_personalize or not sys.stdin.isatty():
        return None

    answer = input(
        f"{Style.CYAN}Include something memorable (a name, a word)? "
        f"It's optional. [y/N]: {Style.RESET}"
    ).strip().lower()

    if answer != "y":
        return None

    keyword = input("Enter a word or name to blend in: ").strip()
    return keyword or None


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.no_color:
        Style.ENABLED = False
        for attr in ("BOLD", "DIM", "GREEN", "CYAN", "YELLOW", "RED", "RESET"):
            setattr(Style, attr, "")

    try:
        if args.check is not None:
            report = estimate_strength(args.check)
            print_check_box(args.check, report)
            return 0

        if args.passphrase:
            for _ in range(args.count):
                phrase = generate_passphrase(word_count=args.words, separator=args.separator)
                report = estimate_strength(phrase)
                print_passphrase_box(phrase, report)
            return 0

        policy = PasswordPolicy(
            length=args.length,
            use_lower=not args.no_lower,
            use_upper=not args.no_upper,
            use_digits=not args.no_digits,
            use_symbols=not args.no_symbols,
            avoid_ambiguous=args.avoid_ambiguous,
        )

        keyword = _maybe_ask_for_personalization(args)

        for _ in range(args.count):
            if keyword:
                pwd = generate_personalized_password(policy, keyword)
                note = "Personalized password: slightly more guessable than a fully random one."
            else:
                pwd = generate_password(policy)
                note = None
            report = estimate_strength(pwd)
            print_password_box(pwd, report, note)

        return 0

    except ValueError as exc:
        print(f"{Style.RED}Error: {exc}{Style.RESET}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
