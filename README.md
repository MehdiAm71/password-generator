# Password Generator

A command-line tool that generates strong, cryptographically secure passwords and passphrases — with clean terminal output and an optional way to blend in something memorable.

## Why this exists

Most "password generator" scripts you find online just wrap `random.choice()` in a loop, which is fine for a demo but not something you'd actually trust. This project uses Python's `secrets` module for every random decision, which is the standard library's interface to your OS's cryptographically secure random source. It also estimates the actual entropy of what it generates instead of just printing a string and calling it "strong."

## Features

- **Cryptographically secure** — built on `secrets`, not `random`.
- **Two generation modes** — random character passwords, or word-based passphrases (diceware-style).
- **Make sure your password is strong** — This tool allows you to determine if your password is strong enough or weak and needs to be changed.
- **Optional personalization** — you can choose to blend a name or word into the password; the tool asks, you decide.
- **Strength report** — entropy in bits, a rating, and an estimated crack time, shown for everything it generates.
- **Clean CLI output** — results are shown in a readable box, not a bare line of text.
- **Zero dependencies** — pure Python standard library.

## Installation

```bash
git clone https://github.com/USERNAME/password-generator.git
cd password-generator
```

Requires **Python 3.10+**. Nothing to install — no `pip install` needed.

## Usage

### Generate a password

```bash
python password_generator.py
```

```
╔═══════════════════════════════════════════════════════════════╗
║ Generated password                                             ║
╟─────────────────────────────────────────────────────────────╢
║ 6bn&{q<gn<vWnK]EX<fS                                           ║
╟─────────────────────────────────────────────────────────────╢
║ Strength     Very strong                                       ║
║ Entropy      131.1 bits                                        ║
║ Crack time   over 4.6e+19 centuries                            ║
╚═══════════════════════════════════════════════════════════════╝
```

If you're running it in an interactive terminal, it will ask once whether you'd like to include something memorable (a name, a word) in the password. It's entirely optional — say no and it stays fully random. For scripts or automation, this prompt is skipped automatically.

### Choose your own length and count

```bash
python password_generator.py --length 24 --count 5
```

### Avoid look-alike characters (useful if you're typing it by hand)

```bash
python password_generator.py --avoid-ambiguous
```

### Turn off a character type

```bash
python password_generator.py --no-symbols --no-upper
```

### Generate a passphrase instead

```bash
python password_generator.py --passphrase --words 6 --separator "_"
```

```
Ember_Amber_Lunar_Jolly_Willow_Kayak_452
```

### Check the strength of a password you already have

```bash
python password_generator.py --check "MyP@ssw0rd123"
```

### Skip the personalization prompt, or supply the word directly

```bash
python password_generator.py --no-personalize
python password_generator.py --personalize "shadowfax"
```

## All options

| Option | Description | Default |
|---|---|---|
| `-l`, `--length` | password length | `16` |
| `-n`, `--count` | how many to generate | `1` |
| `--no-lower` | exclude lowercase letters | off |
| `--no-upper` | exclude uppercase letters | off |
| `--no-digits` | exclude digits | off |
| `--no-symbols` | exclude symbols | off |
| `--avoid-ambiguous` | avoid look-alike characters | off |
| `--passphrase` | generate a passphrase instead | off |
| `--words` | words per passphrase | `5` |
| `--separator` | passphrase word separator | `-` |
| `--personalize WORD` | blend a word/name in directly | — |
| `--no-personalize` | skip the personalization prompt | off |
| `--check PASSWORD` | evaluate an existing password | — |
| `--no-color` | disable colored output | off |

## Running the tests

```bash
python -m unittest tests/test_generator.py -v
```

## How it works

- Every character is chosen with `secrets.choice()`, which pulls from your OS's CSPRNG — `random.choice()` is not designed for this and should never be used for anything security-related.
- When `min_of_each` is on (the default), the generator guarantees at least one character from every enabled type, then shuffles the result with a `secrets`-based Fisher–Yates shuffle so the required characters don't end up in predictable positions.
- Personalization takes your word, applies light leetspeak substitution and random casing, then pads the rest of the password with fully random characters and shuffles everything together. It's a middle ground between "impossible to remember" and "fully random" — the tool tells you when a password was personalized so you know the trade-off.
- Strength is estimated as `length × log2(charset size)`, then converted into a rough crack-time estimate assuming an attacker capable of 10 billion guesses per second.

## What could be added next

This covers the core use case well, but there's room to grow:

- Swap the built-in 56-word list for the full **EFF long wordlist** (7,776 words) for passphrases with real diceware-level entropy.
- **Clipboard support** (`pyperclip`) so the password never has to touch your terminal history.
- **Encrypted export** — save a batch of generated passwords to a file protected by a master password.
- A **config file** (`~/.password-generator.toml`) to store your preferred defaults.
- **GitHub Actions workflow** to run the test suite on every push.
- Packaging for **PyPI** so it's installable with `pip install` and runnable as a plain command.
- A minimal **web or GUI version** for people who don't want to touch a terminal.

Contributions welcome — pick any of these up, or open an issue with your own idea.

## Security note

This is meant for personal and educational use. If you're generating credentials for a real system with real users, also make sure you're hashing and salting stored passwords, using an established password manager for personal storage, and never sending passwords over unencrypted channels.

## License

MIT — see [LICENSE](LICENSE).
