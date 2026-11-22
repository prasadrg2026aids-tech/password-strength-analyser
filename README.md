# PASSWORD STRENGTH ANALYSER & GENERATOR

A privacy-first desktop utility that gives local, explainable password-strength feedback and generates random passwords and memorable passphrases with Python's cryptographic `secrets` module.

## Overview

Passwords that look complicated can still be easy to guess when they reuse familiar words, keyboard walks, sequences, or predictable substitutions. This project helps users identify those patterns and create stronger, unique credentials without sending password data to a service.

## Features

- Live password scoring from 0–100 with a five-level strength label.
- Transparent score breakdown for length, character diversity, uniqueness, patterns, and common-password checks.
- Offline detection of common passwords, predictable suffixes, sequences, repeated runs, repeated halves, keyboard patterns, and common substitutions.
- Actionable weakness, risk, and improvement feedback plus a security checklist.
- Approximate entropy estimate for comparison; it is not a crack-time prediction.
- Secure password generation for lengths 8–64, selectable character categories, ambiguous-character exclusion, and up to 10 suggestions.
- Passphrase generation from a local word list with configurable word count, separator, capitalization, and optional number.
- Copy-to-clipboard controls and a dark Tkinter dashboard.
- No password storage, network transmission, or password logging.

## Technology stack

- Python 3.10+
- Tkinter, `re`, `secrets`, `string`, `math`, and `unittest` from the standard library
- No third-party runtime dependencies

## Installation

1. Install Python 3.10 or newer. Ensure the Python installer includes Tcl/Tk (the standard Windows installer does).
2. Clone or download this project and open its folder in VS Code.
3. Optionally create and activate a virtual environment:

   **Windows PowerShell**
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   **macOS/Linux**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

4. No package installation is required. `requirements.txt` documents that the project uses the standard library only.

## Run

From the project directory:

```powershell
py main.py
```

On macOS/Linux, use:

```bash
python3 main.py
```

## Run tests

```powershell
py -m unittest discover -s tests -v
```

Or on macOS/Linux:

```bash
python3 -m unittest discover -s tests -v
```

## Project structure

```text
password-strength-analyser/
├── main.py
├── analyser.py
├── generator.py
├── scoring.py
├── patterns.py
├── common_passwords.py
├── gui/
│   ├── __init__.py
│   └── interface.py
├── tests/
│   ├── test_analyser.py
│   ├── test_generator.py
│   └── test_scoring.py
├── assets/
│   └── README.md
├── requirements.txt
├── README.md
└── .gitignore
```

## Scoring and interpretation

The analyzer assigns up to 30 points for length, 25 for character diversity, 20 for estimated uniqueness, 15 for pattern resistance, and 10 for resistance to the bundled common-password list. Common or predictable passwords are additionally capped at 20, with their displayed category points proportionally adjusted to match the capped total, so adding character types to a known weak base does not make it appear safe.

| Score | Rating |
|---:|---|
| 0–20 | Very Weak |
| 21–40 | Weak |
| 41–60 | Moderate |
| 61–80 | Strong |
| 81–100 | Very Strong |

This is an educational offline heuristic, not a guarantee of security. Do not enter a password you cannot risk exposing on a shared or monitored device.

## Screenshots

No screenshots are currently included. Launch the application and add captures to `assets/` if desired.

## Security and privacy

- Analysis and generation run on-device; the application contains no network client.
- Passwords are not written to files or databases and are not printed to the terminal.
- Password generation uses `secrets`, not `random`, and includes at least one character from every selected category.
- Password entry and generated suggestions are cleared when the window closes.
- Copying uses the system clipboard. Clipboard contents may remain available to other applications until replaced or cleared.
- The analyzer's common-password list is a small, bundled offline list, not an exhaustive breach corpus.
- Entropy and strength scores are approximate and must not be interpreted as a promise against attack.

## Future improvements

- Optional, user-supplied local dictionary expansion.
- Accessible themes and additional localization.
- GUI automation tests on supported desktop platforms.
- More research-backed password-strength estimation with clearly documented limitations.

## License

No license has been selected. Add a license before redistributing this project.
