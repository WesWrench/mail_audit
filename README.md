# Mail Audit

Email security audit toolkit: three Python packages that check how a domain's mail can be
spoofed or intercepted.

| Package | What it checks | Can run alone |
|---|---|---|
| [`smtp_checker`](smtp_checker/README.md) | MX servers: STARTTLS, certificates, DANE/TLSA, MTA-STS, DNSSEC, open relay | Yes |
| [`mail_antispoof_policy_checker`](mail_antispoof_policy_checker/README.md) | DNS policies: SPF, DMARC, DKIM, dangerous SPF includes, CNAME takeover, unregistered domains | Yes |
| [`mail_audit`](mail_audit/README.md) | Runs both tools above, then builds attack scenarios (spoofing, MITM, open relay, domain takeover) rated by probability and risk | Needs the two others |

```
mail_audit ──imports──► smtp_checker
           └─imports──► mail_antispoof_policy_checker
```

`smtp_checker` and `mail_antispoof_policy_checker` do not depend on each other or on
`mail_audit`. Use them on their own when you only need one side of the audit.

---

## Disclaimer

This tool is a **proof of concept** provided for **educational purposes only**. Do not use it for offensive operations. Use it only in a controlled lab environment where you own the systems or have explicit permission to test them.

The software is provided **as is**, without warranty or technical support. You are responsible for how you use it and for complying with applicable laws.

---

## How the packages find each other

`mail_audit` uses **absolute package imports**, not relative `../` paths:

```python
from smtp_checker.lib import DomainChecker
from mail_antispoof_policy_checker.lib import SPFChecker, DMARCChecker, DKIMChecker
```

For these imports to resolve, **the three folders must be installed as Python packages**.
Each folder has its own `pyproject.toml`. Install them in **editable mode** (`pip install -e`):
Python then imports straight from this repository, so a `git pull` or a local edit applies
immediately with no reinstall.

The sibling packages are not published on PyPI. That is why `mail_audit/pyproject.toml`
does not list them as dependencies: pip would try to download them and fail. Install them
from the local folders as shown below.

---

## Installation

Requirements: **Python 3.9+** and `git`.

```bash
git clone <repository-url> "Mail Audit"
cd "Mail Audit"

# 1. Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate          # Linux / macOS / WSL
.venv\Scripts\activate             # Windows (cmd or PowerShell)

# 2. Install the three packages in editable mode, with their dependencies
pip install -r requirements.txt
```

`requirements.txt` only runs, in order:

```bash
pip install -e ./smtp_checker
pip install -e ./mail_antispoof_policy_checker
pip install -e ./mail_audit
```

### Installing a single tool

Only install what you need:

```bash
pip install -e ./smtp_checker                      # SMTP / TLS / DANE / MTA-STS checks only
pip install -e ./mail_antispoof_policy_checker     # SPF / DMARC / DKIM checks only
```

`mail_audit` requires both: install `smtp_checker` and `mail_antispoof_policy_checker`
**before** `mail_audit`.

### Check the installation

```bash
pip list | grep -iE "smtp-checker|antispoof|mail-audit"     # Windows: findstr /i "smtp antispoof mail-audit"
python -c "import smtp_checker, mail_antispoof_policy_checker, mail_audit; print(mail_audit.__file__)"
```

The printed path must point into **this** clone. Editable installs are global to the Python
environment: if the packages were installed earlier from another copy of the repository,
the tools silently run that other copy. Reinstall from this folder (`pip install -r
requirements.txt`) or use a dedicated virtual environment.

---

## Optional components

| Component | Used for | Without it |
|---|---|---|
| MaxMind license key: `--maxmind-key` or env `MAXMIND_LICENSE_KEY` (free GeoLite2 account) | AS organization of SPF IP ranges | AS organization lookups are skipped |
| `mail_antispoof_policy_checker/lib/domain/` (WHOIS/RDAP + availability checkers) | Unregistered domains in SPF includes and CNAME targets (domain takeover) | That check is disabled. Everything else runs |
| factordb.com (public website, no account) | Known factorizations of DKIM RSA moduli (`dkim_rsa_known_factorization`) | Unreachable or `--skip-factordb-check`: the offline key checks (exponent, small factor, prime modulus) still run |
| `lib/domain/domain_availability_service_checker/` (registrar APIs) | Last stage of the availability check, for domains WHOIS/RDAP cannot decide | NS + WHOIS/RDAP still decide. Undecided domains are reported *potentially unregistered* |

### MaxMind license key

Create a free account at <https://www.maxmind.com/en/geolite2/signup>, generate a license
key, then pass it in **one of two ways**. Never write the key in the code, a README or a
committed file.

**1. Environment variable `MAXMIND_LICENSE_KEY`** (recommended: the key stays out of your
shell history and command lines). It applies to the current terminal session only:

```powershell
# PowerShell
$env:MAXMIND_LICENSE_KEY = "your_license_key_here"
```

```bash
# bash / zsh (Linux, macOS, WSL, Git Bash)
export MAXMIND_LICENSE_KEY="your_license_key_here"
```

```bat
:: Windows cmd (no quotes, no spaces around =)
set MAXMIND_LICENSE_KEY=your_license_key_here
```

To make it permanent: `setx MAXMIND_LICENSE_KEY "your_license_key_here"` on Windows
(applies to *new* terminals), or the `export` line in `~/.bashrc` / `~/.zshrc`.

**2. Command-line argument `--maxmind-key`** (overrides the environment variable):

```bash
mail-audit -i example.com --maxmind-key your_license_key_here
```

The key is validated at startup. Without a valid key, AS organization lookups are skipped
and everything else runs. The MaxMind databases are downloaded on first use into
`mail_antispoof_policy_checker/utils/maxmind/`, then refreshed on MaxMind's release days.
That folder is git-ignored.

---

## Usage

### Full audit (`mail_audit`)

After installation the `mail-audit` command is available from any directory:

```bash
mail-audit -i domains.txt \
    --dkim-selector-file selector.txt \
    --sender test@your-domain.com --recipient someone@external-domain.com \
    --async-mode --output-dir ./output -o audit
```

`python cli.py …` from inside `mail_audit/` works too.

- `-i`: a domain, a comma-separated list, or a file with one domain per line.
- `--dkim-selector-file`: your own DKIM selectors, one per line (default: bundled list).
- `--sender` / `--recipient`: enable the open relay test. Without them it is skipped.
  `--open-relay-mode rcpt|data` sets how far it goes. No message content is ever sent.

Output in `--output-dir`: one JSON + one Excel per tool (`*_smtp`, `*_antispoof`) and the
combined report (`audit.json`, `audit.xlsx`) with the attack scenarios.

Full option list: [mail_audit/README.md](mail_audit/README.md).

### SMTP checks only (`smtp_checker`)

Run from the `smtp_checker/` folder:

```bash
cd smtp_checker
python cli.py --mode domain -i domains.txt -o report.xlsx
python cli.py -i mail.example.com -o results.json            # direct MX hostnames
```

Details: [smtp_checker/README.md](smtp_checker/README.md).

### SPF / DMARC / DKIM only (`mail_antispoof_policy_checker`)

Run from the `mail_antispoof_policy_checker/` folder:

```bash
cd mail_antispoof_policy_checker
python cli.py --hostnames domains.txt --dkim-selector-file ../selector.txt --async-mode
```

Details: [mail_antispoof_policy_checker/README.md](mail_antispoof_policy_checker/README.md).

> The standalone `smtp_checker` and `mail_antispoof_policy_checker` CLIs import their own
> `lib` package relative to their folder (`from lib import …`). Always launch them with
> `python cli.py` **from their folder**. `python -m smtp_checker.cli` does not work.

### As a library

```python
from smtp_checker.lib import DomainChecker
from mail_antispoof_policy_checker.lib import SPFChecker
from mail_audit.lib import MailAuditor
```

Each package README documents its API.

---

## Repository layout

```
Mail Audit/
├── README.md                          ← this file
├── requirements.txt                   ← installs the 3 packages (editable)
├── domains.txt / selector.txt         ← example inputs
├── smtp_checker/                      ← standalone package (pyproject.toml, README, CHANGELOG)
├── mail_antispoof_policy_checker/     ← standalone package (pyproject.toml, README, CHANGELOG)
└── mail_audit/                        ← orchestrator, depends on the two above
```

Each package keeps its own version and CHANGELOG.

---

## Tests

```bash
pip install pytest pytest-asyncio
cd mail_antispoof_policy_checker && python -m pytest tests -q
```

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ModuleNotFoundError: No module named 'smtp_checker'` (or `mail_antispoof_policy_checker`, `mail_audit`) | Packages not installed in the active environment. Activate the venv and run `pip install -r requirements.txt` |
| Code changes have no effect | The packages are installed from another copy of the repository. Check the paths shown by `pip show -f smtp-checker` / `python -c "import mail_audit; print(mail_audit.__file__)"` |
| `ModuleNotFoundError: No module named 'lib'` | A standalone CLI was not launched from its own folder. `cd smtp_checker` (or `mail_antispoof_policy_checker`) and then run `python cli.py` |
| `UnicodeEncodeError: 'charmap' codec…` on Windows when redirecting output | Set `PYTHONUTF8=1` (`$env:PYTHONUTF8 = "1"` in PowerShell) |
| Odd or outdated DNS results | Local resolver cache: add `--nameservers "1.1.1.1,8.8.8.8"` (one list for both SMTP and antispoof checks) |
