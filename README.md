# Secrets Scanner

**Secrets Scanner** is a Python tool designed to detect sensitive information (secrets, API keys, tokens, etc.) in files and directories. It uses regex patterns to identify potential leaks and can generate a JSON report for further analysis.

---

## Features

- Scans files and directories recursively.
- Detects common secret types (AWS keys, GitHub tokens, private keys, etc.).
- Excludes common directories (`.git`, `node_modules`, etc.).
- Generates a JSON report for easy integration with other tools.

---

## Installation

1. **Clone the repository:**
  
   git clone https://github.com/Spellskite-coding/Secrets_finder
   cd Secrets_finder

---

## Basic usage 

1. python3 secrets_finder.py /path/to/target

2.  Save Results to JSON :

  python3 secrets_finder.py /path/to/target --output report.json


## Secrets Patterns

The tool checks for the following secret types by default:

- AWS Access Key
- AWS Secret Key
- GitHub Token
- Generic API Key
- Private Key
- SSH Key
- Password
- Bearer Token
- Database URL
- Slack Token
- Base64 strings

You can modify or add patterns in the `SECRET_PATTERNS` dictionary in the script.

Excluded Directories
By default, the following directories are excluded:

.git
.svn
node_modules
venv
__pycache__

To customize, edit the EXCLUDE_DIRS set in the script.
