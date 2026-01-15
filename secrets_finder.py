#!/usr/bin/env python3
import re
import os
import argparse
from pathlib import Path
import json
from typing import List, Dict, Optional

# Secret detection patterns (add/modify as needed)
SECRET_PATTERNS = {
    "AWS Access Key": r"AWS.*(?:access|secret).*key.*[A-Za-z0-9/+]{40}",
    "AWS Secret Key": r"aws_secret_access_key.*[A-Za-z0-9/+]{40}",
    "GitHub Token": r"gh[opu]_[0-9a-zA-Z]{36,255}",
    "Generic API Key": r"api[_-]?key[\s=:\"]*[a-z0-9]{32,}",
    "Private Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
    "SSH Key": r"ssh-rsa [A-Za-z0-9+/=]+",
    "Password": r"(?:password|passwd|pwd)[\s=:\"]*[a-z0-9!@#$%^&*()]{8,}",
    "Bearer Token": r"bearer[\s=:\"]*[a-z0-9_-]{20,}",
    "Database URL": r"(?:mysql|postgres|redis)://[^\s]+",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
    "Base64": r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
}

# Directories to exclude by default
EXCLUDE_DIRS = {".git", ".svn", "node_modules", "venv", "__pycache__"}

def scan_file(file_path: Path, patterns: Dict[str, str]) -> List[Dict]:
    """
    Scans a single file for secrets using provided regex patterns.

    Args:
        file_path: Path to the file to scan.
        patterns: Dictionary of secret types and their regex patterns.

    Returns:
        List of dictionaries containing found secrets.
    """
    results = []
    try:
        with file_path.open("r", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                for secret_type, pattern in patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        result = {
                            "type": secret_type,
                            "file": str(file_path),
                            "line": line_num,
                            "content": line.strip()
                        }
                        results.append(result)
    except (PermissionError, UnicodeDecodeError):
        pass
    return results

def scan_dir(directory: Path, patterns: Dict[str, str], exclude_dirs: set = EXCLUDE_DIRS) -> List[Dict]:
    """
    Recursively scans a directory for secrets, excluding specified directories.

    Args:
        directory: Path to the directory to scan.
        patterns: Dictionary of secret types and their regex patterns.
        exclude_dirs: Set of directory names to exclude.

    Returns:
        List of dictionaries containing found secrets.
    """
    results = []
    for root, dirs, files in os.walk(directory):
        # Exclude unwanted directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for file in files:
            file_path = Path(root) / file
            results.extend(scan_file(file_path, patterns))
    return results

def generate_report(results: List[Dict], output_file: Optional[str] = None) -> None:
    """
    Generates a report of found secrets, either as JSON or printed to console.

    Args:
        results: List of dictionaries containing found secrets.
        output_file: Optional path to save the report as JSON.
    """
    if output_file:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[+] Report saved to {output_file}")
    else:
        for result in results:
            print(f"[!] {result['type']} found in {result['file']} (line {result['line']}): {result['content']}")

def main():
    parser = argparse.ArgumentParser(description="Secret scanner for files and directories.")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--output", help="Output file for JSON report")
    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        print("[-] Target not found.")
        return

    if target.is_file():
        results = scan_file(target, SECRET_PATTERNS)
    else:
        results = scan_dir(target, SECRET_PATTERNS)

    if results:
        generate_report(results, args.output)
    else:
        print("[+] No secrets detected.")

if __name__ == "__main__":
    main()
