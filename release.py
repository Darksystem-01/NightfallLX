#!/usr/bin/env python3
"""Create the NightfallLX GitHub repository and publish the current tree."""

from __future__ import annotations

import getpass
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("requests is required: python -m pip install requests")

ROOT = Path(__file__).resolve().parent
DEFAULT_USERNAME = "Darksystem-01"
DEFAULT_REPO = "NightfallLX"
COMMIT_MESSAGE = (
    "feat: NightfallLX v1.0.0 - Advanced Web Vulnerability Assessment Framework"
)
ASKPASS_SCRIPT = """#!/bin/sh
case "$1" in
  *Username*) printf '%s\\n' "$NIGHTFALL_GIT_USER" ;;
  *Password*) printf '%s\\n' "$NIGHTFALL_GIT_TOKEN" ;;
  *) printf '\\n' ;;
esac
"""
GITIGNORE = """# NightfallLX generated output
.vapf-loot/
.nightfalllx/
loot/
reports/
*.sarif
*.report.md
*.report.json

# Secrets and local environment
.env
.env.*
*.pem
*.key

# Python
__pycache__/
*.py[cod]
.venv/
venv/
.mypy_cache/
.ruff_cache/
.pytest_cache/
*.egg-info/
dist/
build/
.coverage
htmlcov/

# Generated artefacts
*.log
*.hprof
heapdump*
p0*
ports.txt
scan_plan.md
lab_server.py
"""
README_TEMPLATE = """# NightfallLX

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/{owner}/{repo}/actions)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Advanced AI-Assisted Web Vulnerability Assessment Framework**

NightfallLX is an evidence-first security assessment framework for authorised
web application testing. It combines adaptive HTTP behaviour, WAF-aware payload
mutation, and bounded verification to turn ambiguous scanner output into
defensible findings.

## Features

- **0-100 Confidence Engine** — findings are scored from converging signals, not
  a single reflected payload or timing sample.
- **WAF Evasion** — fingerprint-driven payload mutation, encoding changes, and
  browser-like TLS profiles through `curl_cffi`.
- **SQLi** — boolean and time-based verification with bounded MySQL
  `@@version` extraction.
- **XSS** — DOM-aware verification with execution-context checks.
- **LFI** — read-only PHP filter disclosure checks.
- **Safe RCE PoC** — fixed harmless `id`, `whoami`, and `sleep` probes only.
- **Doctor & Bootstrap** — environment checks plus automatic SecLists download.

## Quick Start

```bash
git clone https://github.com/{owner}/{repo}.git
cd {repo}
pip install -e .
nightfalllx --doctor
```

Download the SecLists wordlists on first use:

```bash
nightfalllx --download-wordlists
```

Show the version:

```bash
nightfalllx --version
```

## Usage

```bash
nightfalllx -u http://127.0.0.1:8080
nightfalllx -u http://127.0.0.1:8080 --auto
nightfalllx -u http://127.0.0.1:8080 --modules sqli,xss,lfi
```

## Requirements

- Python 3.10+
- Optional external tools: `ffuf`, `nmap`, `sqlmap`

## Legal Disclaimer

NightfallLX is intended **only** for systems you own or have explicit written
authorisation to test. Unauthorised access, scanning, or exploitation is illegal
and unethical. The authors accept no liability for misuse or damage caused by
this software. Always define scope, follow the rules of engagement, and stop if
you do not have permission.
"""


def prompt(label: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip()
    return value or (default or "")


def create_repository(token: str, username: str, repo: str) -> tuple[str, str]:
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    payload = {
        "name": repo,
        "description": "Advanced AI-Assisted Web Vulnerability Assessment Framework",
        "private": False,
    }
    response = requests.post(
        "https://api.github.com/user/repos",
        headers=headers,
        json=payload,
        timeout=30,
    )
    if response.status_code == 201:
        data = response.json()
        owner = str(data.get("owner", {}).get("login") or username)
        return str(data.get("html_url") or f"https://github.com/{owner}/{repo}"), owner
    if response.status_code == 422:
        message = response.text.lower()
        if "already exists" in message or "name already exists" in message:
            print("[release] Repository already exists; continuing with the push.")
            return f"https://github.com/{username}/{repo}", username
        sys.exit(f"GitHub rejected repository creation: {response.text[:300]}")
    if response.status_code == 401:
        sys.exit("GitHub rejected the token (401). Create a fresh token and retry.")
    if response.status_code == 403:
        sys.exit("GitHub denied access (403). The token needs repository write scope.")
    sys.exit(f"GitHub API error {response.status_code}: {response.text[:300]}")


def write_readme(owner: str, repo: str) -> None:
    (ROOT / "README.md").write_text(
        README_TEMPLATE.format(owner=owner, repo=repo),
        encoding="utf-8",
    )


def run(command: list[str], env: dict[str, str] | None = None) -> None:
    print(f"$ {shlex.join(command)}")
    result = subprocess.run(command, cwd=ROOT, text=True, env=env)
    if result.returncode != 0:
        sys.exit(f"Command failed with exit code {result.returncode}.")


def has_head() -> bool:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def has_staged_changes() -> bool:
    result = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        cwd=ROOT,
        check=False,
    )
    return result.returncode != 0


def commit(allow_empty: bool) -> None:
    command = [
        "git",
        "-c",
        "user.name=NightfallLX",
        "-c",
        "user.email=nightfalllx@users.noreply.github.com",
        "commit",
    ]
    if allow_empty:
        command.append("--allow-empty")
    command.extend(["-m", COMMIT_MESSAGE])
    run(command)


def push_with_token(username: str, token: str) -> None:
    handle, path_text = tempfile.mkstemp(prefix="nightfall-askpass-", suffix=".sh")
    os.close(handle)
    askpass = Path(path_text)
    askpass.write_text(ASKPASS_SCRIPT, encoding="utf-8")
    askpass.chmod(0o700)
    env = os.environ.copy()
    env.update(
        {
            "GIT_ASKPASS": str(askpass),
            "GIT_ASKPASS_REQUIRE": "force",
            "GIT_TERMINAL_PROMPT": "0",
            "NIGHTFALL_GIT_USER": username,
            "NIGHTFALL_GIT_TOKEN": token,
        }
    )
    try:
        run(["git", "-c", "credential.helper=", "push", "-u", "origin", "main"], env=env)
    finally:
        askpass.unlink(missing_ok=True)


def main() -> int:
    print("NightfallLX release helper")
    print("The token is used in memory only; it is never written to the git remote.")
    token = getpass.getpass("GitHub token (hidden input): ").strip()
    if not token:
        sys.exit("A GitHub token is required.")
    username = prompt("GitHub username", DEFAULT_USERNAME)
    repo = prompt("Repository name", DEFAULT_REPO)
    if not username or not repo:
        sys.exit("Username and repository name cannot be empty.")

    print(f"[release] Creating https://github.com/{username}/{repo} ...")
    try:
        _, owner = create_repository(token, username, repo)
    except requests.RequestException as exc:
        sys.exit(f"GitHub API request failed: {exc}")
    write_readme(owner, repo)
    (ROOT / ".gitignore").write_text(GITIGNORE, encoding="utf-8")

    if not (ROOT / ".git").exists():
        run(["git", "init"])
    else:
        print("[release] Existing git repository detected.")

    run(["git", "add", "."])
    if has_staged_changes():
        commit(allow_empty=False)
    elif not has_head():
        commit(allow_empty=True)
    else:
        print("[release] No changes to commit.")

    subprocess.run(
        ["git", "remote", "remove", "origin"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    repo_url = f"https://github.com/{owner}/{repo}"
    run(["git", "remote", "add", "origin", repo_url])
    run(["git", "branch", "-M", "main"])

    print("[release] Pushing main ...")
    push_with_token(owner, token)

    print(f"\nRepository: {repo_url}")
    print(f"Clone: git clone {repo_url}.git")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
