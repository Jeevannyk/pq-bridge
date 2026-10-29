"""Fetch the real bank / fintech repositories at the exact commits used for the recorded results.

    python -m pqbridge.fetch_repos                 all 11 repos into data/repos/ (about 450 MB, a few minutes)
    python -m pqbridge.fetch_repos moov-io_ach     only the named repos

Idempotent: a repo already at its pinned commit is skipped. Commits are pinned in data/repos.json.
"""
import json
import subprocess
import sys
from pathlib import Path

from . import config

SPEC = config.ROOT / "data" / "repos.json"
DEST = config.ROOT / "data" / "repos"


def _git(*args, cwd=None):
    p = subprocess.run(["git", "-c", "core.longpaths=true", *args], cwd=cwd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if p.returncode:
        raise RuntimeError(f"git {' '.join(args)}: {p.stderr.strip()[-300:]}")
    return p.stdout.strip()


def fetch_one(name, url, commit, dest, log=print):
    d = dest / name
    if (d / ".git").exists():
        try:
            if _git("rev-parse", "HEAD", cwd=d) == commit:
                log(f"  {name}: already at {commit[:8]}")
                return "present"
        except RuntimeError:
            pass
    d.mkdir(parents=True, exist_ok=True)
    if not (d / ".git").exists():
        _git("init", "-q", cwd=d)
        _git("remote", "add", "origin", url, cwd=d)
    _git("fetch", "-q", "--depth", "1", "origin", commit, cwd=d)
    _git("checkout", "-q", "--force", "FETCH_HEAD", cwd=d)
    log(f"  {name}: fetched {commit[:8]}")
    return "fetched"


def run(only=None, dest: Path = DEST, log=print):
    rows = json.loads(SPEC.read_text())
    if only:
        rows = [r for r in rows if r["name"] in only]
        if not rows:
            raise RuntimeError(f"no repo named {only}; see {SPEC}")
    dest.mkdir(parents=True, exist_ok=True)
    log(f"Fetching {len(rows)} repositories into {dest}")
    return {r["name"]: fetch_one(r["name"], r["url"], r["commit"], dest, log) for r in rows}


if __name__ == "__main__":
    run(sys.argv[1:] or None)
