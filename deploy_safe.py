#!/usr/bin/env python3
"""
Reusable deploy-safety script — backup before overwrite, verify after, rollback on demand.

Copy this into any project that deploys files to a remote host (FTP, SCP, S3, etc.).
Adapt the `upload()`, `download()`, and `exists()` functions to the project's transport.

Hard rules (never transgress):
  1. NEVER overwrite/delete a remote artifact without first backing up the current version.
  2. NEVER treat a deploy as done until you've downloaded it back and verified size + hash.
  3. Every deploy is logged with a timestamp and content hash.
  4. Rollback to any prior backup is a single command.

Usage:
  python3 deploy_safe.py <file> [<file> ...]      # deploy (backup + upload + verify)
  python3 deploy_safe.py --rollback <timestamp>   # restore a backup
  python3 deploy_safe.py --list                   # list backups

Credential resolution: override get_credentials() for the project's transport.
Secrets are never printed and never hardcoded.
"""

import os
import sys
import json
import hashlib
import datetime
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKUP_ROOT = os.path.join(SCRIPT_DIR, "backup")
LOG_FILE = os.path.join(SCRIPT_DIR, "deploy.log")


def log(msg):
    line = f"[{datetime.datetime.now().isoformat()}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ==== TRANSPORT — override these for the project ====

def get_credentials():
    """Return whatever the transport needs. Never print secrets."""
    raise NotImplementedError("override get_credentials() for this project's transport")


def remote_download(remote_name, creds, out_path):
    """Download current remote version to out_path. Return True on success."""
    raise NotImplementedError("override remote_download() for this project's transport")


def remote_upload(local_path, creds, remote_name):
    """Upload local_path to remote_name. Return True on success."""
    raise NotImplementedError("override remote_upload() for this project's transport")


# ==== CORE (do not modify) ====

def list_backups():
    if not os.path.isdir(BACKUP_ROOT):
        return []
    return sorted(d for d in os.listdir(BACKUP_ROOT)
                  if os.path.isdir(os.path.join(BACKUP_ROOT, d)))


def cmd_list():
    backups = list_backups()
    if not backups:
        print("No backups found.")
        return
    print("Available backups:")
    for b in backups:
        files = os.listdir(os.path.join(BACKUP_ROOT, b))
        print(f"  {b}: {', '.join(files)}")


def cmd_rollback(timestamp):
    src_dir = os.path.join(BACKUP_ROOT, timestamp)
    if not os.path.isdir(src_dir):
        print(f"✗ Backup '{timestamp}' not found. Use --list.")
        sys.exit(1)
    creds = get_credentials()
    for fname in sorted(os.listdir(src_dir)):
        src = os.path.join(src_dir, fname)
        if not remote_upload(src, creds, fname):
            print(f"  ✗ Failed to restore {fname}")
            sys.exit(1)
        print(f"→ Restored {fname}")
    log(f"ROLLBACK to {timestamp}")
    print("✓ Rollback complete.")


def cmd_deploy(local_files):
    creds = get_credentials()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(BACKUP_ROOT, ts)
    os.makedirs(backup_dir, exist_ok=True)

    deployed = []
    for local_path in local_files:
        local_path = os.path.abspath(local_path)
        if not os.path.isfile(local_path) or os.path.getsize(local_path) == 0:
            print(f"✗ Refusing to deploy missing/empty file: {local_path}")
            sys.exit(1)
        remote_name = os.path.basename(local_path)
        local_hash = sha256_file(local_path)

        # 1. BACKUP current remote
        backup_path = os.path.join(backup_dir, remote_name)
        if remote_download(remote_name, creds, backup_path):
            print(f"  ✓ Backed up {remote_name} ({os.path.getsize(backup_path)} bytes)")
        else:
            print(f"  → {remote_name} not present remotely (new file)")

        # 2. UPLOAD
        if not remote_upload(local_path, creds, remote_name):
            print(f"  ✗ Upload failed for {remote_name}")
            sys.exit(1)

        # 3. VERIFY (download back + hash compare)
        verify_path = os.path.join(backup_dir, f".verify_{remote_name}")
        if not remote_download(remote_name, creds, verify_path):
            print(f"  ✗ Post-deploy verification failed for {remote_name}")
            sys.exit(1)
        if sha256_file(verify_path) != local_hash:
            print(f"  ✗ Hash mismatch after deploy for {remote_name} — corruption on server")
            sys.exit(1)
        os.remove(verify_path)
        print(f"  ✓ Verified {remote_name} (hash match)")
        deployed.append(remote_name)
        log(f"DEPLOY {remote_name} hash={local_hash[:12]} backup={ts}")

    print(f"\n✓ Deployed {len(deployed)} file(s). Backup: backup/{ts}/")
    print(f"  Rollback: python3 deploy_safe.py --rollback {ts}")


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)
    if args[0] == "--list":
        cmd_list()
    elif args[0] == "--rollback":
        if len(args) != 2:
            print("Usage: deploy_safe.py --rollback <timestamp>")
            sys.exit(1)
        cmd_rollback(args[1])
    else:
        cmd_deploy(args)


if __name__ == "__main__":
    main()
