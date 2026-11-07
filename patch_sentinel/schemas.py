"""Tool schemas — the API the model reads.

The description is the only thing that decides whether a tool gets called and how its answer is
worded, so each one names what it measures, what it refuses, and what a refusal means. A
capability the description does not name is not used, however well it is implemented.
"""
from __future__ import annotations

CVE_SCAN = {
    "name": "cve_scan",
    "description": (
        "Answer 'are we patched?' with evidence, for this machine and any configured remote host. "
        "Use it whenever the user asks whether a machine is patched, up to date, vulnerable, or what "
        "updates are pending — including 'is the kernel patched', 'any security updates', 'are the "
        "containers current'. It measures four things per host: the running kernel versus the newest "
        "installed and the newest installable one (three states — a kernel patch counts only when it "
        "is RUNNING), every package the apt simulation would install (deliberately not filtered to "
        "-security, because fixes ship through -updates too), which recent Ubuntu advisory names those "
        "exact versions, and whether each running container image's tag still resolves to the digest "
        "we run. Read-only: it installs nothing, reboots nothing, writes no system state. "
        "Every check has three outcomes — clean, finding, could-not-look — so the payload carries "
        "`outcomes` per host, a `blind` list, and `exit_code` (0 nothing to do, 1 something to patch, "
        "2 at least one check could not answer). An unreachable host or a registry that rate-limited "
        "us is reported as unknown WITH its reason; never summarize an unknown as patched, and never "
        "say 'clean' when exit_code is 2. Quote the measurement time (`scan.at`) with any numbers you "
        "report."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": (
                    "Optional host label to scan. Omit to scan every configured host (this machine is "
                    "always one of them). An unknown label returns the refusal shape rather than a "
                    "guess."
                ),
            },
        },
        "required": [],
    },
}

CVE_PLAN = {
    "name": "cve_plan",
    "description": (
        "Propose the exact commands that would close what cve_scan found on one host — ranked, with "
        "risk, expected downtime, why each step is needed, how to verify it by effect, and how to "
        "reverse it. Use it after cve_scan when the user asks what to do, how to fix it, or whether "
        "it needs a reboot. It NEVER executes anything: no install, no restart, no reboot, no ssh "
        "write. The command is apt-get full-upgrade, not upgrade, because a new kernel is a new "
        "package that plain upgrade keeps back; a kernel that is installed but not running produces a "
        "reboot step, not an install step. Answers from the last measurement when it is fresh (the "
        "payload quotes its timestamp). Applying is a separate, operator-confirmed action that does "
        "not exist in this version — say so if asked to apply."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": (
                    "Host label to plan for. Omit for this machine. An unknown label returns the "
                    "refusal shape."
                ),
            },
        },
        "required": [],
    },
}

CVE_EXPLAIN = {
    "name": "cve_explain",
    "description": (
        "Explain one CVE id from the vendor's own record: which Ubuntu security notice names it, when "
        "that notice was published, the fixed package versions it lists for this release, and — from "
        "the last scan — whether that fix is installable here, already installed, or already running. "
        "Use it when the user names a CVE ('what about CVE-2026-98432?', 'does that affect us?'). "
        "The Ubuntu CVE page's own status word is deliberately not used as a source, because it lags "
        "behind the archive (it read 'work in progress' for a week while the fix was installable). "
        "If no fetched advisory names the id, it returns {\"match\": \"none\", \"answer\": null, "
        "\"reason\": ..., \"nearest\": [...]} — relay that refusal; do not answer from general "
        "knowledge or from the model's memory of the CVE."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "The CVE identifier, e.g. 'CVE-2026-98432'.",
            },
        },
        "required": ["cve_id"],
    },
}

CVE_COVERAGE = {
    "name": "cve_coverage",
    "description": (
        "State what this plugin can see and what it cannot: which sources actually answered and when, "
        "which hosts were unreachable, and the standing gaps that no scan closes — CVEs inside "
        "container image layers (needs an image scanner), language/package-manager dependencies "
        "outside the OS package manager (needs an SBOM and a dependency scanner), and hosts that are "
        "not Ubuntu (the advisory feed is Ubuntu's). Use it when the user asks how complete, how "
        "reliable, or how trustworthy the answer is, or asks what it misses. The gap list is never "
        "empty and never green: an empty gap list would be a claim that nothing is missed."
    ),
    "parameters": {"type": "object", "properties": {}, "required": []},
}

CVE_LIBRARIES = {
    "name": "cve_libraries",
    "description": (
        "Check the language and framework packages installed on a host against the OSV advisory "
        "database — the half of the attack surface an OS package manager cannot see. Use it when the "
        "question is about the app stack rather than the OS: 'is our node/php/python stack "
        "vulnerable?', 'any scary library versions?', 'are we exposed to <library> CVE'? It lists "
        "npm's global tree and the pip environment of the first python3 on PATH (the same adapter "
        "shape covers crates.io, Packagist, NuGet, RubyGems and Go when those tools are present), "
        "queries api.osv.dev in one batch, and returns each vulnerable package with its advisory id, "
        "aliases (CVE ids among them), a severity band, the versions that fix it and the OSV link. "
        "Every ecosystem reports an outcome (ok / missing / unreadable) so a tool that is not "
        "installed is never read as clean. Pass `project` with a directory to read that repository's "
        "lockfiles instead of the machine: package-lock.json, yarn.lock, pnpm-lock.yaml, "
        "requirements.txt, constraints.txt, poetry.lock, Pipfile.lock, go.sum, Cargo.lock, "
        "composer.lock, Gemfile.lock and pubspec.lock are parsed, and only pinned exact versions "
        "count (a `>=` range is reported as unverifiable, not guessed). NOT covered, and say so when "
        "asked about completeness: virtualenvs other than that interpreter, vendor directories, "
        "project manifests with no lockfile, and anything inside a container image."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "host": {"type": "string",
                     "description": "Host label. Omit for this machine."},
            "project": {"type": "string",
                        "description": ("A local directory to read instead of the machine: every "
                                        "lockfile under it (npm, pip/poetry/Pipfile, Go, Cargo, "
                                        "Composer, Bundler, Pub) up to three levels deep, skipping "
                                        "node_modules/.venv/vendor/target. Local hosts only — a "
                                        "remote project path is refused, not guessed.")},
        },
        "required": [],
    },
}

CVE_APPLY = {
    "name": "cve_apply",
    "description": (
        "CHANGES THE MACHINE. Runs the patch plan on one host — the only tool here that is not "
        "read-only — and is refused unless the operator has typed the host name themselves. "
        "Call it only after the user has seen the plan and explicitly asked to apply it, and only "
        "with `confirm` set to the exact host label the user typed. `dry_run` defaults to TRUE: "
        "that call refreshes metadata, prints the exact command and writes a receipt, and applies "
        "nothing. A real apply needs dry_run=false IN ADDITION to the typed name, so never pass "
        "it on your own initiative — ask, show the command, and let the user decide. Order of "
        "operations: preflight (this user must be able to run sudo without a prompt, or it "
        "refuses), stage (metadata refresh / download-only), apply (full-upgrade on apt, "
        "upgrade --refresh on rpm), then verify by effect (the host is re-measured: uname -r and "
        "the pending list) and a receipt line is written to receipts.jsonl. If the kernel was "
        "updated, the answer says a reboot is still owed — installing is not running."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "host": {"type": "string",
                     "description": "Host label from cve_scan. Omit for this machine."},
            "confirm": {"type": "string",
                        "description": ("The host label, typed by the operator. Must match "
                                        "exactly or nothing runs.")},
            "dry_run": {"type": "boolean",
                        "description": ("true (default) = stage and print, apply nothing. false = "
                                        "apply for real, only when the user asked for it.")},
        },
        "required": ["confirm"],
    },
}

CVE_IMAGE = {
    "name": "cve_image",
    "description": (
        "Read what is inside one container image and check it against OSV: the image is unpacked with "
        "`docker save` (never started), its distro is read from /etc/os-release, and its package "
        "database from dpkg or apk. Use it when the question is about an image rather than a host — "
        "'is our nginx image patched?', 'what CVEs are baked into <image>?'. Debian, Ubuntu and Alpine "
        "images are fully measured; an rpm-based image (needs a sqlite rpmdb reader) or an image with "
        "no package database answers `unsupported`/`unmeasured` and exit_code 2 — never 'clean'. The "
        "result carries the OS, the package count read, the advisories with their fixing version, and "
        "KEV/EPSS annotations."),
    "parameters": {
        "type": "object",
        "properties": {
            "image": {"type": "string",
                      "description": ("Image name or id as docker knows it, e.g. 'nginx:1.27' or "
                                      "'a1b2c3d4'. One image per call.")},
            "host": {"type": "string",
                     "description": "Host label whose docker daemon to ask. Omit for this machine."},
        },
        "required": ["image"],
    },
}

SCHEMAS = {schema["name"]: schema
           for schema in (CVE_SCAN, CVE_PLAN, CVE_EXPLAIN, CVE_COVERAGE, CVE_LIBRARIES,
                          CVE_IMAGE, CVE_APPLY)}
