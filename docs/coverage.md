# Coverage: what is measured, what is excluded, and how each one was proven

This page exists because "we cover many ecosystems" is a claim, and claims rot. Every row below says
which command reads the machine, and exactly how far the proof goes. If a row says *format only*, no
capture of that tool's output exists in this repository and the reader has never been exercised
against a real toolchain.

One structural point: several stores can hold *different* packages in the same ecosystem — `pip` sees
the interpreter's environment, `pipx` its own venvs, `uv` its tool store; `dotnet tool list` knows
global tools while `~/.nuget/packages` knows every restored package. Every store that answers
contributes and duplicates are dropped, rather than the first one winning and hiding the rest.

Two rules decide inclusion:

1. **Machine-wide only.** A reader lists what is installed for the machine's user, not what one
   project happens to depend on. Per-project files are someone else's question ("which of my
   project's dependencies…") and pretending otherwise produces a number nobody can act on.
2. **A missing tool is an outcome.** `missing` and `unreadable` are reported as such. An empty list
   from a tool that is not installed is the classic false clean, and this plugin exists to avoid it.

## OS package managers

| family | command | proven on |
|---|---|---|
| apt | `apt-get -s dist-upgrade`, `dpkg-query` | this machine (Ubuntu 26.04) and a Debian 12 VM |
| dnf | `dnf -q check-update`, `rpm -qa` | a Fedora 45 VM |
| pacman | `pacman -Q`, `pacman -Qu` | an Arch VM |
| zypper | `zypper -q lu`, `rpm -qf` | an openSUSE Leap 15.6 VM |

Alpine (`apk`) is registered; its cloud image needed the `nocloud_` variant before it would take a
cloud-init seed (the plain one booted to a login prompt with no user), and once it did, `apk` answered.
The VM was recreated later and its `authorized_keys` no longer holds this machine's lab key, so the
*inventory* reading is proven and the *vendor-lag* reading is not.

## Vendor lag: "fixed upstream, not in this archive yet"

This comparison needs a feed that names a fixed version **per release**. Which families have one:

| family | source | how the fixed version is read | state |
|---|---|---|---|
| Ubuntu | `ubuntu.com/security/notices.json` | `release_packages` per release, binary package names | proven live (beelink, 26.04) |
| Debian | OSV `Debian:<major>` | `affected[].ranges[].events[].fixed`, source package names | proven live (Debian 12 VM) |
| Alpine | OSV `Alpine:v<major.minor>` | same shape, source names | **adapter tested against captured payloads**; the lab VM's key was rejected at scan time, so the lag path has not run on a live Alpine host |
| Rocky / AlmaLinux / RHEL | OSV `Rocky Linux:<major>`, `AlmaLinux:<major>`, `Red Hat:<major>` | same shape | adapter tested against captured payloads; no RHEL host in the lab yet |
| Arch | `security.archlinux.org/all.json` | `fixed` per AVG, binary names, resolved advisories skipped | proven live (Arch VM) |
| Fedora | Bodhi `updates/?type=security&status=stable&releases=F<major>` | `builds[].nvr` split from the right, indexed per package; the update alias is the notice | **proven live** (Fedora 45 VM: 109 pending, 38 advisories matched, 9 fix-in-archive, 29 already fixed, 0 lag — a measured zero, not an assumption) |
| openSUSE / SLES | `ftp.suse.com/pub/projects/security/oval/opensuse.<product>.xml.gz` | OVAL `definition → criterion → rpminfo_test → object/state`, epoch stripped | **proven live** (Leap 15.6 VM: 4,965 packages indexed, 90 already fixed, 6 lag rows, e.g. `kernel-default-base …103.0 → …103.1` for `CVE-2026-43284`; the VM had never refreshed its index, and the scan says so) |

The distro records key on the **source** package (`openssl`, not `libssl3`), so installed binaries are
mapped to their source before querying and back again for the report. SUSE's OVAL names *binary*
packages instead, so both keys are indexed there — a source-only map answered "no advisory names an
installed version", which reads as clean.

Both new feeds are cached (Bodhi 6 h, OVAL 12 h) because they are expensive: a Bodhi page takes about
ten seconds and the OVAL document is 12 MB compressed, parsing to a 4,965-package index in ~7 s.

A feed's **own date** travels with the result. openSUSE Leap 15.6's OVAL last moved on 2026-06-25
because the release left support; the host row quotes the date, flags anything older than 30 days, and
the pane says *a stale feed is not a vendor delay*. Same rule as the archive index: a machine that has
not looked is not a machine the vendor forgot.

A family with no feed answers `unsupported` with the reason — never "no lag".

## Project environments

`cve_libraries` also reads **every virtualenv on the machine**: one `find` for `*.dist-info` directories
under project `.venv`/`venv`, pipx and poetry environments, and the package name and version come from
the directory name — nothing is imported, no interpreter is launched, no project code runs.

Measured on the beelink: **9 environments, 232 packages** — and the finding that mattered was
`pillow 12.3.0` in three projects (59 advisories, fix 13.0.0). The same package in three environments
is **one** finding that names its three environments, not three rows.

Two lessons are pinned in `tests/test_environments.py`: a bare `*.dist-info` walk finds uv's
unpacked-wheel cache (485 "environments" of nothing), so the path must name a venv; and the exclusions
run **in the find**, because `head` runs before Python sees a line — a backup of the home directory
otherwise ate 350 of the 600 budget.

Not read: `node_modules/`, `vendor/`, and projects whose only manifest is a range (`composer.json`,
`Cargo.toml`, `go.mod`).

## Project lockfiles

`cve_libraries` with a `project` argument (or the field in the pane) reads a repository instead of the
machine: `package-lock.json`, `yarn.lock` (v1 and berry), `pnpm-lock.yaml`, `requirements.txt`,
`constraints.txt`, `poetry.lock`, `Pipfile.lock`, `go.sum`, `Cargo.lock`, `composer.lock`,
`Gemfile.lock`, `pubspec.lock` — three levels deep, skipping `node_modules`, `.venv`, `vendor`,
`target`.

Two limits are stated rather than hidden: only **pinned** versions count (a `>=` range is reported,
never guessed), and a project with only a manifest (`composer.json`, `Cargo.toml`, `go.mod`,
`*.csproj`) has no exact version to check — committing the lockfile is what closes it.

Measured on a three-file fixture (`/tmp/demo-project`): 3 lockfiles read, 5 packages, **82 advisories**,
each with the fixing version, its EPSS score and a KEV flag where one applies.

## Language ecosystems

`cve_libraries` reads each toolchain's own machine-wide store, then asks OSV for advisories that name
those exact versions.

| ecosystem | command | proof |
|---|---|---|
| npm | `npm ls -g --json` | real machine |
| PyPI | `pip list --format=json`, `pipx list --short`, `uv tool list` | real machine (pip); container capture (pipx, uv) |
| Packagist | `composer global show --format=json` | container capture (`composer:latest`) |
| RubyGems | `gem list --local` | container capture (`ruby:3-slim`), 88 real lines incl. `(default: 0.4.0)` |
| Maven | every `*.pom` under `~/.m2/repository`, plus `*.jar` under `~/.gradle/caches/modules-2/files-2.1` | container capture (`maven:3-eclipse-temurin-21`), 227 artifacts; Gradle layout from the tool's own directory scheme, no capture yet |
| Go | `go version -m` on each `GOPATH/bin` binary | container capture (`golang:alpine`) |
| crates.io | `cargo install --list` | container capture (`rust:1-slim`), path-install shape |
| Pub (Dart) | `dart pub global list` | container capture (`dart:stable`), args 2.5.0 |
| NuGet | `~/.nuget/packages` (ids read from each `.nuspec`), then `dotnet tool list -g` | container capture (`dotnet/sdk:8.0`), Newtonsoft.Json 12.0.1 + Serilog 2.10.0 |

Each capture is committed under `tests/fixtures/` and asserted in `tests/test_libraries.py`, so the
parser cannot drift from the output it was written against without a test failing.

Two captures taught a lesson worth repeating: `bash -lc` inside a container is a **login** shell, and
it resets `PATH` — `cargo` and `go` were "not found" until the probes used `bash -c`/`sh -c`. And
`golang:alpine` has no bash at all. A capture that comes back empty is a capture to debug, not a
parser to trust.

Ecosystem names were confirmed against the live API rather than assumed: `rack 2.2.0` → 36 advisories
(RubyGems), `laravel/framework 6.0.0` → 16 (Packagist), `log4j-core 2.14.1` → advisories (Maven),
`Jinja2 2.10` → 12 (PyPI).

## Excluded, with the reason

| not covered | why |
|---|---|
| project lockfiles (`package-lock.json`, `composer.lock`, `Cargo.toml`, `go.mod`, `*.csproj`) | per-project, not machine-wide; guessing which project is meant is how a scanner lies. One chat question away. |
| inside container images | needs an image scanner (trivy) and a vulnerability database; refused on purpose in 0.1.0. |
| Hex/Elixir, CocoaPods, Swift | no machine-wide store — both resolve per project. |
| `~/.gradle/caches` verification | the reader exists and its layout is documented, but no Gradle build has been captured yet — it is the one row here without a fixture. |
| Conda, CPAN, CRAN, PECL | OSV does not carry these ecosystems, so a reader would produce findings nobody can look up. |
| Windows (winget/choco) | needs a PowerShell transport, not a shell block. |

## What a "finding" is

An advisory (OSV/GHSA record) that names the exact installed version. One package can carry many —
`Jinja2 2.10` carries 12 — which is why findings are grouped per package with a count, the worst
severity, and the first version that closes it.

The `~/.nuget/packages` case is worth keeping as a lesson even though it is now covered: the folder
names are lowercased package ids, and querying OSV under the wrong casing returns **zero** advisories
— a false clean, which is worse than a stated gap. The reader takes the id from each package's own
`.nuspec` (`Newtonsoft.Json`, not `newtonsoft.json`), verified against a real restore in the .NET 8
SDK container.

Where the advisory carries its own **Workarounds** section, that text is shown with the finding: the
vendor's temporary mitigation, quoted rather than invented.
