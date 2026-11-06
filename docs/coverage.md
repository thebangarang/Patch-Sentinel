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
| Fedora | — (Bodhi holds CVE→build per update) | not read | **named gap**: the host says the lag is unmeasured |
| openSUSE / SLES | — (SUSE publishes CSAF/VEX) | not read | **named gap**, same |

The distro records key on the **source** package (`openssl`, not `libssl3`), so installed binaries are
mapped to their source before querying and back again for the report. A family with no feed answers
`unsupported` with the reason — never "no lag".

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
