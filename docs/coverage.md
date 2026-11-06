# Coverage: what is measured, what is excluded, and how each one was proven

This page exists because "we cover many ecosystems" is a claim, and claims rot. Every row below says
which command reads the machine, and exactly how far the proof goes. If a row says *format only*, no
capture of that tool's output exists in this repository and the reader has never been exercised
against a real toolchain.

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

Alpine (`apk`) is written but **not registered**: its cloud images would not take a cloud-init seed,
so no Alpine host has ever been read. Alpine therefore answers `unsupported`.

## Language ecosystems

`cve_libraries` reads each toolchain's own machine-wide store, then asks OSV for advisories that name
those exact versions.

| ecosystem | command | proof |
|---|---|---|
| npm | `npm ls -g --json` | real machine |
| PyPI | `pip list --format=json` (first pip on PATH) | real machine |
| Packagist | `composer global show --format=json` | container capture (`composer:latest`) |
| RubyGems | `gem list --local` | container capture (`ruby:3-slim`), 88 real lines incl. `(default: 0.4.0)` |
| Maven | every `*.pom` under `~/.m2/repository` | container capture (`maven:3-eclipse-temurin-21`), 227 artifacts |
| Go | `go version -m` on each `GOPATH/bin` binary | container capture (`golang:alpine`) |
| crates.io | `cargo install --list` | container capture (`rust:1-slim`), path-install shape |
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
| `~/.gradle/caches` | same shape as `~/.m2` but the layout differs per Gradle version; not yet captured. |
| inside container images | needs an image scanner (trivy) and a vulnerability database; refused on purpose in 0.1.0. |
| Hex/Elixir, CocoaPods, Swift | no machine-wide store — both resolve per project. |
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
